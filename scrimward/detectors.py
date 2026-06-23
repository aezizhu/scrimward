"""Secret/PII detectors and the ``Span`` type they emit.

A :class:`Detector` is a named string ``pattern`` with a ``token_prefix`` and an
optional ``validate`` callback (Luhn, octet range, base64 decode). :func:`detect`
compiles each pattern, runs it, drops candidates the validator rejects, and
returns a list of :class:`Span` — half-open ``[start, end)`` slices tagged with
the detector ``name``/``prefix`` and matched ``text``.

Built-in detectors are ordered **most-specific-first** so the engine's overlap
resolver prefers the high-confidence, narrowly-scoped match. High precision is a
*performance* feature too: over-masking destroys the context the model needs, so
detectors validate before they fire (and the engine drops allowlisted matches).
Names/order/prefixes are the contract the engine imports; the patterns are here.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    """A detected region of text to be replaced by a token."""

    start: int
    end: int
    name: str
    prefix: str
    text: str


@dataclass(frozen=True)
class Detector:
    """A named, validated secret/PII pattern (``pattern`` is a regex *string*)."""

    name: str
    pattern: str
    token_prefix: str
    validate: Callable[[str], bool] | None = None


# --- validators -----------------------------------------------------------


def _luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_ok(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _jwt_ok(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    try:
        for seg in parts[:2]:
            base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:
        return False
    return True


def _iban_ok(value: str) -> bool:
    """ISO 13616 mod-97 check — what turns a loose IBAN regex into a precise one."""
    v = value.replace(" ", "").upper()
    if not 15 <= len(v) <= 34:
        return False
    rearranged = v[4:] + v[:4]  # move country+check digits to the end
    digits = []
    for c in rearranged:
        if c.isdigit():
            digits.append(c)
        elif "A" <= c <= "Z":
            digits.append(str(ord(c) - 55))  # A->10 .. Z->35
        else:
            return False
    return int("".join(digits)) % 97 == 1


_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _high_entropy_ok(value: str) -> bool:
    """True if ``value`` is a high-entropy run worth masking (the catch-all gate).

    Closes the *unknown-prefix* secret class. Calibrated to detect-secrets: a
    base64-charset run needs Shannon entropy > 4.5 bits/char, an all-hex run
    > 3.0. Two benign shapes are rejected here (others are handled by the
    candidate regex / the engine allowlist): pure-numeric runs (IDs, timestamps,
    phone digits — max digit entropy is log2(10)=3.32, so a uniform 20-digit ID
    clears the hex limit; they are NEVER a credible secret) and low-variety runs.
    Full bare hex digests (git SHA / md5 / sha256) DO fire by design — sparing
    those exact lengths would also spare real 128/256-bit hex keys — and are
    suppressed per-value via the engine allowlist, not here.
    """
    v = value.rstrip("=")  # trailing base64 padding carries no entropy signal
    n = len(v)
    if n < 20:
        return False
    if v.isdigit():  # pure-numeric is unmaskable noise, never a secret
        return False
    counts = Counter(v)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    limit = 3.0 if all(ch in _HEX_CHARS for ch in v) else 4.5
    return entropy > limit  # strict > : a value exactly at the limit is benign


# --- the registry (MOST-SPECIFIC-FIRST) -----------------------------------
#
# An empty ``pattern`` means the detector is intentionally disabled (too
# false-positive-prone without context, e.g. a bare 40-char AWS secret). detect()
# skips empty patterns.
BUILTINS: tuple[Detector, ...] = (
    # --- high-confidence vendor prefixes (most-specific first) ---
    Detector("aws_access_key", r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[0-9A-Z])[0-9A-Z]{16}\b", "AWS_KEY"),
    # Re-enabled keyword-anchored (gitleaks/detect-secrets pattern): a BARE
    # 40-char base64 over-fires, but an AWS_SECRET_ACCESS_KEY assignment is
    # unambiguous. The keyword is the FP guard; the whole "key=value" is masked.
    Detector(
        "aws_secret_key",
        r"(?i:aws_secret_access_key|aws_secret_key)[\"'\s]*[=:]\s*[\"']?[A-Za-z0-9/+]{40}",
        "AWS_SECRET",
    ),
    Detector("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "GH_TOKEN"),
    Detector("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b", "GH_PAT"),
    Detector("gitlab_pat", r"\bglpat-[A-Za-z0-9_-]{20,}\b", "GITLAB_PAT"),
    Detector("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{16,}\b", "ANTHROPIC_KEY"),
    Detector("openai_key", r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b", "OPENAI_KEY"),
    Detector("stripe_secret_key", r"\b[rs]k_live_[A-Za-z0-9]{24,}\b", "STRIPE_KEY"),
    Detector("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "SLACK_TOKEN"),
    Detector("slack_app_token", r"\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+\b", "SLACK_APP"),
    Detector(
        "slack_webhook_url",
        r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{24}\b",
        "SLACK_WEBHOOK",
    ),
    Detector("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "GOOGLE_KEY"),
    Detector("google_oauth_access_token", r"\bya29\.[A-Za-z0-9_-]{20,}\b", "GOOGLE_OAUTH"),
    Detector("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", "NPM_TOKEN"),
    Detector("pypi_token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b", "PYPI_TOKEN"),
    Detector("huggingface_token", r"\bhf_[A-Za-z0-9]{34}\b", "HF_TOKEN"),
    Detector("digitalocean_token", r"\bdo[oprt]_v1_[a-f0-9]{64}\b", "DO_TOKEN"),
    Detector("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "SENDGRID_KEY"),
    Detector("shopify_access_token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "SHOPIFY_TOKEN"),
    Detector("linear_api_key", r"\blin_api_[A-Za-z0-9]{40}\b", "LINEAR_KEY"),
    Detector("twilio_account_sid", r"\bAC[a-f0-9]{32}\b", "TWILIO_SID"),
    Detector("twilio_api_key_sid", r"\bSK[a-f0-9]{32}\b", "TWILIO_KEY"),
    Detector("square_access_token", r"\b(?:sq0atp-|EAAA)[A-Za-z0-9_-]{22,}\b", "SQUARE_TOKEN"),
    Detector("mailgun_key", r"\bkey-[a-f0-9]{32}\b", "MAILGUN_KEY"),
    Detector("notion_token", r"\b(?:secret_|ntn_)[A-Za-z0-9]{43,50}\b", "NOTION_TOKEN"),
    # --- structural secrets ---
    Detector(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "PRIVATE_KEY",
    ),
    Detector("jwt", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT", _jwt_ok),
    Detector("bearer_token", r"\bBearer\s+[A-Za-z0-9._\-]{20,}", "BEARER"),
    Detector("connection_string", r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "CONN_STR"),
    # --- keyword-anchored (the keyword is the FP guard; whole span masked) ---
    Detector(
        "cloudflare_api_token",
        r"(?i:(?:cloudflare|cf)[ _-]?(?:api[ _-]?)?token)[\"'=:\s]+[A-Za-z0-9_-]{40}\b",
        "CF_TOKEN",
    ),
    Detector("azure_storage_key", r"(?i:AccountKey)=[A-Za-z0-9+/]{86}==", "AZURE_KEY"),
    Detector("azure_sas_signature", r"[?&]sig=[A-Za-z0-9%]{43,}(?:%3D|=)", "AZURE_SAS"),
    Detector("aws_account_in_arn", r"\barn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:", "AWS_ARN"),
    # --- PII ---
    Detector("credit_card", r"\b\d(?:[ -]?\d){12,18}\b", "CC", _luhn_ok),
    Detector("us_ssn", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "SSN"),
    Detector("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "IBAN", _iban_ok),
    Detector("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
    Detector("phone", r"\+\d[\d\s().\-]{7,}\d", "PHONE"),
    Detector("mac_address", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "MAC"),
    Detector("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", _ipv4_ok),
    # --- generic keyword-anchored catch-all — lowest priority but for the entropy one ---
    Detector(
        "generic_assigned_secret",
        r"(?i:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
        r"[\"'\s]*[=:]\s*[\"']?[A-Za-z0-9+/_\-]{12,}[\"']?",
        "GENERIC_SECRET",
    ),
    # --- shapeless high-entropy catch-all — ABSOLUTE LAST (lowest priority) ---
    # Claims only the bytes no higher-confidence detector classified. The negative
    # lookbehind anchors the true left edge of a base64 run ('+'/'/' are non-word,
    # so \b would mis-anchor); ={0,2} consumes trailing padding into group(0).
    # HARD-DEPENDS on the union-merge resolver (R1): a vendor match inside a wider
    # entropy run must mask the whole union, else the flanking bytes leak.
    Detector(
        "high_entropy_string",
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}",
        "HIGH_ENTROPY",
        _high_entropy_ok,
    ),
)


_COMPILED: dict[str, re.Pattern[str]] = {}


def _compiled(pattern: str) -> re.Pattern[str]:
    rx = _COMPILED.get(pattern)
    if rx is None:
        rx = re.compile(pattern)
        _COMPILED[pattern] = rx
    return rx


def detect(text: str, detectors: tuple[Detector, ...] = BUILTINS) -> list[Span]:
    """Find all (validated) spans in ``text`` using ``detectors`` (in order).

    Compiles each detector's string ``pattern`` (cached), applies its
    ``validate`` callback to drop false positives, and returns the spans. Only
    *finds* — it does not mutate text, drop allowlisted values, or mint tokens
    (the engine does that). Disabled detectors (empty pattern) are skipped.
    """
    spans: list[Span] = []
    for d in detectors:
        if not d.pattern:
            continue
        for m in _compiled(d.pattern).finditer(text):
            value = m.group(0)
            if d.validate is not None and not d.validate(value):
                continue
            spans.append(Span(m.start(), m.end(), d.name, d.token_prefix, value))
    return spans
