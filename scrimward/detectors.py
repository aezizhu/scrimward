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
import re
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


# --- the registry (MOST-SPECIFIC-FIRST) -----------------------------------
#
# An empty ``pattern`` means the detector is intentionally disabled (too
# false-positive-prone without context, e.g. a bare 40-char AWS secret). detect()
# skips empty patterns.
BUILTINS: tuple[Detector, ...] = (
    Detector("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS_KEY"),
    Detector("aws_secret_key", "", "AWS_SECRET"),  # disabled: bare 40-char b64 over-fires
    Detector("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b", "GH_TOKEN"),
    Detector("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{16,}\b", "ANTHROPIC_KEY"),
    Detector("openai_key", r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b", "OPENAI_KEY"),
    Detector("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "SLACK_TOKEN"),
    Detector("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "GOOGLE_KEY"),
    Detector(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        "PRIVATE_KEY",
    ),
    Detector("jwt", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT", _jwt_ok),
    Detector("bearer_token", r"\bBearer\s+[A-Za-z0-9._\-]{20,}", "BEARER"),
    Detector("connection_string", r"\b[a-z][a-z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+", "CONN_STR"),
    Detector("credit_card", r"\b\d(?:[ -]?\d){12,18}\b", "CC", _luhn_ok),
    Detector("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
    Detector("phone", r"\+\d[\d\s().\-]{7,}\d", "PHONE"),
    Detector("ip_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP", _ipv4_ok),
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
