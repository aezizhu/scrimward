"""Runtime configuration for the Scrimward proxy.

Single source of truth for *where* the proxy listens, *where* it forwards,
*which* rules/allowlist apply, and *where/how* the vault is persisted.

Environment variables (all optional; local-first defaults):

- ``REDACT_UPSTREAM`` — upstream base URL. Default ``https://api.anthropic.com``.
- ``REDACT_HOST``     — bind host. Default ``127.0.0.1`` (never 0.0.0.0 by default).
- ``REDACT_PORT``     — bind port. Default ``8788``.
- ``REDACT_RULES``    — path to the user rules + allowlist JSON (gitignored).
- ``REDACT_VAULT``    — on-disk vault path. Default in-memory only (None).
- ``REDACT_VAULT_ENCRYPT`` — opt-in: the token IS AES-SIV ciphertext, so the
  vault keeps NO cleartext at rest (needs the ``vault-encrypt`` extra). Off by default.
- ``REDACT_IMAGES``   — opt-in on-device image redaction via Apple Vision (macOS;
  needs the ``image`` extra). Off by default → images fail closed.
- ``REDACT_ENTROPY``  — opt-in: enable the shapeless high-entropy catch-all that
  masks un-prefixed secrets. Off by default (it also masks git SHAs / hashes /
  UUIDs, which is noisy in coding prompts).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .vault import normalize_token_prefix

DEFAULT_UPSTREAM = "https://api.anthropic.com"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788
DEFAULT_RULES_PATH = "config/rules.json"

ENV_UPSTREAM = "REDACT_UPSTREAM"
ENV_HOST = "REDACT_HOST"
ENV_PORT = "REDACT_PORT"
ENV_RULES = "REDACT_RULES"
ENV_VAULT = "REDACT_VAULT"
ENV_VAULT_ENCRYPT = "REDACT_VAULT_ENCRYPT"
ENV_IMAGES = "REDACT_IMAGES"
ENV_ENTROPY = "REDACT_ENTROPY"

# Truthy values that enable on-device image redaction (macOS + Apple Vision).
_TRUTHY = frozenset({"1", "true", "on", "yes", "strict"})


@dataclass(frozen=True)
class UserRule:
    """A user-declared redaction rule (precise by construction)."""

    name: str
    pattern: str
    token_prefix: str


@dataclass(frozen=True)
class Allowlist:
    """Known-safe values that match a detector pattern but are NOT secrets.

    ``hashes`` allowlists by lowercase SHA-256 hex of the matched text, so a
    reviewed false positive can be suppressed without storing the raw value in
    config (a privacy win over ``literals`` — borrowed from ggshield).
    """

    literals: frozenset[str] = field(default_factory=frozenset)
    patterns: tuple[str, ...] = ()
    hashes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Config:
    """Resolved Scrimward runtime configuration."""

    upstream: str = DEFAULT_UPSTREAM
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    rules_path: Path = field(default_factory=lambda: Path(DEFAULT_RULES_PATH))
    vault_path: Path | None = None
    vault_encrypt: bool = False
    user_rules: tuple[UserRule, ...] = ()
    allowlist: Allowlist = field(default_factory=Allowlist)
    redact_images: bool = False
    detect_entropy: bool = False


def load(*, rules_path: str | os.PathLike[str] | None = None) -> Config:
    """Resolve a :class:`Config` from environment + the rules file.

    Precedence: explicit ``rules_path`` > env var > default. A *present but
    unparseable* rules file raises (fail-closed) via :func:`load_rules`.
    """
    upstream = os.environ.get(ENV_UPSTREAM, DEFAULT_UPSTREAM)
    host = os.environ.get(ENV_HOST, DEFAULT_HOST)
    port = int(os.environ.get(ENV_PORT, str(DEFAULT_PORT)))

    rp = rules_path if rules_path is not None else os.environ.get(ENV_RULES, DEFAULT_RULES_PATH)
    rules_path_p = Path(rp)

    vault_env = os.environ.get(ENV_VAULT)
    vault_path = Path(vault_env) if vault_env else None
    vault_encrypt = os.environ.get(ENV_VAULT_ENCRYPT, "").strip().lower() in _TRUTHY

    redact_images = os.environ.get(ENV_IMAGES, "").strip().lower() in _TRUTHY
    detect_entropy = os.environ.get(ENV_ENTROPY, "").strip().lower() in _TRUTHY

    if rules_path_p.exists():
        user_rules, allowlist = load_rules(rules_path_p)
    else:
        user_rules, allowlist = (), Allowlist()

    return Config(
        upstream=upstream,
        host=host,
        port=port,
        rules_path=rules_path_p,
        vault_path=vault_path,
        vault_encrypt=vault_encrypt,
        user_rules=user_rules,
        allowlist=allowlist,
        redact_images=redact_images,
        detect_entropy=detect_entropy,
    )


def load_rules(path: str | os.PathLike[str]) -> tuple[tuple[UserRule, ...], Allowlist]:
    """Parse user rules + allowlist from a JSON file.

    Returns ``(user_rules, allowlist)``. A missing file → empty rules + empty
    allowlist (a valid state). A present-but-unparseable file RAISES — a broken
    rules file is a fail-closed condition, not a silent "redact nothing".
    """
    p = Path(path)
    if not p.exists():
        return (), Allowlist()
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("scrimward rules file must be a JSON object")
    rules = tuple(
        UserRule(
            name=str(r["name"]),
            pattern=str(r["pattern"]),
            # Normalize at the boundary so a bad prefix in the rules file fails
            # closed at load (not at first request) and stays reversible.
            token_prefix=normalize_token_prefix(str(r.get("token_prefix", "CUSTOM"))),
        )
        for r in data.get("rules", [])
    )
    al = data.get("allowlist", {}) or {}
    allowlist = Allowlist(
        literals=frozenset(al.get("literals", [])),
        patterns=tuple(al.get("patterns", [])),
        hashes=frozenset(h.lower() for h in al.get("hashes", [])),
    )
    return rules, allowlist
