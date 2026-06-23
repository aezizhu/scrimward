"""Runtime configuration for the Scrimward proxy.

Single source of truth for *where* the proxy listens, *where* it forwards,
*which* rules/allowlist apply, and *where/how* the vault is persisted.

Environment variables (all optional; local-first defaults):

- ``REDACT_UPSTREAM`` — upstream base URL. Default ``https://api.anthropic.com``.
- ``REDACT_HOST``     — bind host. Default ``127.0.0.1`` (never 0.0.0.0 by default).
- ``REDACT_PORT``     — bind port. Default ``8788``.
- ``REDACT_RULES``    — path to the user rules + allowlist JSON (gitignored).
- ``REDACT_VAULT``    — on-disk vault path. Default in-memory only (None).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_UPSTREAM = "https://api.anthropic.com"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788
DEFAULT_RULES_PATH = "config/rules.json"

ENV_UPSTREAM = "REDACT_UPSTREAM"
ENV_HOST = "REDACT_HOST"
ENV_PORT = "REDACT_PORT"
ENV_RULES = "REDACT_RULES"
ENV_VAULT = "REDACT_VAULT"


@dataclass(frozen=True)
class UserRule:
    """A user-declared redaction rule (precise by construction)."""

    name: str
    pattern: str
    token_prefix: str


@dataclass(frozen=True)
class Allowlist:
    """Known-safe values that match a detector pattern but are NOT secrets."""

    literals: frozenset[str] = field(default_factory=frozenset)
    patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    """Resolved Scrimward runtime configuration."""

    upstream: str = DEFAULT_UPSTREAM
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    rules_path: Path = field(default_factory=lambda: Path(DEFAULT_RULES_PATH))
    vault_path: Path | None = None
    user_rules: tuple[UserRule, ...] = ()
    allowlist: Allowlist = field(default_factory=Allowlist)


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
        user_rules=user_rules,
        allowlist=allowlist,
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
            token_prefix=str(r.get("token_prefix", "CUSTOM")),
        )
        for r in data.get("rules", [])
    )
    al = data.get("allowlist", {}) or {}
    allowlist = Allowlist(
        literals=frozenset(al.get("literals", [])),
        patterns=tuple(al.get("patterns", [])),
    )
    return rules, allowlist
