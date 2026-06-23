"""The session vault — reversible token <-> secret mapping.

The vault makes redaction *reversible*: the engine mints a stable typed token via
:meth:`Vault.token_for`, and the proxy calls :meth:`Vault.unmask` on the streamed
reply to swap the token back for the real value locally — so the user sees a
complete answer while the secret never left the machine.

Determinism is load-bearing for correctness AND prompt-cache survival: the same
secret maps to the **same** token for the whole session (so redacted bytes are
stable across turns). The per-session ``salt`` is minted once at construction;
token shape is ``«PREFIX_<salt>_N»`` with a per-prefix counter ``N``.

Persistence: in-memory by default (session-lifetime, never written). When backed
by a file it is created ``0600`` inside a ``0700`` directory — it holds real
secrets in cleartext and must never be group/world readable.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from contextvars import ContextVar
from pathlib import Path

VAULT_FILE_MODE = 0o600
VAULT_DIR_MODE = 0o700

# Guillemets are rare in real content, so tokens are reliable to locate.
TOKEN_OPEN = "«"
TOKEN_CLOSE = "»"

# Token grammar for scanning a reply: «UPPER_PREFIX_<6 hex>_<digits>». Matches
# are only substituted when present in this vault's reverse map, so an imperfect
# match never causes a false substitution.
_TOKEN_SCAN = re.compile(r"«[A-Z0-9_]+_[0-9a-f]{6}_\d+»")


class Vault:
    """A session-scoped, reversible token store."""

    def __init__(self, session_id: str, path: Path | None = None) -> None:
        self.session_id = session_id
        self.path = Path(path) if path is not None else None
        self._secret_to_token: dict[str, str] = {}
        self._token_to_secret: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        # Session-constant salt (minted once) → same secret yields same token.
        self._salt: str = secrets.token_hex(3)  # 6 hex chars
        if self.path is not None and self.path.exists():
            self._load()

    def token_for(self, secret: str, prefix: str) -> str:
        """Return the stable token for ``secret`` under family ``prefix``.

        Mints ``«PREFIX_<salt>_N»`` on first sight, dedups thereafter, and
        persists when file-backed.
        """
        existing = self._secret_to_token.get(secret)
        if existing is not None:
            return existing
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        token = f"{TOKEN_OPEN}{prefix}_{self._salt}_{n}{TOKEN_CLOSE}"
        self._secret_to_token[secret] = token
        self._token_to_secret[token] = secret
        self._persist()
        return token

    def unmask(self, text: str) -> str:
        """Replace every token known to this vault with its real secret.

        Only tokens minted by this vault are substituted; unknown ``«…»`` runs
        are left untouched. The reverse of :meth:`token_for`.
        """
        if not self._token_to_secret or TOKEN_OPEN not in text:
            return text
        return _TOKEN_SCAN.sub(
            lambda m: self._token_to_secret.get(m.group(0), m.group(0)), text
        )

    # --- persistence ------------------------------------------------------

    def _load(self) -> None:
        assert self.path is not None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self._salt = data.get("salt", self._salt)
        self._token_to_secret = dict(data.get("tokens", {}))
        self._secret_to_token = {v: k for k, v in self._token_to_secret.items()}
        for token in self._token_to_secret:
            # «PREFIX_salt_N» → recover the max N per prefix.
            inner = token[len(TOKEN_OPEN) : -len(TOKEN_CLOSE)]
            prefix, _salt, n = inner.rsplit("_", 2)
            self._counters[prefix] = max(self._counters.get(prefix, 0), int(n))

    def _persist(self) -> None:
        """Atomically write the maps to ``self.path`` (0600 file / 0700 dir).

        No-op when in-memory. The file holds cleartext secrets, so the dir is
        forced to ``0700`` and the file to ``0600``.
        """
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, VAULT_DIR_MODE)
        except OSError:
            pass
        payload = json.dumps(
            {"salt": self._salt, "tokens": self._token_to_secret},
            ensure_ascii=False,
        )
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".vault-")
        try:
            os.fchmod(fd, VAULT_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


# --- per-session active-vault ContextVar ---------------------------------

_current_vault: ContextVar[Vault | None] = ContextVar("scrimward_current_vault", default=None)


def current_vault() -> Vault | None:
    """Return the vault bound to the current execution context, if any."""
    return _current_vault.get()


def set_current_vault(vault: Vault | None) -> object:
    """Bind ``vault`` as the current-context vault; return the reset token."""
    return _current_vault.set(vault)
