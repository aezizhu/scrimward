"""The ``Adapter`` Protocol — the per-provider body contract.

An adapter knows three things about one provider's wire format:

1. :meth:`matches` — does this adapter handle the given request path/headers?
2. :meth:`redact_request` — parse the JSON body, redact the text fields the
   provider puts user content in, and reserialize. **RAISE on an unparseable /
   unexpected body** — that raise is what makes the proxy fail closed.
3. :meth:`unmask_stream` — rewrite the provider's streamed SSE response, swapping
   masked tokens back to real secrets, and doing so in a way that is safe across
   chunk boundaries (a token that splits across two SSE deltas must be
   reassembled, not corrupted).

Adapters satisfy this Protocol **structurally** — concrete adapters do not need
to subclass it; they only need to provide methods with matching signatures.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Protocol, runtime_checkable

from ..engine import Redactor
from ..vault import Vault


@runtime_checkable
class Adapter(Protocol):
    """Structural contract every per-provider body adapter implements."""

    def matches(self, path: str, headers: Mapping[str, str]) -> bool:
        """Return ``True`` if this adapter handles the given request.

        Called by the proxy for each incoming request, in registry order; the
        first adapter to return ``True`` owns the request. Match on the request
        ``path`` (e.g. ``/v1/messages``) and, when needed, headers. Returning
        ``False`` from every adapter is a fail-closed condition (unknown path →
        the proxy blocks).
        """
        ...

    def redact_request(self, body: bytes, red: Redactor) -> bytes:
        """Parse ``body`` as this provider's JSON, redact text, reserialize.

        Locate the text fields where the provider carries user content (system
        prompt, ``messages[].content`` as string or content blocks, …), run each
        through ``red.redact_text``, and return the re-encoded JSON bytes.

        FAIL-CLOSED: if ``body`` is not valid JSON or does not have the expected
        shape, **raise** — the proxy turns that into a 5xx and forwards NOTHING.
        Never return the original bytes on error.
        """
        ...

    def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
        """Rewrite the streamed SSE response, un-masking tokens.

        Consumes the upstream byte stream and yields the same SSE bytes with
        every known token (``«PREFIX_salt_N»``) replaced by its real secret from
        ``vault``. Must be **cross-chunk safe**: carry-buffer a trailing partial
        token (or partial SSE event) so a token that straddles two deltas is
        reassembled before substitution — never emit a half-substituted token.

        Returns an async iterator of the rewritten bytes (an ``async def`` /
        ``async for`` generator).
        """
        ...
