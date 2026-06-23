"""Anthropic Messages adapter.

Where the text lives (Anthropic Messages, ``POST /v1/messages``):

- ``system`` — a string OR a list of ``{"type": "text", "text": ...}`` blocks.
- ``messages[].content`` — a string OR a list of content blocks; redact the
  ``text`` of each ``{"type": "text", ...}`` block (and tool-result text).

Streamed response (SSE): text arrives in ``content_block_delta`` events whose
``delta`` is ``{"type": "text_delta", "text": "…"}``. The un-masker rewrites the
``text`` of those deltas, carry-buffering any token that splits across two
deltas.

This adapter satisfies the :class:`~scrimward.adapters.base.Adapter` Protocol
structurally (no inheritance required).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping

from ..engine import Redactor
from ..vault import TOKEN_CLOSE, TOKEN_OPEN, Vault

# Request path this adapter owns.
MESSAGES_PATH = "/v1/messages"

# SSE event terminators (model: Headroom helpers ``_SSE_EVENT_TERMINATORS``).
# A complete event ends at the first of these; partial tail bytes are carried.
_SSE_EVENT_TERMINATORS: tuple[bytes, ...] = (b"\n\n", b"\r\n\r\n")


def _find_sse_event_terminator(buf: bytearray) -> tuple[int, int] | None:
    """Return ``(index, terminator_len)`` of the earliest complete event end.

    Model: Headroom ``proxy/helpers._find_sse_event_terminator``. Operates on
    bytes so a multi-byte UTF-8 char split across reads is never decoded until
    its whole event has arrived. Returns ``None`` when no complete event is
    buffered yet (all bytes are a partial tail to carry).
    """
    matches = [
        (idx, len(terminator))
        for terminator in _SSE_EVENT_TERMINATORS
        if (idx := buf.find(terminator)) != -1
    ]
    if not matches:
        return None
    return min(matches, key=lambda match: match[0])


def _parse_sse_event(event_bytes: bytes) -> tuple[str | None, str | None]:
    """Decode one complete SSE event's bytes into ``(event_name, data_str)``.

    Decoding a COMPLETE event must succeed — invalid UTF-8 here means the
    upstream emitted a broken frame, which we surface loudly (raise) rather
    than silently corrupting. ``data_str`` is ``None`` when the event carries
    no ``data:`` line (e.g. a bare comment / keep-alive ``:ping``); per spec
    multiple ``data:`` lines join with ``\\n``.
    """
    event_text = event_bytes.decode("utf-8")
    event_name: str | None = None
    data_lines: list[str] = []
    for line in event_text.splitlines():
        if not line or line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[len("event:") :].lstrip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:") :].lstrip())
    data_str = "\n".join(data_lines) if data_lines else None
    return event_name, data_str


def _split_unmaskable(text: str) -> tuple[str, str]:
    """Split ``text`` into ``(safe, carry)`` at a trailing partial token.

    A typed token is ``«PREFIX_salt_N»``. If ``text`` ends with an *open*
    ``«`` that has no matching ``»`` after it, that tail may be the first half
    of a token whose remainder lands in a later SSE delta — so it is returned
    as ``carry`` (held back, un-touched) while everything before the ``«`` is
    safe to un-mask now. When the last ``«`` is already closed by a later
    ``»`` the whole string is safe (``carry == ""``).
    """
    open_idx = text.rfind(TOKEN_OPEN)
    if open_idx == -1:
        return text, ""
    # If a close marker appears after the last open, the trailing token is
    # complete (and any earlier tokens are too) — nothing to carry.
    if text.find(TOKEN_CLOSE, open_idx) != -1:
        return text, ""
    return text[:open_idx], text[open_idx:]


class AnthropicAdapter:
    """Adapter for the Anthropic Messages API."""

    def matches(self, path: str, headers: Mapping[str, str]) -> bool:
        """Return ``True`` for the Anthropic Messages endpoint.

        Owns exactly ``POST /v1/messages`` (query strings tolerated). Path is
        the sole discriminator; auth/version headers pass through verbatim and
        are not needed to route. Returning ``False`` lets the proxy fall to the
        next adapter, or — if none match — fail closed.
        """
        clean = path.split("?", 1)[0].rstrip("/")
        return clean == MESSAGES_PATH

    def redact_request(self, body: bytes, red: Redactor) -> bytes:
        """Redact ``system`` + ``messages[].content`` text, reserialize.

        FAIL-CLOSED: any failure to parse the body as a JSON object, or a body
        that does not have the expected Messages shape, RAISES — the proxy
        turns that into a 5xx and forwards NOTHING. The original bytes are
        never returned.

        Walk:

        - ``system``: a ``str`` (redacted whole) or a list of ``{"type":
          "text", "text": ...}`` blocks (each block's ``text`` redacted).
        - ``messages[*]["content"]``: a ``str`` or a list of content blocks;
          for ``type == "text"`` redact ``text``; for ``tool_result`` recurse
          into its ``content`` (str or nested text blocks).

        Re-serialization is compact and key-order-preserving so the redacted
        bytes stay stable across turns (Anthropic prompt-cache survival).
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            # Unparseable body → fail closed. Never forward originals.
            raise ValueError(f"anthropic: request body is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(
                "anthropic: request body must be a JSON object, "
                f"got {type(data).__name__}"
            )

        if "system" in data:
            data["system"] = self._redact_system(data["system"], red)

        if "messages" in data:
            messages = data["messages"]
            if not isinstance(messages, list):
                raise ValueError(
                    "anthropic: 'messages' must be a list, "
                    f"got {type(messages).__name__}"
                )
            data["messages"] = [self._redact_message(m, red) for m in messages]

        # Compact, deterministic re-encode (no spaces) — non-ASCII secrets are
        # preserved verbatim (ensure_ascii=False) so token bytes round-trip.
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _redact_system(self, system: object, red: Redactor) -> object:
        """Redact the ``system`` field (str OR list of text blocks)."""
        if isinstance(system, str):
            return red.redact_text(system)
        if isinstance(system, list):
            return [self._redact_block(block, red) for block in system]
        raise ValueError(
            "anthropic: 'system' must be a string or a list of blocks, "
            f"got {type(system).__name__}"
        )

    def _redact_message(self, message: object, red: Redactor) -> object:
        """Redact one ``messages[]`` entry's ``content`` (str OR blocks)."""
        if not isinstance(message, dict):
            raise ValueError(
                "anthropic: each message must be an object, "
                f"got {type(message).__name__}"
            )
        if "content" not in message:
            # A message with no content is not the shape we redact — refuse
            # rather than silently forwarding an un-inspected message.
            raise ValueError("anthropic: message is missing required 'content'")
        message["content"] = self._redact_content(message["content"], red)
        return message

    def _redact_content(self, content: object, red: Redactor) -> object:
        """Redact a ``content`` value: a string OR a list of content blocks."""
        if isinstance(content, str):
            return red.redact_text(content)
        if isinstance(content, list):
            return [self._redact_block(block, red) for block in content]
        raise ValueError(
            "anthropic: 'content' must be a string or a list of blocks, "
            f"got {type(content).__name__}"
        )

    def _redact_block(self, block: object, red: Redactor) -> object:
        """Redact one content block.

        - ``{"type": "text", "text": ...}`` → redact ``text``.
        - ``{"type": "tool_result", "content": ...}`` → recurse into
          ``content`` (a str or nested text blocks; tool output frequently
          carries the very secrets we must mask).
        - Any other block type (image, tool_use, document, …) carries no user
          free-text to redact and is passed through untouched.

        A ``text`` block whose ``text`` is not a string is a malformed body →
        fail closed (raise) rather than forward it un-redacted.
        """
        if not isinstance(block, dict):
            raise ValueError(
                "anthropic: content block must be an object, "
                f"got {type(block).__name__}"
            )
        btype = block.get("type")
        if btype == "text":
            text = block.get("text")
            if not isinstance(text, str):
                raise ValueError(
                    "anthropic: text block 'text' must be a string, "
                    f"got {type(text).__name__}"
                )
            block["text"] = red.redact_text(text)
        elif btype == "tool_result":
            if "content" in block:
                block["content"] = self._redact_content(block["content"], red)
        return block

    async def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
        """Un-mask tokens in ``content_block_delta`` text, cross-chunk safe.

        Two layers of carry-buffering keep this correct across arbitrary TCP
        chunk boundaries:

        1. **SSE-event reassembly** (byte buffer): bytes accumulate in
           ``sse_buf``; only events terminated by ``\\n\\n`` / ``\\r\\n\\r\\n``
           are drained and decoded, so a UTF-8 char (or a whole event) split
           across chunks is never decoded half-formed.
        2. **Token reassembly** (text carry): a typed token
           (``«PREFIX_salt_N»``) may straddle two ``text_delta`` events. After
           reassembling each delta's text we hold back any trailing *open*
           ``«…`` tail (``token_carry``) until the closing ``»`` arrives in a
           later delta, so ``vault.unmask`` only ever sees whole tokens — a
           half-substituted token is never emitted.

        ``content_block_delta`` (``text_delta``) and ``message_delta`` events
        are rewritten; all other events (``message_start``, ``ping``,
        ``content_block_start/stop``, ``message_stop`` …) pass through with
        their bytes preserved exactly so ``usage`` / cache frames are intact.
        On ``message_stop`` (and at stream end) any residual ``token_carry`` is
        flushed un-masked so no buffered text is ever dropped.
        """
        sse_buf = bytearray()
        token_carry = ""

        async for chunk in aiter_bytes:
            if not chunk:
                continue
            sse_buf.extend(chunk)
            while True:
                match = _find_sse_event_terminator(sse_buf)
                if match is None:
                    break
                idx, term_len = match
                event_bytes = bytes(sse_buf[:idx])
                terminator = bytes(sse_buf[idx : idx + term_len])
                del sse_buf[: idx + term_len]

                out_bytes, token_carry = self._rewrite_event(
                    event_bytes, terminator, vault, token_carry
                )
                yield out_bytes

        # Stream ended. Drain anything still buffered as a (possibly partial)
        # final event, then flush a residual token carry so nothing is lost.
        if sse_buf:
            event_bytes = bytes(sse_buf)
            sse_buf.clear()
            out_bytes, token_carry = self._rewrite_event(
                event_bytes, b"", vault, token_carry
            )
            yield out_bytes
        if token_carry:
            # No further deltas can complete this tail — emit it un-masked
            # (best effort) so buffered text is never silently dropped.
            yield vault.unmask(token_carry).encode("utf-8")

    def _rewrite_event(
        self, event_bytes: bytes, terminator: bytes, vault: Vault, token_carry: str
    ) -> tuple[bytes, str]:
        """Rewrite one complete SSE event; return ``(out_bytes, new_carry)``.

        Only ``content_block_delta``/``message_delta`` text is un-masked (with
        token carry-buffering); every other event — and any event we cannot
        confidently rewrite — is passed through byte-for-byte. Passing an event
        through verbatim while a non-empty ``token_carry`` is pending would
        reorder text, so the carry is flushed by prepending it to the next
        rewritable delta; on terminal/non-text events it is flushed inline.
        """
        event_name, data_str = _parse_sse_event(event_bytes)
        passthrough = event_bytes + terminator

        # No data payload (comment/keep-alive) — pass through, keep carry.
        if data_str is None or data_str == "[DONE]":
            return passthrough, token_carry

        try:
            obj = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            # Un-parseable data frame: never corrupt it. Pass through verbatim;
            # the carry stays pending for a later well-formed delta.
            return passthrough, token_carry

        etype = obj.get("type") if isinstance(obj, dict) else None

        # --- content_block_delta with a text_delta → un-mask its text ---
        if etype == "content_block_delta" and isinstance(obj.get("delta"), dict):
            delta = obj["delta"]
            if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
                combined = token_carry + delta["text"]
                safe, new_carry = _split_unmaskable(combined)
                delta["text"] = vault.unmask(safe)
                out = self._reserialize(event_name, obj, terminator)
                return out, new_carry
            return passthrough, token_carry

        # --- message_delta → un-mask any text the model echoes here ---
        if etype == "message_delta" and isinstance(obj.get("delta"), dict):
            delta = obj["delta"]
            if isinstance(delta.get("text"), str):
                combined = token_carry + delta["text"]
                safe, new_carry = _split_unmaskable(combined)
                delta["text"] = vault.unmask(safe)
                out = self._reserialize(event_name, obj, terminator)
                return out, new_carry
            return passthrough, token_carry

        # --- message_stop (and content_block_stop): flush residual carry ---
        if etype in ("message_stop", "content_block_stop"):
            if token_carry:
                flushed = vault.unmask(token_carry).encode("utf-8")
                return flushed + passthrough, ""
            return passthrough, token_carry

        # --- everything else: verbatim, carry preserved ---
        return passthrough, token_carry

    @staticmethod
    def _reserialize(event_name: str | None, obj: object, terminator: bytes) -> bytes:
        """Re-emit a rewritten event as SSE bytes.

        Reproduces the canonical Anthropic SSE framing (``event:`` line then a
        single compact ``data:`` line) and re-uses the original event's
        terminator so byte framing downstream is unchanged. ``ensure_ascii``
        is off so un-masked non-ASCII secrets survive intact.
        """
        data_line = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        if event_name is not None:
            head = f"event: {event_name}\n{data_line}"
        else:
            head = data_line
        term = terminator if terminator else b"\n\n"
        return head.encode("utf-8") + term
