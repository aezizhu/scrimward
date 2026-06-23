"""OpenAI Chat Completions adapter.

Where the text lives (``POST /v1/chat/completions``):

- ``messages[].content`` — a string OR a list of parts; redact the ``text`` of
  each ``{"type": "text", "text": ...}`` part.
- ``tools[].function.description`` — free text, redacted too.

Streamed response (SSE): text arrives in ``choices[].delta.content`` on each
``data:`` chunk (terminated by ``data: [DONE]``). The un-masker rewrites that
``content``, carry-buffering any token that splits across two chunks. The SSE
framing + token carry helpers are shared with the Anthropic adapter.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping

from ..engine import Redactor
from ..vault import Vault
from .anthropic import (
    _find_sse_event_terminator,
    _parse_sse_event,
    _split_unmaskable,
)

CHAT_COMPLETIONS_PATH = "/v1/chat/completions"


class OpenAIChatAdapter:
    """Adapter for the OpenAI Chat Completions API."""

    def matches(self, path: str, headers: Mapping[str, str]) -> bool:
        """Own exactly ``POST /v1/chat/completions`` (query strings tolerated)."""
        clean = path.split("?", 1)[0].rstrip("/")
        return clean == CHAT_COMPLETIONS_PATH

    def redact_request(self, body: bytes, red: Redactor) -> bytes:
        """Redact ``messages[].content`` + tool descriptions, reserialize.

        FAIL-CLOSED: raise on a body that is not a JSON object — the proxy turns
        that into a 5xx and forwards NOTHING.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"openai_chat: request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"openai_chat: request body must be a JSON object, got {type(data).__name__}"
            )

        messages = data.get("messages")
        if messages is not None:
            if not isinstance(messages, list):
                raise ValueError("openai_chat: 'messages' must be a list")
            for msg in messages:
                if isinstance(msg, dict) and "content" in msg:
                    msg["content"] = self._redact_content(msg["content"], red)

        tools = data.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                fn = tool.get("function") if isinstance(tool, dict) else None
                if isinstance(fn, dict) and isinstance(fn.get("description"), str):
                    fn["description"] = red.redact_text(fn["description"])

        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _redact_content(self, content: object, red: Redactor) -> object:
        """Redact a ``content`` value: a string OR a list of parts."""
        if isinstance(content, str):
            return red.redact_text(content)
        if isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("text"), str)
                ):
                    part["text"] = red.redact_text(part["text"])
            return content
        # null content (assistant tool-call messages) — nothing to redact.
        return content

    async def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
        """Un-mask ``choices[].delta.content`` tokens, cross-chunk safe.

        SSE-event reassembly (byte buffer) defends against UTF-8/event splits;
        a text carry holds back any trailing open ``«…`` token tail until its
        ``»`` arrives in a later chunk. ``data: [DONE]`` and non-content events
        pass through verbatim; a residual carry is flushed at stream end.
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
                out, token_carry = self._rewrite_event(
                    event_bytes, terminator, vault, token_carry
                )
                yield out

        if sse_buf:
            out, token_carry = self._rewrite_event(bytes(sse_buf), b"", vault, token_carry)
            yield out
        if token_carry:
            yield vault.unmask(token_carry).encode("utf-8")

    def _rewrite_event(
        self, event_bytes: bytes, terminator: bytes, vault: Vault, token_carry: str
    ) -> tuple[bytes, str]:
        passthrough = event_bytes + terminator
        _name, data_str = _parse_sse_event(event_bytes)
        if data_str is None or data_str == "[DONE]":
            if data_str == "[DONE]" and token_carry:
                return vault.unmask(token_carry).encode("utf-8") + passthrough, ""
            return passthrough, token_carry

        try:
            obj = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return passthrough, token_carry

        choices = obj.get("choices") if isinstance(obj, dict) else None
        if not isinstance(choices, list):
            return passthrough, token_carry

        changed = False
        new_carry = token_carry
        for choice in choices:
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                combined = new_carry + delta["content"]
                safe, new_carry = _split_unmaskable(combined)
                delta["content"] = vault.unmask(safe)
                changed = True
        if not changed:
            return passthrough, token_carry

        data_line = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        term = terminator if terminator else b"\n\n"
        return data_line.encode("utf-8") + term, new_carry
