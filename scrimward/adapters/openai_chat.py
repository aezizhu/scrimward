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
from ..image_redactor import (
    ImageRedactionError,
    image_redaction_available,
    redact_data_uri,
    redact_pdf_data_uri,
)
from .base import AttachmentRedactionUnsupported

# Un-redactable binary attachment part types — the engine is text-only, so these
# fail closed. (image_url + file are handled separately: redacted when enabled.)
_BINARY_PART_TYPES = frozenset({"input_audio"})

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

        # Deny-by-default backstop: redact any un-enumerated text field
        # (tool_calls[].function.arguments, function_call.arguments, …).
        red.redact_object(data)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _redact_content(self, content: object, red: Redactor) -> object:
        """Redact a ``content`` value: a string OR a list of parts."""
        if isinstance(content, str):
            return red.redact_text(content)
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    continue
                ptype = part.get("type")
                if ptype == "image_url":
                    self._redact_image_url(part, red)
                elif ptype == "file":
                    self._redact_file(part, red)
                elif ptype in _BINARY_PART_TYPES:  # input_audio → fail closed
                    raise AttachmentRedactionUnsupported(
                        f"openai_chat: message contains a {ptype} part, which "
                        "cannot be redacted yet — refusing to forward it (fail-closed)"
                    )
                elif ptype == "text" and isinstance(part.get("text"), str):
                    part["text"] = red.redact_text(part["text"])
            return content
        # null content (assistant tool-call messages) — nothing to redact.
        return content

    def _redact_image_url(self, part: dict, red: Redactor) -> None:
        """Redact an ``image_url`` part's inline data URI in place, or fail closed."""
        if not (red.redact_images and image_redaction_available()):
            raise AttachmentRedactionUnsupported(
                "openai_chat: message contains an image_url part and image "
                "redaction is off/unavailable — refusing to forward it (fail-closed)"
            )
        img = part.get("image_url")
        try:
            img["url"] = redact_data_uri(img.get("url") if isinstance(img, dict) else None)
        except (ImageRedactionError, AttributeError, TypeError) as exc:
            raise AttachmentRedactionUnsupported(
                f"openai_chat: image could not be safely redacted ({exc}) — "
                "refusing to forward it (fail-closed)"
            ) from exc

    def _redact_file(self, part: dict, red: Redactor) -> None:
        """Redact a ``file`` part's inline PDF (``file.file_data``), or fail closed."""
        if not (red.redact_pdf and image_redaction_available()):
            raise AttachmentRedactionUnsupported(
                "openai_chat: message contains a file part and PDF redaction is "
                "off/unavailable — refusing to forward it (fail-closed)"
            )
        file_obj = part.get("file")
        try:
            file_obj["file_data"] = redact_pdf_data_uri(
                file_obj.get("file_data") if isinstance(file_obj, dict) else None
            )
        except (ImageRedactionError, AttributeError, TypeError) as exc:
            raise AttachmentRedactionUnsupported(
                f"openai_chat: file could not be safely redacted ({exc}) — "
                "refusing to forward it (fail-closed)"
            ) from exc

    async def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
        """Un-mask ``choices[].delta.content`` AND ``delta.tool_calls[].function.
        arguments`` tokens, cross-chunk safe.

        A model that received a masked «TOKEN» echoes it back — into reply text OR
        into a tool call it streams, which the LOCAL tool must receive RESTORED.
        Each token tail is carry-buffered until its closing ``»`` arrives. Carry
        is held PER TARGET — keyed by (choice index, "content" | tool_call index) —
        so a split token in one field/choice can't corrupt another (n>1 / parallel
        tool calls). A residual carry is flushed at stream end.
        """
        sse_buf = bytearray()
        carries: dict[str, str] = {}

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
                out, carries = self._rewrite_event(event_bytes, terminator, vault, carries)
                yield out

        if sse_buf:
            out, carries = self._rewrite_event(bytes(sse_buf), b"", vault, carries)
            yield out
        residual = "".join(carries.values())
        if residual:
            yield vault.unmask(residual).encode("utf-8")

    def _rewrite_event(
        self, event_bytes: bytes, terminator: bytes, vault: Vault, carries: dict[str, str]
    ) -> tuple[bytes, dict[str, str]]:
        passthrough = event_bytes + terminator
        _name, data_str = _parse_sse_event(event_bytes)
        if data_str is None or data_str == "[DONE]":
            if data_str == "[DONE]" and carries:
                flushed = vault.unmask("".join(carries.values())).encode("utf-8")
                return flushed + passthrough, {}
            return passthrough, carries

        try:
            obj = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return passthrough, carries

        choices = obj.get("choices") if isinstance(obj, dict) else None
        if not isinstance(choices, list):
            return passthrough, carries

        changed = False
        for ci, choice in enumerate(choices):
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if not isinstance(delta, dict):
                continue
            cidx = choice.get("index", ci) if isinstance(choice, dict) else ci  # stable across events
            if isinstance(delta.get("content"), str):
                key = f"{cidx}:content"
                combined = carries.get(key, "") + delta["content"]
                safe, carries[key] = _split_unmaskable(combined)
                delta["content"] = vault.unmask(safe)
                changed = True
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    fn = tc.get("function") if isinstance(tc, dict) else None
                    if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                        key = f"{cidx}:tc:{tc.get('index', 0)}"
                        combined = carries.get(key, "") + fn["arguments"]
                        safe, carries[key] = _split_unmaskable(combined)
                        fn["arguments"] = vault.unmask(safe)
                        changed = True
        if not changed:
            return passthrough, carries

        data_line = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        term = terminator if terminator else b"\n\n"
        return data_line.encode("utf-8") + term, carries
