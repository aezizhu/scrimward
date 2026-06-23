"""OpenAI Responses API adapter (``POST /v1/responses``) — used by Codex CLI.

Where the text lives:

- ``instructions`` — the system/developer prompt (a string).
- ``input[]`` — items: ``type:"message"`` carry ``content`` (a string, or parts
  ``{type:"input_text"|"output_text", text}``); tool-output items
  (``function_call_output`` / ``local_shell_call_output`` /
  ``apply_patch_call_output``) carry an ``output`` string (shell stdout, patched
  file contents — high secret density).

NEVER touched: reasoning items' ``encrypted_content`` (an opaque server-signed
blob — mutating it breaks the turn) and ``computer_call_output`` screenshots.

Streamed response (SSE, typed events): text arrives in
``response.output_text.delta`` (``delta``) and
``response.function_call_arguments.delta`` (``delta``); ``response.output_text.done``
carries the full ``text``. The un-masker rewrites those, carry-buffering a token
that splits across deltas. SSE framing helpers are shared with the Anthropic
adapter.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping

from ..engine import Redactor
from ..vault import Vault
from .anthropic import _find_sse_event_terminator, _parse_sse_event, _split_unmaskable

RESPONSES_PATH = "/v1/responses"

_TOOL_OUTPUT_TYPES = frozenset(
    {"function_call_output", "local_shell_call_output", "apply_patch_call_output"}
)
_TEXT_PART_TYPES = frozenset({"input_text", "output_text"})


class OpenAIResponsesAdapter:
    """Adapter for the OpenAI Responses API."""

    def matches(self, path: str, headers: Mapping[str, str]) -> bool:
        return path.split("?", 1)[0].rstrip("/") == RESPONSES_PATH

    def redact_request(self, body: bytes, red: Redactor) -> bytes:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"openai_responses: request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"openai_responses: request body must be a JSON object, got {type(data).__name__}"
            )

        if isinstance(data.get("instructions"), str):
            data["instructions"] = red.redact_text(data["instructions"])

        inp = data.get("input")
        if isinstance(inp, str):
            data["input"] = red.redact_text(inp)
        elif isinstance(inp, list):
            for item in inp:
                self._redact_item(item, red)

        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _redact_item(self, item: object, red: Redactor) -> None:
        if not isinstance(item, dict):
            return
        itype = item.get("type")
        # message content (str or list of {type, text} parts)
        content = item.get("content")
        if isinstance(content, str):
            item["content"] = red.redact_text(content)
        elif isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and isinstance(part.get("text"), str)
                    and part.get("type", "input_text") in _TEXT_PART_TYPES
                ):
                    part["text"] = red.redact_text(part["text"])
        # tool-output strings (shell stdout / patches) — high secret density.
        if itype in _TOOL_OUTPUT_TYPES and isinstance(item.get("output"), str):
            item["output"] = red.redact_text(item["output"])
        # reasoning.encrypted_content / computer_call_output screenshots: untouched.

    async def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
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
                out, token_carry = self._rewrite(event_bytes, terminator, vault, token_carry)
                yield out
        if sse_buf:
            out, token_carry = self._rewrite(bytes(sse_buf), b"", vault, token_carry)
            yield out
        if token_carry:
            yield vault.unmask(token_carry).encode("utf-8")

    def _rewrite(
        self, event_bytes: bytes, terminator: bytes, vault: Vault, carry: str
    ) -> tuple[bytes, str]:
        passthrough = event_bytes + terminator
        name, data_str = _parse_sse_event(event_bytes)
        if data_str is None or data_str == "[DONE]":
            return passthrough, carry
        try:
            obj = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return passthrough, carry
        etype = obj.get("type") if isinstance(obj, dict) else None

        if etype in (
            "response.output_text.delta",
            "response.function_call_arguments.delta",
        ) and isinstance(obj.get("delta"), str):
            combined = carry + obj["delta"]
            safe, new_carry = _split_unmaskable(combined)
            obj["delta"] = vault.unmask(safe)
            return self._reserialize(name, obj, terminator), new_carry

        if etype == "response.output_text.done" and isinstance(obj.get("text"), str):
            obj["text"] = vault.unmask(carry + obj["text"])
            return self._reserialize(name, obj, terminator), ""

        return passthrough, carry

    @staticmethod
    def _reserialize(name: str | None, obj: object, terminator: bytes) -> bytes:
        data_line = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        head = f"event: {name}\n{data_line}" if name is not None else data_line
        term = terminator if terminator else b"\n\n"
        return head.encode("utf-8") + term
