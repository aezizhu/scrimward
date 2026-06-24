"""Google Gemini adapter — native generateContent + Cloud Code Assist (Gemini CLI).

Two request envelopes (the adapter detects which):

- **Native** (API-key / Vertex): ``POST .../models/{model}:generateContent``
  with top-level ``contents[].parts[].text`` + ``systemInstruction.parts[].text``.
- **Cloud Code Assist** (the Gemini CLI's default "Login with Google" path):
  ``POST .../v1internal:streamGenerateContent`` where the real payload is wrapped
  under ``request`` — ``request.contents[]…`` + ``request.systemInstruction`` — and
  ``model`` / ``project`` are routing IDs that must NOT be touched.

``functionCall`` / ``functionResponse`` parts are preserved. Binary parts
(``inlineData`` / ``fileData`` — images, PDFs, audio) are un-redactable today,
so they FAIL CLOSED: the request is refused rather than forwarded un-redacted.

Streamed response (``alt=sse``): bare ``data: {GenerateContentResponse}`` lines
(no ``event:`` names). The un-masker rewrites ``candidates[].content.parts[].text``,
carry-buffering a token that splits across parts/chunks. SSE framing helpers are
shared with the Anthropic adapter.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator, Mapping

from ..engine import Redactor
from ..image_redactor import (
    ImageRedactionError,
    image_redaction_available,
    redact_image_bytes,
    redact_pdf_bytes,
)
from ..vault import Vault
from .anthropic import _find_sse_event_terminator, _parse_sse_event, _split_unmaskable
from .base import AttachmentRedactionUnsupported


def _is_binary_attachment_part(part: dict) -> bool:
    """True if a Gemini ``parts[]`` entry carries an inline/file binary blob.

    Free text rides in ``text`` parts; anything in ``inlineData`` (base64) or
    ``fileData`` (URI) is non-text binary — an image, PDF, audio clip, etc. —
    that the text-only engine cannot redact, so ANY such part fails closed
    (keying on ``image/*`` mime alone would leak a base64 PDF of the same
    screenshot). REST/CCA use camelCase, proto JSON snake_case; both checked.
    """
    return any(
        isinstance(part.get(blob_key), dict)
        for blob_key in ("inlineData", "inline_data", "fileData", "file_data")
    )


class GeminiAdapter:
    """Adapter for Google Gemini (native + Cloud Code Assist envelopes)."""

    def matches(self, path: str, headers: Mapping[str, str]) -> bool:
        p = path.split("?", 1)[0].lower()
        return "generatecontent" in p or "v1internal" in p

    def redact_request(self, body: bytes, red: Redactor) -> bytes:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"gemini: request body is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"gemini: request body must be a JSON object, got {type(data).__name__}")

        # Cloud Code Assist wraps the real payload under "request"; redact there
        # and leave the outer model/project routing IDs untouched.
        if isinstance(data.get("request"), dict) and "contents" in data["request"]:
            self._redact_envelope(data["request"], red)
        else:
            self._redact_envelope(data, red)

        # Deny-by-default backstop: redact any un-enumerated text field
        # (functionCall.args, functionResponse.response = tool output, …). Routing
        # IDs (model/project) are non-secret text and pass through unchanged.
        red.redact_object(data)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _redact_envelope(self, env: dict, red: Redactor) -> None:
        for key in ("systemInstruction", "system_instruction"):
            if key in env:
                env[key] = self._redact_content_like(env[key], red)
        contents = env.get("contents")
        if isinstance(contents, list):
            for content in contents:
                self._redact_content_like(content, red)

    def _redact_content_like(self, obj: object, red: Redactor) -> object:
        """Redact a Content / systemInstruction (a str, or ``{parts:[{text}]}``)."""
        if isinstance(obj, str):
            return red.redact_text(obj)
        if isinstance(obj, dict):
            parts = obj.get("parts")
            if isinstance(parts, list):
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    if _is_binary_attachment_part(part):
                        self._redact_binary_part(part, red)
                    elif isinstance(part.get("text"), str):
                        part["text"] = red.redact_text(part["text"])
            return obj
        return obj

    def _redact_binary_part(self, part: dict, red: Redactor) -> None:
        """Redact an inline base64 IMAGE part in place, or fail closed.

        Only ``inlineData`` (base64) with an ``image/*`` MIME is redactable;
        ``fileData`` (a URI we can't fetch) and non-image inline blobs (PDF /
        audio) always fail closed.
        """
        blob = None
        for key in ("inlineData", "inline_data"):
            if isinstance(part.get(key), dict):
                blob = part[key]
                break
        mime = (blob.get("mimeType") or blob.get("mime_type") or "").lower() if blob else ""
        is_image = blob and mime.startswith("image/")
        is_pdf = blob and mime == "application/pdf"
        if not (is_image or is_pdf):  # fileData (URI) / audio / other → fail closed
            raise AttachmentRedactionUnsupported(
                "gemini: request contains a non-image/non-PDF or URI binary part, "
                "which cannot be redacted — refusing to forward it (fail-closed)"
            )
        gate = red.redact_pdf if is_pdf else red.redact_images
        if not (gate and image_redaction_available()):
            kind = "PDF" if is_pdf else "image"
            raise AttachmentRedactionUnsupported(
                f"gemini: request contains an inline {kind} and {kind} redaction "
                "is off/unavailable — refusing to forward it (fail-closed)"
            )
        try:
            raw = base64.b64decode(blob.get("data", ""), validate=True)
            redacted = redact_pdf_bytes(raw) if is_pdf else redact_image_bytes(raw, mime)
        except (ImageRedactionError, ValueError, TypeError) as exc:
            raise AttachmentRedactionUnsupported(
                f"gemini: attachment could not be safely redacted ({exc}) — "
                "refusing to forward it (fail-closed)"
            ) from exc
        blob["data"] = base64.b64encode(redacted).decode("ascii")

    async def unmask_stream(
        self, aiter_bytes: AsyncIterator[bytes], vault: Vault
    ) -> AsyncIterator[bytes]:
        sse_buf = bytearray()
        carry = ""
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
                out, carry = self._rewrite(event_bytes, terminator, vault, carry)
                yield out
        if sse_buf:
            out, carry = self._rewrite(bytes(sse_buf), b"", vault, carry)
            yield out
        if carry:
            yield vault.unmask(carry).encode("utf-8")

    def _rewrite(self, event_bytes: bytes, terminator: bytes, vault: Vault, carry: str) -> tuple[bytes, str]:
        passthrough = event_bytes + terminator
        _name, data_str = _parse_sse_event(event_bytes)
        if data_str is None or data_str == "[DONE]":
            return passthrough, carry
        try:
            obj = json.loads(data_str)
        except (json.JSONDecodeError, ValueError):
            return passthrough, carry
        candidates = obj.get("candidates") if isinstance(obj, dict) else None
        if not isinstance(candidates, list):
            return passthrough, carry

        changed = False
        for cand in candidates:
            content = cand.get("content") if isinstance(cand, dict) else None
            parts = content.get("parts") if isinstance(content, dict) else None
            if not isinstance(parts, list):
                continue
            for part in parts:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    combined = carry + part["text"]
                    safe, carry = _split_unmaskable(combined)
                    part["text"] = vault.unmask(safe)
                    changed = True
        if not changed:
            return passthrough, carry

        data_line = "data: " + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        return data_line.encode("utf-8") + (terminator if terminator else b"\n\n"), carry
