"""Scrimward test suite — unit tests + the load-bearing security tests.

The two tests that matter most for a *redaction* proxy:

- ``test_proxy_canary_e2e`` — a planted secret must be ABSENT from what the
  upstream receives, a token must be PRESENT, and the reply must un-mask back to
  the real value locally (auth header passed through verbatim).
- ``test_proxy_fail_closed_*`` — a body we can't redact (bad JSON / unknown
  path) must be BLOCKED with a 5xx and the upstream must receive ZERO requests.

No real network: a tiny threaded mock upstream stands in for the provider.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.server
import io
import json
import re
import threading

import httpx
import pytest

from scrimward.adapters.anthropic import AnthropicAdapter
from scrimward.adapters.gemini import GeminiAdapter
from scrimward.adapters.openai_chat import OpenAIChatAdapter
from scrimward.adapters.openai_responses import OpenAIResponsesAdapter
from scrimward.config import Allowlist, Config, load_rules
from scrimward.detectors import BUILTINS, detect
from scrimward.image_redactor import image_redaction_available
from scrimward.engine import Redactor
from scrimward.proxy import create_app
from scrimward.vault import Vault

# UTF-8 bytes for the guillemets that delimit a token («…»).
_TOKEN_BYTES_RE = re.compile(rb"\xc2\xab.*?\xc2\xbb", re.DOTALL)


def _run(coro):
    return asyncio.run(coro)


class _MockUpstream:
    """Threaded mock provider: records request bodies, echoes the token in SSE."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        received = self.received

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length", 0))
                body = self.rfile.read(length)
                received.append({"body": body, "headers": dict(self.headers)})
                m = _TOKEN_BYTES_RE.search(body)
                echo = m.group(0).decode("utf-8") if m else "hello"
                sse = (
                    "event: content_block_delta\n"
                    'data: {"type":"content_block_delta","delta":'
                    '{"type":"text_delta","text":%s}}\n\n'
                    "event: message_stop\n"
                    'data: {"type":"message_stop"}\n\n'
                ) % json.dumps(f"reply: {echo}")
                payload = sse.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


async def _post(app, path: str, body: bytes, headers: dict | None = None):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as client:
        resp = await client.post(path, content=body, headers=headers or {})
        text = (await resp.aread()).decode("utf-8")
        return resp.status_code, text


# --- detectors ------------------------------------------------------------


def test_detectors_find_and_validate():
    spans = detect("ping alice@example.com key AKIAIOSFODNN7EXAMPLE done")
    names = {s.name for s in spans}
    assert "email" in names
    assert "aws_access_key" in names
    # Luhn: a valid test card is detected, an invalid 16-digit run is rejected.
    assert any(s.name == "credit_card" for s in detect("pay 4242 4242 4242 4242"))
    assert not any(s.name == "credit_card" for s in detect("id 1234 5678 9012 3456"))


# --- vault ----------------------------------------------------------------


def test_vault_roundtrip_and_stability():
    v = Vault("s1")
    t1 = v.token_for("a@b.com", "EMAIL")
    t2 = v.token_for("a@b.com", "EMAIL")
    assert t1 == t2  # same secret → same token (deterministic)
    assert v.token_for("c@d.com", "EMAIL") != t1
    assert v.unmask(f"write to {t1} please") == "write to a@b.com please"
    assert v.unmask("nothing to see") == "nothing to see"


# --- engine ---------------------------------------------------------------


def test_engine_redacts_and_allowlist():
    out = Redactor(Vault("s")).redact_text("mail alice@example.com")
    assert "alice@example.com" not in out
    assert "«EMAIL_" in out
    allow = Redactor(Vault("s2"), allowlist=Allowlist(literals=frozenset({"alice@example.com"})))
    assert allow.redact_text("mail alice@example.com") == "mail alice@example.com"


def test_allowlist_by_sha256_hash():
    # Allowlist a reviewed value by its hash — no raw secret stored in config.
    val = "alice@example.com"
    h = hashlib.sha256(val.encode("utf-8")).hexdigest()
    r = Redactor(Vault("s"), allowlist=Allowlist(hashes=frozenset({h})))
    assert r.redact_text(f"mail {val}") == f"mail {val}"  # hash-allowlisted → not masked
    # a non-allowlisted email is still redacted.
    assert "«EMAIL_" in r.redact_text("mail bob@example.com")


def test_load_rules_parses_allowlist_hashes(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"allowlist": {"hashes": ["deadbeef" * 8]}}))
    _rules, allow = load_rules(p)
    assert "deadbeef" * 8 in allow.hashes


def test_multi_secret_canary_none_leak():
    # A blob mixing many secret types must come out FULLY masked — a regression
    # guard so no future detector/engine change silently starts leaking one.
    planted = {
        "aws_key": _j("AKIA", "IOSFODNN7EXAMPLE"),
        "stripe": _j("sk_live_", "4eC39HqLyjWDarjtT1zdp7dc"),
        "gh_pat": _j("github_pat_", "11ABCDE0Y0aBcDeFgHiJkL", "_",
                     "1234567890abcdefGHIJKLMNOPqrstuvWXYZ0123456789abcdefGHIJKLM"),
        "email": "ops@example.com",
        "ssn": "123-45-6789",
        "iban": "DE89370400440532013000",
    }
    blob = " ".join(f"{k}={v}" for k, v in planted.items())
    out = Redactor(Vault("s")).redact_text(blob)
    for k, v in planted.items():
        assert v not in out, f"{k} secret leaked: {v!r}"


# --- anthropic adapter ----------------------------------------------------


def test_anthropic_redact_request_and_fail_closed():
    a = AnthropicAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "x",
            "system": "you help",
            "messages": [{"role": "user", "content": "key sk-ant-abcdefghijklmnop1234"}],
        }
    ).encode()
    out = a.redact_request(body, red)
    assert b"sk-ant-abcdefghijklmnop1234" not in out
    with pytest.raises(Exception):
        a.redact_request(b"{ not json", red)


def test_unmask_stream_handles_split_token():
    v = Vault("s")
    token = v.token_for("topsecret@example.com", "EMAIL")
    half = len(token) // 2

    async def src():
        yield (
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":%s}}\n\n'
            % json.dumps("see " + token[:half])
        ).encode()
        yield (
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":%s}}\n\n'
            % json.dumps(token[half:] + " end")
        ).encode()
        yield b'data: {"type":"message_stop"}\n\n'

    async def collect():
        out = b""
        async for c in AnthropicAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "topsecret@example.com" in result
    assert token not in result


# --- proxy: the load-bearing security tests -------------------------------


def test_proxy_canary_e2e():
    mock = _MockUpstream()
    try:
        app = create_app(Config(upstream=mock.url))
        canary = "alice.secret@example.com"
        body = json.dumps(
            {"model": "x", "messages": [{"role": "user", "content": f"email me at {canary}"}]}
        ).encode()
        status, resp_text = _run(
            _post(
                app,
                "/v1/messages",
                body,
                {
                    "content-type": "application/json",
                    "x-api-key": "sk-test-key",
                    "anthropic-version": "2023-06-01",
                },
            )
        )
        assert status == 200
        assert len(mock.received) == 1
        recv_body = mock.received[0]["body"]
        # The canary must NOT appear in what the upstream received...
        assert canary.encode() not in recv_body
        # ...but a token must.
        assert _TOKEN_BYTES_RE.search(recv_body) is not None
        # Auth header forwarded verbatim.
        assert mock.received[0]["headers"].get("x-api-key") == "sk-test-key"
        # And the reply was un-masked locally back to the real value.
        assert canary in resp_text
    finally:
        mock.stop()


def test_proxy_fail_closed_on_bad_json():
    mock = _MockUpstream()
    try:
        app = create_app(Config(upstream=mock.url))
        status, _ = _run(
            _post(app, "/v1/messages", b"{ not valid json", {"content-type": "application/json"})
        )
        assert status >= 500  # blocked
        assert len(mock.received) == 0  # NOTHING forwarded
    finally:
        mock.stop()


def test_proxy_fail_closed_on_unknown_path():
    mock = _MockUpstream()
    try:
        app = create_app(Config(upstream=mock.url))
        status, _ = _run(
            _post(app, "/v1/unknown", b"{}", {"content-type": "application/json"})
        )
        assert status >= 500
        assert len(mock.received) == 0
    finally:
        mock.stop()


# --- OpenAI Responses adapter (Codex) -------------------------------------


def test_openai_responses_redact_request():
    a = OpenAIResponsesAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-5",
            "instructions": "you help; ping ops@example.com",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "key sk-abcdefghijklmnopqrstuvwxyz123456"}],
                },
                {"type": "local_shell_call_output", "output": "leaked AKIAIOSFODNN7EXAMPLE here"},
                {"type": "reasoning", "encrypted_content": "OPAQUE-sk-zzzzzzzzzzzzzzzzzzzzzzzz-BLOB"},
            ],
        }
    ).encode()
    out = a.redact_request(body, red)
    assert b"ops@example.com" not in out  # instructions redacted
    assert b"sk-abcdefghijklmnopqrstuvwxyz123456" not in out  # message redacted
    assert b"AKIAIOSFODNN7EXAMPLE" not in out  # tool output redacted
    # reasoning.encrypted_content is opaque and must be forwarded untouched,
    # even though it contains a key-shaped string.
    assert b"OPAQUE-sk-zzzzzzzzzzzzzzzzzzzzzzzz-BLOB" in out
    with pytest.raises(Exception):
        a.redact_request(b"{ not json", red)


def test_openai_responses_unmask_delta():
    v = Vault("s")
    token = v.token_for("secret@example.com", "EMAIL")

    async def src():
        yield (
            "event: response.output_text.delta\n"
            'data: {"type":"response.output_text.delta","delta":%s}\n\n' % json.dumps("got " + token)
        ).encode()

    async def collect():
        out = b""
        async for c in OpenAIResponsesAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "secret@example.com" in result
    assert token not in result


# --- Gemini adapter -------------------------------------------------------


def test_gemini_redact_native():
    a = GeminiAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "contents": [{"role": "user", "parts": [{"text": "mail alice@example.com"}]}],
            "systemInstruction": {"parts": [{"text": "key AKIAIOSFODNN7EXAMPLE"}]},
        }
    ).encode()
    out = a.redact_request(body, red)
    assert b"alice@example.com" not in out
    assert b"AKIAIOSFODNN7EXAMPLE" not in out
    with pytest.raises(Exception):
        a.redact_request(b"{ not json", red)


def test_gemini_redact_cloud_code_assist_envelope():
    a = GeminiAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gemini-2.5-pro",
            "project": "my-gcp-project",
            "request": {
                "contents": [
                    {"role": "user", "parts": [{"text": "token sk-abcdefghijklmnopqrstuvwxyz0"}]}
                ]
            },
        }
    ).encode()
    out = a.redact_request(body, red)
    assert b"sk-abcdefghijklmnopqrstuvwxyz0" not in out  # redacted inside request
    assert b"my-gcp-project" in out  # outer routing IDs untouched
    assert b"gemini-2.5-pro" in out


def test_gemini_unmask_stream():
    v = Vault("s")
    token = v.token_for("priv@example.com", "EMAIL")

    async def src():
        yield (
            'data: {"candidates":[{"content":{"parts":[{"text":%s}]}}]}\n\n' % json.dumps("here: " + token)
        ).encode()

    async def collect():
        out = b""
        async for c in GeminiAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "priv@example.com" in result
    assert token not in result


# --- streaming hardening: cross-chunk token reassembly for EVERY adapter ----
#
# The most leak-prone path is a masked token «PREFIX_salt_N» split across two SSE
# deltas — a carry-buffer bug there would emit a half-substituted token. These
# prove the un-mask reassembles correctly for all four providers (the audit found
# 3 of 4 adapters had no split test).


def test_anthropic_unmask_reassembles_at_every_split():
    v = Vault("s")
    token = v.token_for("topsecret@example.com", "EMAIL")

    def make_src(cut):
        async def src():
            yield (
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":%s}}\n\n'
                % json.dumps("see " + token[:cut])
            ).encode()
            yield (
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":%s}}\n\n'
                % json.dumps(token[cut:] + " end")
            ).encode()
            yield b'data: {"type":"message_stop"}\n\n'
        return src

    for cut in range(1, len(token)):  # split at EVERY interior position
        async def collect(s=make_src(cut)):
            out = b""
            async for c in AnthropicAdapter().unmask_stream(s(), v):
                out += c
            return out.decode("utf-8")
        result = _run(collect())
        assert "topsecret@example.com" in result, f"split at {cut} not reassembled: {result!r}"
        assert token not in result, f"token leaked at split {cut}"


def test_openai_chat_unmask_split_token():
    v = Vault("s")
    token = v.token_for("secret@example.com", "EMAIL")
    h = len(token) // 2

    async def src():
        yield ('data: {"choices":[{"delta":{"content":%s}}]}\n\n' % json.dumps("got " + token[:h])).encode()
        yield ('data: {"choices":[{"delta":{"content":%s}}]}\n\n' % json.dumps(token[h:] + " ok")).encode()
        yield b"data: [DONE]\n\n"

    async def collect():
        out = b""
        async for c in OpenAIChatAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "secret@example.com" in result
    assert token not in result


def test_openai_responses_unmask_split_token():
    v = Vault("s")
    token = v.token_for("secret@example.com", "EMAIL")
    h = len(token) // 2

    async def src():
        yield (
            "event: response.output_text.delta\n"
            'data: {"type":"response.output_text.delta","delta":%s}\n\n' % json.dumps("got " + token[:h])
        ).encode()
        yield (
            "event: response.output_text.delta\n"
            'data: {"type":"response.output_text.delta","delta":%s}\n\n' % json.dumps(token[h:] + " ok")
        ).encode()

    async def collect():
        out = b""
        async for c in OpenAIResponsesAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "secret@example.com" in result
    assert token not in result


def test_gemini_unmask_split_token():
    v = Vault("s")
    token = v.token_for("secret@example.com", "EMAIL")
    h = len(token) // 2

    async def src():
        yield ('data: {"candidates":[{"content":{"parts":[{"text":%s}]}}]}\n\n' % json.dumps("got " + token[:h])).encode()
        yield ('data: {"candidates":[{"content":{"parts":[{"text":%s}]}}]}\n\n' % json.dumps(token[h:] + " ok")).encode()

    async def collect():
        out = b""
        async for c in GeminiAdapter().unmask_stream(src(), v):
            out += c
        return out.decode("utf-8")

    result = _run(collect())
    assert "secret@example.com" in result
    assert token not in result


# --- image fail-closed (no Apple Vision yet → refuse, never forward) -------
#
# Image redaction is not implemented. Until it is, ANY request carrying an
# image MUST fail closed: ``redact_request`` raises and the proxy forwards
# NOTHING. These pin the headline "an image never leaks" guarantee for every
# adapter — closing the fail-OPEN hole where image blocks were passed through
# untouched.


# --- image redaction v1 (Apple Vision, strict fill-all, opt-in) ------------
#
# When REDACT_IMAGES is on AND Vision is available, the Anthropic adapter
# redacts an image in place (every text region + face → opaque box, re-verified)
# instead of refusing. When off / unavailable / un-redactable → still fail closed.
#
# NOTE: the live-redaction tests are skipif(not _VISION) — on non-macOS CI they
# SKIP, so "all passed" there does NOT exercise actual redaction. The fail-closed
# paths (disabled / url / redaction-error) and the adapter fail-closed wiring run
# everywhere; the live-Vision tests run only on macOS/Apple Silicon.

_VISION = image_redaction_available()


def _text_png(text: str) -> bytes:
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (700, 160), "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 44)
    except Exception:
        font = ImageFont.load_default()
    draw.text((20, 55), text, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _anthropic_image_body(b64: str, media_type: str = "image/png") -> bytes:
    return json.dumps(
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                    ],
                }
            ],
        }
    ).encode()


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_image_redactor_strict_fill_removes_text():
    from scrimward.image_redactor import _detect_boxes, _stack, redact_image_bytes

    raw = _text_png("SECRET AKIAIOSFODNN7EXAMPLE")
    out = redact_image_bytes(raw, "image/png")  # raises if any region survives
    assert out and out != raw
    vision, nsdata, _img, _draw = _stack()
    assert _detect_boxes(vision, nsdata, out) == []  # no text/face regions remain


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_anthropic_redacts_image_when_enabled():
    import base64

    from scrimward.image_redactor import _detect_boxes, _stack

    raw = _text_png("SECRET AKIAIOSFODNN7EXAMPLE")
    b64 = base64.b64encode(raw).decode()
    red = Redactor(Vault("s"), redact_images=True)
    out = AnthropicAdapter().redact_request(_anthropic_image_body(b64), red)  # no raise
    new_b64 = json.loads(out)["messages"][0]["content"][0]["source"]["data"]
    assert new_b64 != b64  # image bytes replaced with the redacted version
    vision, nsdata, _img, _draw = _stack()
    assert _detect_boxes(vision, nsdata, base64.b64decode(new_b64)) == []


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_image_redactor_refuses_when_fill_misses(monkeypatch):
    # Force a fill MISS — every box drawn as a 0-area rect — and prove the
    # re-verify safety net REFUSES. This is the line that makes images
    # fail-closed; without this test an inverted/dead re-verify passes silently.
    import scrimward.image_redactor as ir

    monkeypatch.setattr(ir, "_to_pixel_rect", lambda *a, **k: (0, 0, 0, 0))
    raw = _text_png("SECRET AKIAIOSFODNN7EXAMPLE")
    with pytest.raises(ir.ImageRedactionError):
        ir.redact_image_bytes(raw, "image/png")


def test_anthropic_image_fails_closed_on_redaction_error(monkeypatch):
    # Runs everywhere (no Vision needed): if redaction raises for ANY reason,
    # the adapter must fail closed (block the whole request), never forward.
    import scrimward.adapters.anthropic as ant
    from scrimward.image_redactor import ImageRedactionError

    monkeypatch.setattr(ant, "image_redaction_available", lambda: True)

    def _boom(*a, **k):
        raise ImageRedactionError("simulated redaction failure")

    monkeypatch.setattr(ant, "redact_image_bytes", _boom)
    red = Redactor(Vault("s"), redact_images=True)
    with pytest.raises(Exception):
        AnthropicAdapter().redact_request(_anthropic_image_body("AAAA"), red)


def test_anthropic_image_fails_closed_when_disabled():
    # default (redact_images off) → image still refused, fail-closed.
    red = Redactor(Vault("s"))
    with pytest.raises(Exception):
        AnthropicAdapter().redact_request(_anthropic_image_body("AAAA"), red)


def test_anthropic_url_image_fails_closed_even_when_enabled():
    # a url-source image can't be redacted locally → fail closed regardless.
    body = json.dumps(
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "image", "source": {"type": "url", "url": "https://x/y.png"}}],
                }
            ],
        }
    ).encode()
    red = Redactor(Vault("s"), redact_images=True)
    with pytest.raises(Exception):
        AnthropicAdapter().redact_request(body, red)


def test_anthropic_fail_closed_on_image_block():
    a = AnthropicAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "what is in this screenshot?"},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/png",
                                "data": "iVBORw0KGgoAAAANS",
                            },
                        },
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_openai_chat_fail_closed_on_image_url_part():
    a = OpenAIChatAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe this"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_openai_responses_fail_closed_on_input_image():
    a = OpenAIResponsesAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-5",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "read this"},
                        {"type": "input_image", "image_url": "data:image/png;base64,AAAA"},
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_openai_responses_fail_closed_on_computer_screenshot():
    a = OpenAIResponsesAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-5",
            "input": [
                {
                    "type": "computer_call_output",
                    "call_id": "c1",
                    "output": {
                        "type": "computer_screenshot",
                        "image_url": "data:image/png;base64,AAAA",
                    },
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_gemini_fail_closed_on_inline_image():
    a = GeminiAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "what is this?"},
                        {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                    ],
                }
            ]
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_anthropic_fail_closed_on_document_block():
    a = AnthropicAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": "JVBERi0xLjcK",
                            },
                        }
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_openai_chat_fail_closed_on_input_audio_part():
    a = OpenAIChatAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-4o-audio",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "transcribe this"},
                        {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_openai_responses_fail_closed_on_input_file():
    a = OpenAIResponsesAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "model": "gpt-5",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "summarize"},
                        {
                            "type": "input_file",
                            "filename": "secret.pdf",
                            "file_data": "data:application/pdf;base64,JVBERi0xLjcK",
                        },
                    ],
                }
            ],
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_gemini_fail_closed_on_inline_pdf():
    a = GeminiAdapter()
    red = Redactor(Vault("s"))
    body = json.dumps(
        {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {"text": "summarize this"},
                        {"inlineData": {"mimeType": "application/pdf", "data": "JVBERi0xLjcK"}},
                    ],
                }
            ]
        }
    ).encode()
    with pytest.raises(Exception):
        a.redact_request(body, red)


def test_proxy_fail_closed_on_image():
    mock = _MockUpstream()
    try:
        app = create_app(Config(upstream=mock.url))
        body = json.dumps(
            {
                "model": "x",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": "AAAA",
                                },
                            }
                        ],
                    }
                ],
            }
        ).encode()
        status, _ = _run(_post(app, "/v1/messages", body, {"content-type": "application/json"}))
        assert status >= 500  # blocked, fail-closed
        assert len(mock.received) == 0  # the image NEVER reached the upstream
    finally:
        mock.stop()


# --- R3: unicode-evasion normalization ------------------------------------
#
# A zero-width / format char spliced into a secret, or a full-width homoglyph,
# bypasses every regex detector. redact_text must NFKC-normalize + strip Cf
# chars before detecting (and forward the normalized text).


def test_zero_width_char_evasion_is_redacted():
    out = Redactor(Vault("s")).redact_text("key AKIA​IOSFODNN7EXAMPLE done")
    assert "AKIA" not in out  # the key (zero-width stripped) was detected + masked
    assert "​" not in out  # the zero-width char is gone from the forwarded text
    assert "«AWS_KEY_" in out


def test_fullwidth_homoglyph_evasion_is_redacted():
    # Full-width latin letters fold to ASCII under NFKC, so the email is caught.
    out = Redactor(Vault("s")).redact_text("ping ｍｅ@example.com now")
    assert "@example.com" not in out
    assert "«EMAIL_" in out


# --- R5: token-prefix validation (reversibility) --------------------------
#
# A token_prefix outside [A-Z0-9_]+ mints a token that the «PREFIX_salt_N» scan
# can't match, so unmask never restores it — a silent reversibility bug.


def test_token_prefix_lowercase_hyphen_is_normalized_and_reversible():
    v = Vault("s")
    tok = v.token_for("s3cretvalue", "my-key")  # lowercase + hyphen
    assert v.unmask(f"see {tok} now") == "see s3cretvalue now"


def test_token_prefix_invalid_raises():
    v = Vault("s")
    with pytest.raises(ValueError):
        v.token_for("x", "bad prefix!")  # space + '!' cannot be normalized


def test_load_rules_normalizes_token_prefix(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": [{"name": "r", "pattern": "foo", "token_prefix": "my-key"}]}))
    rules, _allow = load_rules(p)
    assert rules[0].token_prefix == "MY_KEY"


# --- expanded detector coverage (26 new detectors) ------------------------
#
# Each detector is exercised in isolation: every positive MUST match, every
# look-alike negative MUST NOT (false-positive guard). Vectors are the ones the
# design workflow compiled + asserted.

def _j(*parts: str) -> str:
    """Reassemble a secret-shaped test fixture from separate literal parts.

    Splitting the vendor prefix from the body keeps the full secret pattern from
    ever appearing CONTIGUOUSLY in this source file, so GitHub push-protection /
    secret scanners don't flag scrimward's OWN detector fixtures (fitting, for a
    redaction tool). The test still sees the reassembled string, so coverage is
    unchanged.
    """
    return "".join(parts)


_DETECTOR_CASES: dict[str, tuple[list[str], list[str]]] = {
    # broadened AWS access-key prefixes (gitleaks: A3T*/ABIA/ACCA beyond AKIA/ASIA)
    "aws_access_key": (
        [_j("ABIA", "IOSFODNN7EXAMPLE"), _j("A3TA", "IOSFODNN7EXAMPLE")],
        ["AKIASHORT", "ABIAlowercase123"],
    ),
    # re-enabled (was disabled): keyword-anchored so a bare 40-char base64 (which
    # over-fired) is NOT caught, but a real AWS_SECRET_ACCESS_KEY assignment is.
    "aws_secret_key": (
        [_j("aws_secret_access_key=", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")],
        ["abcdefghij0123456789ABCDEFGHIJ0123456789ab"],  # bare 40-char, no keyword
    ),
    "github_fine_grained_pat": (
        # real format: github_pat_ + 22 alnum + _ + 59 alnum
        [_j("github_pat_", "11ABCDE0Y0aBcDeFgHiJkL", "_", "1234567890abcdefGHIJKLMNOPqrstuvWXYZ0123456789abcdefGHIJKLM")],
        ["github_patterns_are_cool", "github_pat_short_token"],
    ),
    "gitlab_pat": ([_j("glpat-", "ABCDEFGhijkl1234567890")], ["glpat-short"]),
    "npm_token": ([_j("npm_", "abcdefghij0123456789ABCDEFGHIJ012345")], ["npm_install"]),
    "pypi_token": (
        [_j("pypi-", "AgEIcHlwaS5vcmc", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
        ["pypi-something"],
    ),
    "huggingface_token": ([_j("hf_", "abcdefghijklmnopqrstuvwxyzABCDEFGH")], ["hf_short"]),
    "digitalocean_token": (
        [_j("dop_v1_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
        ["dop_v1_short"],
    ),
    "stripe_secret_key": (
        [_j("sk_live_", "4eC39HqLyjWDarjtT1zdp7dc")],
        [_j("sk_test_", "4eC39HqLyjWDarjtT1zdp7dc")],
    ),
    "sendgrid_key": (
        [_j("SG.", "aaaaaaaaaaaaaaaaaaaaaa", ".bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")],
        ["SG.short.token"],
    ),
    "twilio_account_sid": ([_j("AC", "0123456789abcdef0123456789abcdef")], ["ACCOUNT_NAME_HERE"]),
    "twilio_api_key_sid": ([_j("SK", "0123456789abcdef0123456789abcdef")], ["SKIP_THIS_LINE_NOW"]),
    "google_oauth_access_token": ([_j("ya29.", "a0AfH6SMBabcdefghijklmnop")], ["ya30.notatoken1234567890"]),
    "slack_app_token": (
        [_j("xapp-", "1-A01B2C3D4E5-1234567890123-abcdef0123456789abcdef0123456789")],
        ["xapp-nope"],
    ),
    "slack_webhook_url": (
        [_j("https://hooks.slack.com/services/", "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")],
        ["https://example.com/services/T/B/x"],
    ),
    "shopify_access_token": (
        [_j("shpat_", "0123456789abcdef0123456789abcdef"), _j("shpca_", "ABCDEF0123456789ABCDEF0123456789")],
        ["shpat_short"],
    ),
    "linear_api_key": (
        [_j("lin_api_", "a1B2c3D4e5a1B2c3D4e5a1B2c3D4e5a1B2c3D4e5")],
        ["lin_apikey_missing_underscore"],
    ),
    "notion_token": (
        [
            _j("secret_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            _j("ntn_", "0123456789ABCDEFGHIJ0123456789ABCDEFGHIJ123"),
        ],
        ["secret_short"],
    ),
    "mailgun_key": ([_j("key-", "0123456789abcdef0123456789abcdef")], ["key-short"]),
    "square_access_token": (
        [_j("sq0atp-", "abcDEF0123456789_-xyzQ"), _j("EAAA", "Ed8sB0123456789abcdefghijklmno")],
        ["EAAAshort"],
    ),
    "cloudflare_api_token": (
        [_j("cloudflare_api_token=", "vAbCdEfGhIj0123456789_-KLMnoPQRstUVwxyz0")],
        ["cloudflare config docs"],
    ),
    "azure_storage_key": (
        [_j("AccountKey=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")],
        ["AccountName=devstoreaccount1"],
    ),
    "azure_sas_signature": (
        [_j("?sig=", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%3D")],
        ["?signal=on"],
    ),
    "aws_account_in_arn": ([_j("arn:aws:iam::", "123456789012:user/dev")], ["arn:aws:s3:::my-bucket"]),
    "us_ssn": (["123-45-6789"], ["000-12-3456"]),
    "iban": (["DE89370400440532013000", "GB29NWBK60161331926819"], ["HELLO12345678901234"]),
    "mac_address": (["00:1A:2B:3C:4D:5E"], ["00:1A:2B:3C:4D"]),
    "generic_assigned_secret": ([_j("password=", "hunter2hunter2hunter2")], ["token: short"]),
}


def test_new_detectors_registered():
    by_name = {d.name for d in BUILTINS}
    missing = [name for name in _DETECTOR_CASES if name not in by_name]
    assert not missing, f"detectors not registered: {missing}"


def test_new_detectors_positive_and_negative():
    by_name = {d.name: d for d in BUILTINS}
    for name, (positives, negatives) in _DETECTOR_CASES.items():
        det = by_name[name]
        for pos in positives:
            assert detect(pos, (det,)), f"{name} should match {pos!r}"
        for neg in negatives:
            assert not detect(neg, (det,)), f"{name} should NOT match {neg!r}"
