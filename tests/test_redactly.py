"""Redactly test suite — unit tests + the load-bearing security tests.

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
import http.server
import json
import re
import threading

import httpx
import pytest

from redactly.adapters.anthropic import AnthropicAdapter
from redactly.config import Allowlist, Config
from redactly.detectors import detect
from redactly.engine import Redactor
from redactly.proxy import create_app
from redactly.vault import Vault

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
