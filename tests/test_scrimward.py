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
import importlib.util
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
from scrimward.config import Allowlist, Config, UserRule, load_rules
from scrimward.detectors import BUILTINS, Span, detect
from scrimward.image_redactor import image_redaction_available
from scrimward.engine import Redactor, _RankedSpan
from scrimward.proxy import create_app
from scrimward.vault import Vault

_HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None

# UTF-8 bytes for the guillemets that delimit a token («…»).
_TOKEN_BYTES_RE = re.compile(rb"\xc2\xab.*?\xc2\xbb", re.DOTALL)


def _run(coro):
    return asyncio.run(coro)


class _MockUpstream:
    """Threaded mock provider: records request bodies, echoes the token in SSE."""

    def __init__(self, json_reply: bool = False) -> None:
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
                if json_reply:  # non-streaming application/json reply (H1)
                    payload = json.dumps({"content": f"reply: {echo}"}).encode("utf-8")
                    ctype = "application/json"
                else:
                    payload = (
                        (
                            "event: content_block_delta\n"
                            'data: {"type":"content_block_delta","delta":'
                            '{"type":"text_delta","text":%s}}\n\n'
                            "event: message_stop\n"
                            'data: {"type":"message_stop"}\n\n'
                        )
                        % json.dumps(f"reply: {echo}")
                    ).encode("utf-8")
                    ctype = "text/event-stream"
                self.send_response(200)
                self.send_header("content-type", ctype)
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


# --- encrypt-token vault (opt-in): token IS the ciphertext, no cleartext-at-rest


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_vault_encrypt_roundtrip_and_determinism():
    v = Vault("s", encrypt=True)
    t1 = v.token_for("a@b.com", "EMAIL")
    t2 = v.token_for("a@b.com", "EMAIL")
    assert t1 == t2  # AES-SIV is deterministic → same secret → same token
    assert v.token_for("c@d.com", "EMAIL") != t1
    assert t1.startswith("«EMAIL~") and t1.endswith("»")
    assert "a@b.com" not in t1  # the secret is encrypted, not embedded
    assert v.unmask(f"write to {t1} please") == "write to a@b.com please"


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_vault_encrypt_writes_no_cleartext_at_rest(tmp_path):
    p = tmp_path / "vault.json"
    v = Vault("s", path=p, encrypt=True)
    v.token_for("topsecret@example.com", "EMAIL")
    # encrypt mode persists NOTHING — key is in-memory, the token self-decrypts.
    assert not p.exists()


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_vault_encrypt_unmask_leaves_foreign_tokens():
    v = Vault("s", encrypt=True)
    # a standard-shaped token (not an encrypt token) and prose are left untouched.
    assert v.unmask("see «NOPE_a1b2c3_1» and plain text") == "see «NOPE_a1b2c3_1» and plain text"


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_redactor_with_encrypt_vault_roundtrip():
    v = Vault("s", encrypt=True)
    masked = Redactor(v).redact_text("mail alice@example.com now")
    assert "alice@example.com" not in masked
    assert "«EMAIL~" in masked
    assert v.unmask(masked) == "mail alice@example.com now"


# --- engine ---------------------------------------------------------------


# --- R1: overlap resolver merges overlapping spans into their UNION ---------
#
# Old behavior dropped the lower-priority overlapping span, leaking its flanking
# bytes. Now overlapping spans coalesce into one masked region; the merged
# token's prefix comes from the most-specific (lowest-priority) contributor.


def _rs(start, end, prefix, priority, s):
    return _RankedSpan(span=Span(start, end, prefix.lower(), prefix, s[start:end]), priority=priority)


def test_union_merge_narrow_inside_broad():
    s = "x" * 50
    out = Redactor(Vault("s"))._resolve_overlaps_ranked(s, [_rs(0, 50, "BROAD", 9, s), _rs(10, 20, "NARROW", 2, s)])
    assert len(out) == 1
    assert (out[0].start, out[0].end, out[0].prefix, out[0].text) == (0, 50, "NARROW", s[0:50])


def test_union_merge_adjacent_not_merged():
    s = "y" * 20
    out = Redactor(Vault("s"))._resolve_overlaps_ranked(s, [_rs(0, 10, "A", 1, s), _rs(10, 20, "B", 1, s)])
    assert [(o.start, o.end, o.prefix) for o in out] == [(0, 10, "A"), (10, 20, "B")]


def test_union_merge_transitive_min_priority_in_middle():
    s = "z" * 26
    ranked = [_rs(0, 10, "A", 5, s), _rs(8, 18, "B", 1, s), _rs(16, 26, "C", 5, s)]
    out = Redactor(Vault("s"))._resolve_overlaps_ranked(s, ranked)
    assert len(out) == 1
    assert (out[0].start, out[0].end, out[0].prefix) == (0, 26, "B")


def test_union_merge_deterministic_under_shuffle():
    s = "w" * 26
    base = [_rs(0, 10, "A", 5, s), _rs(8, 18, "B", 1, s), _rs(16, 26, "C", 5, s)]
    r = Redactor(Vault("s"))
    results = [
        [(o.start, o.end, o.prefix, o.text) for o in r._resolve_overlaps_ranked(s, [base[i] for i in perm])]
        for perm in ([0, 1, 2], [2, 1, 0], [1, 0, 2])
    ]
    assert results[0] == results[1] == results[2]


# --- C0: deny-by-default recursive backstop — no un-enumerated text leaks -----


def test_redact_object_redacts_nested_text_but_keeps_non_secrets():
    red = Redactor(Vault("s"))
    obj = {"a": {"b": ["x", "mail secret@example.com please"]}, "model": "gpt-4o"}
    red.redact_object(obj)
    assert "secret@example.com" not in json.dumps(obj)
    assert obj["model"] == "gpt-4o"  # non-secret text preserved


def test_redact_object_preserves_opaque_binary_and_encrypted_fields():
    # The backstop must NOT corrupt image data, data URIs, or opaque server blobs.
    red = Redactor(Vault("s"), detect_entropy=True)  # entropy on = harshest case
    obj = {
        "source": {"type": "base64", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"},
        "inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgoAAAANSUhEUg"},
        "image_url": {"url": "data:image/png;base64,iVBORw0KGgoAAAANS"},
        "reasoning": {"encrypted_content": "OPAQUEsk0123456789abcdefBLOBxyz"},
    }
    red.redact_object(obj)
    assert obj["source"]["data"] == "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
    assert obj["inlineData"]["data"] == "iVBORw0KGgoAAAANSUhEUg"
    assert obj["image_url"]["url"] == "data:image/png;base64,iVBORw0KGgoAAAANS"
    assert obj["reasoning"]["encrypted_content"] == "OPAQUEsk0123456789abcdefBLOBxyz"


def test_anthropic_redacts_tool_use_input_args():
    # C3: tool_use.input (shell commands / patches) must be redacted, not forwarded raw.
    body = json.dumps(
        {"model": "x", "messages": [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "mail ops@secret.example.com"}}]}]}
    ).encode()
    out = AnthropicAdapter().redact_request(body, Redactor(Vault("s")))
    assert b"ops@secret.example.com" not in out


def test_anthropic_redacts_tool_description():
    # C7: tools[].description free text must be redacted.
    body = json.dumps(
        {"model": "x", "messages": [{"role": "user", "content": "hi"}],
         "tools": [{"name": "db", "description": "connects to postgres://u:pw@db.internal/prod"}]}
    ).encode()
    out = AnthropicAdapter().redact_request(body, Redactor(Vault("s")))
    assert b"postgres://u:pw@db.internal" not in out


def test_openai_chat_redacts_tool_call_arguments():
    # C5
    body = json.dumps(
        {"model": "x", "messages": [{"role": "assistant", "content": None, "tool_calls": [
            {"id": "c", "type": "function", "function": {"name": "f", "arguments": '{"to":"leak@secret.example.com"}'}}]}]}
    ).encode()
    out = OpenAIChatAdapter().redact_request(body, Redactor(Vault("s")))
    assert b"leak@secret.example.com" not in out


def test_openai_responses_redacts_function_call_arguments():
    # C4
    body = json.dumps(
        {"model": "x", "input": [{"type": "function_call", "name": "f", "arguments": '{"q":"leak@secret.example.com"}'}]}
    ).encode()
    out = OpenAIResponsesAdapter().redact_request(body, Redactor(Vault("s")))
    assert b"leak@secret.example.com" not in out


def test_gemini_redacts_function_response_output():
    # C6: functionResponse.response (tool OUTPUT — highest secret density) must be redacted.
    body = json.dumps(
        {"contents": [{"role": "user", "parts": [
            {"functionResponse": {"name": "f", "response": {"stdout": "found leak@secret.example.com here"}}}]}]}
    ).encode()
    out = GeminiAdapter().redact_request(body, Redactor(Vault("s")))
    assert b"leak@secret.example.com" not in out


def test_guard_bootstrap_escape_matches_invocation_not_substring():
    # C2: the PreToolUse guard's bootstrap escape must allow only a scrimward
    # INVOCATION, not any command that merely CONTAINS "scrimward" (the repo
    # lives at ~/Desktop/scrimward/, so a substring check disables the guard).
    from scrimward.cli import _is_scrimward_bootstrap

    assert _is_scrimward_bootstrap("scrimward setup")
    assert _is_scrimward_bootstrap("bin/scrimward-py status")
    assert _is_scrimward_bootstrap("/Users/x/bin/scrimward-py hook guard")
    assert _is_scrimward_bootstrap("ENV=1 scrimward setup")
    assert not _is_scrimward_bootstrap("cat ~/Desktop/scrimward/.env")
    assert not _is_scrimward_bootstrap("printenv  # scrimward")
    assert not _is_scrimward_bootstrap("rm -rf /tmp/x")


def test_vendor_keys_caught_when_glued_to_word_chars():
    # C8: a vendor key concatenated to adjacent word chars (no separator) must
    # still fire — \b anchoring let `prefixAKIA…` / `AKIA…suffix` evade.
    red = Redactor(Vault("s"))
    aws = _j("AKIA", "IOSFODNN7EXAMPLE")
    assert aws not in red.redact_text("baseUrl+" + "prefixword" + aws)  # leading glue
    assert aws not in red.redact_text(aws + "gluedsuffix")  # trailing glue
    gh = _j("ghp_", "abcdefghijklmnopqrstuvwxyz0123456789AB")
    assert gh not in red.redact_text("x" + gh)


def test_short_labeled_secret_masked_in_default_mode():
    # C9: an explicitly-labeled credential with a 6-11 char value forwarded raw.
    red = Redactor(Vault("s"))
    assert "Tiger123" not in red.redact_text("config password=Tiger123 ok")
    assert "hunter2" not in red.redact_text("token: hunter2 here")


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


def test_entropy_detector_masks_unprefixed_secret():
    # The catch-all's primary value: a high-entropy secret with NO vendor prefix
    # that no other detector would match still gets masked.
    secret = _j("Xb9KpQ2mZ7vL4nR8", "tY1wC3eF6gH0jK5aB7dN2sV9uW")
    out = Redactor(Vault("s"), detect_entropy=True).redact_text(f"my custom token is {secret} ok")
    assert secret not in out
    assert "«HIGH_ENTROPY_" in out


def test_entropy_detector_is_opt_in():
    # Default-off: a high-entropy run (e.g. a git SHA-like blob) is NOT masked,
    # so coding prompts full of hashes are untouched until REDACT_ENTROPY is set.
    secret = _j("Xb9KpQ2mZ7vL4nR8", "tY1wC3eF6gH0jK5aB7dN2sV9uW")
    out = Redactor(Vault("s")).redact_text(f"my custom token is {secret} ok")
    assert secret in out  # untouched by default


def test_entropy_allowlist_spares_bare_sha_not_embedded():
    # The usability linchpin: with entropy ON, a confirmed FP (a 40-hex git SHA)
    # is suppressed via the allowlist — which fullmatches the span text BEFORE the
    # overlap merge — yet the SAME SHA inside a wider high-entropy run is still
    # masked (the span is the whole run, so it can't be smuggled past).
    sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"  # 40-hex; fires the entropy gate
    r = Redactor(Vault("s"), allowlist=Allowlist(patterns=(r"[0-9a-f]{40}",)), detect_entropy=True)
    assert r.redact_text(f"commit {sha} landed") == f"commit {sha} landed"  # spared
    blob = _j("Xb9KpQ2mZ7vL4nR8", "tY1wC3eF6") + sha  # 40-hex inside a 65-char run
    assert sha not in r.redact_text(f"blob {blob} end")  # masked — allowlist can't be smuggled past


def test_entropy_union_merge_prevents_flanking_leak():
    # A narrow high-priority match (a user rule) inside a broad high-entropy run:
    # without R1 union-merge the flanking high-entropy bytes would LEAK. R1+R2
    # together mask the whole run.
    rule = (UserRule(name="midmark", pattern="MID", token_prefix="MARK"),)
    left = _j("Xb9KpQ2m", "ZvL4nR8t")
    right = _j("Y1wC3eF6", "gH0jK5aB7dN2sV9uW")
    blob = left + "MID" + right
    out = Redactor(Vault("s"), user_rules=rule, detect_entropy=True).redact_text(f"see {blob} ok")
    assert left not in out and right not in out  # flanking high-entropy masked — no leak
    assert "MID" not in out  # token prefix is MARK, so the matched literal is truly gone
    assert "«MARK_" in out  # the whole run coalesced into one merged token


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


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_proxy_canary_e2e_encrypt_vault():
    mock = _MockUpstream()
    try:
        app = create_app(Config(upstream=mock.url, vault_encrypt=True))
        canary = "alice.secret@example.com"
        body = json.dumps(
            {"model": "x", "messages": [{"role": "user", "content": f"email me at {canary}"}]}
        ).encode()
        status, resp_text = _run(
            _post(app, "/v1/messages", body, {"content-type": "application/json", "x-api-key": "k"})
        )
        assert status == 200
        recv_body = mock.received[0]["body"]
        assert canary.encode() not in recv_body  # secret absent from the wire
        assert b"~" in recv_body  # an encrypt token «PREFIX~hex» went upstream
        assert canary in resp_text  # decrypted locally back to the real value
    finally:
        mock.stop()


def test_unmask_body_restores_tokens_in_json_and_raw():
    from scrimward.proxy import _unmask_body

    v = Vault("s")
    tok = v.token_for("alice@example.com", "EMAIL")
    out = _unmask_body(json.dumps({"content": f"hi {tok}", "n": [{"x": tok}]}).encode(), v)
    assert b"alice@example.com" in out and tok.encode() not in out
    raw = _unmask_body(f"plain {tok} text".encode(), v)  # non-JSON → raw unmask
    assert b"alice@example.com" in raw


def test_proxy_canary_e2e_non_streaming_reply():
    # H1: a stream:false (application/json) reply must have its tokens restored.
    mock = _MockUpstream(json_reply=True)
    try:
        app = create_app(Config(upstream=mock.url))
        canary = "alice.secret@example.com"
        body = json.dumps(
            {"model": "x", "messages": [{"role": "user", "content": f"email me at {canary}"}], "stream": False}
        ).encode()
        status, resp_text = _run(_post(app, "/v1/messages", body, {"content-type": "application/json"}))
        assert status == 200
        assert canary.encode() not in mock.received[0]["body"]  # outbound masked
        assert canary in resp_text  # the non-streaming reply was un-masked locally
    finally:
        mock.stop()


# --- H3: cli fail-closed boundary (was entirely untested) ------------------


def test_is_routed_requires_matching_url_and_healthz(monkeypatch, tmp_path):
    from scrimward import cli

    p = tmp_path / "settings.local.json"
    p.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:8788"}}))
    monkeypatch.setattr(cli, "_healthz", lambda *a, **k: True)
    assert cli._is_routed(8788, settings_path=p) is True
    monkeypatch.setattr(cli, "_healthz", lambda *a, **k: False)  # proxy down
    assert cli._is_routed(8788, settings_path=p) is False  # fail-closed
    p.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "http://elsewhere:9"}}))
    monkeypatch.setattr(cli, "_healthz", lambda *a, **k: True)
    assert cli._is_routed(8788, settings_path=p) is False  # wrong URL → not routed


def test_write_and_restore_base_url_round_trip(tmp_path):
    from scrimward import cli

    p = tmp_path / "settings.local.json"
    p.write_text(json.dumps({"env": {"OTHER": "keep"}, "permissions": "x"}))
    prev = cli._write_base_url("http://127.0.0.1:8788", settings_path=p)
    assert prev is None  # ANTHROPIC_BASE_URL was unset
    data = json.loads(p.read_text())
    assert data["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:8788"
    assert data["env"]["OTHER"] == "keep" and data["permissions"] == "x"  # siblings preserved
    cli._restore_base_url(prev, settings_path=p)  # prev None → key removed
    restored = json.loads(p.read_text())
    assert "ANTHROPIC_BASE_URL" not in restored["env"] and restored["env"]["OTHER"] == "keep"


# --- H4: every adapter redacts + routes through the full proxy --------------


@pytest.mark.parametrize(
    "path,body,auth",
    [
        ("/v1/messages", {"model": "x", "messages": [{"role": "user", "content": "email CANARY"}]}, ("x-api-key", "k")),
        ("/v1/chat/completions", {"model": "x", "messages": [{"role": "user", "content": "email CANARY"}]}, ("authorization", "Bearer k")),
        ("/v1/responses", {"model": "x", "input": "email CANARY"}, ("authorization", "Bearer k")),
        ("/v1internal:generateContent", {"contents": [{"role": "user", "parts": [{"text": "email CANARY"}]}]}, ("x-goog-api-key", "k")),
    ],
)
def test_proxy_e2e_redacts_and_forwards_auth_for_all_adapters(path, body, auth):
    mock = _MockUpstream()
    canary = "alice.secret@example.com"
    raw = json.dumps(body).replace("CANARY", canary).encode()
    try:
        app = create_app(Config(upstream=mock.url))
        status, _ = _run(_post(app, path, raw, {"content-type": "application/json", auth[0]: auth[1]}))
        assert status == 200
        recv = mock.received[0]
        assert canary.encode() not in recv["body"]  # outbound masked
        assert _TOKEN_BYTES_RE.search(recv["body"]) is not None  # a token went upstream
        assert recv["headers"].get(auth[0]) == auth[1]  # auth header forwarded verbatim
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


def _pdf_page_image(text: str, font_size: int = 40):
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (612, 300), "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
    except Exception:
        font = ImageFont.load_default()
    draw.text((30, 140), text, fill="black", font=font)
    return img


def _text_pdf(text: str, font_size: int = 40) -> bytes:
    buf = io.BytesIO()
    _pdf_page_image(text, font_size).save(buf, "PDF", resolution=72.0)
    return buf.getvalue()


def _pdf_page_has_no_text(pdf_bytes: bytes, page: int = 1) -> bool:
    # Rasterize the (already-redacted) page at the render scale and confirm Vision
    # finds no readable text — i.e. nothing leaked through.
    import Quartz
    from CoreFoundation import CFDataCreate

    from scrimward.image_redactor import _detect_boxes, _rasterize_pdf_page, _stack

    data = CFDataCreate(None, pdf_bytes, len(pdf_bytes))
    doc = Quartz.CGPDFDocumentCreateWithProvider(Quartz.CGDataProviderCreateWithCFData(data))
    png = _rasterize_pdf_page(Quartz, doc, page)
    vision, nsdata, _img, _draw = _stack()
    return _detect_boxes(vision, nsdata, png) == []


def _anthropic_pdf_body(b64: str) -> bytes:
    return json.dumps(
        {
            "model": "x",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": b64}},
                    ],
                }
            ],
        }
    ).encode()


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_anthropic_redacts_pdf_when_enabled():
    import base64

    b64 = base64.b64encode(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    out = AnthropicAdapter().redact_request(_anthropic_pdf_body(b64), Redactor(Vault("s"), redact_pdf=True))
    new_b64 = json.loads(out)["messages"][0]["content"][0]["source"]["data"]
    assert new_b64 != b64  # rasterized + redacted + reassembled
    assert base64.b64decode(new_b64).startswith(b"%PDF")  # still a valid PDF (re-verify passed)


def test_anthropic_pdf_fails_closed_when_disabled():
    # default (redact_pdf off) → document/PDF still refused.
    with pytest.raises(Exception):
        AnthropicAdapter().redact_request(_anthropic_pdf_body("JVBERi0="), Redactor(Vault("s")))


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_openai_chat_redacts_pdf_file_when_enabled():
    import base64

    uri = "data:application/pdf;base64," + base64.b64encode(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": [{"type": "file", "file": {"file_data": uri, "filename": "x.pdf"}}]}]}
    ).encode()
    out = OpenAIChatAdapter().redact_request(body, Redactor(Vault("s"), redact_pdf=True))
    new_uri = json.loads(out)["messages"][0]["content"][0]["file"]["file_data"]
    assert new_uri != uri and base64.b64decode(new_uri.split(",", 1)[1]).startswith(b"%PDF")


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_openai_responses_redacts_input_file_pdf_when_enabled():
    import base64

    uri = "data:application/pdf;base64," + base64.b64encode(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"model": "gpt-5", "input": [{"type": "message", "role": "user", "content": [{"type": "input_file", "filename": "x.pdf", "file_data": uri}]}]}
    ).encode()
    out = OpenAIResponsesAdapter().redact_request(body, Redactor(Vault("s"), redact_pdf=True))
    new_uri = json.loads(out)["input"][0]["content"][0]["file_data"]
    assert new_uri != uri and base64.b64decode(new_uri.split(",", 1)[1]).startswith(b"%PDF")


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_gemini_redacts_inline_pdf_when_enabled():
    import base64

    b64 = base64.b64encode(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"contents": [{"role": "user", "parts": [{"inlineData": {"mimeType": "application/pdf", "data": b64}}]}]}
    ).encode()
    out = GeminiAdapter().redact_request(body, Redactor(Vault("s"), redact_pdf=True))
    new_b64 = json.loads(out)["contents"][0]["parts"][0]["inlineData"]["data"]
    assert new_b64 != b64 and base64.b64decode(new_b64).startswith(b"%PDF")


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_pdf_redaction_handles_small_body_text():
    # The 72-DPI leak guard: ~12px body text would be missed if rendered 1:1.
    from scrimward.image_redactor import redact_pdf_bytes

    out = redact_pdf_bytes(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE body text", font_size=12))
    assert _pdf_page_has_no_text(out)  # no readable text survived the redaction


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_pdf_redaction_multipage():
    from scrimward.image_redactor import redact_pdf_bytes

    buf = io.BytesIO()
    _pdf_page_image("page one").save(
        buf, "PDF", save_all=True, append_images=[_pdf_page_image("SECRET AKIAIOSFODNN7EXAMPLE")], resolution=72.0
    )
    out = redact_pdf_bytes(buf.getvalue())
    assert _pdf_page_has_no_text(out, page=2)  # the secret on page 2 was redacted


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_pdf_redaction_fails_closed_when_a_page_cant_be_cleaned(monkeypatch):
    # If a page's fill misses (forced here), the per-page re-verify must make the
    # whole PDF redaction RAISE → the adapter fails closed.
    import scrimward.image_redactor as ir

    monkeypatch.setattr(ir, "_to_pixel_rect", lambda *a, **k: (0, 0, 0, 0))
    with pytest.raises(ir.ImageRedactionError):
        ir.redact_pdf_bytes(_text_pdf("SECRET AKIAIOSFODNN7EXAMPLE"))


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


def _no_text_remains(raw: bytes) -> bool:
    from scrimward.image_redactor import _detect_boxes, _stack

    vision, nsdata, _img, _draw = _stack()
    return _detect_boxes(vision, nsdata, raw) == []


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_openai_chat_redacts_image_when_enabled():
    import base64

    uri = "data:image/png;base64," + base64.b64encode(_text_png("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"model": "gpt-4o", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": uri}}]}]}
    ).encode()
    out = OpenAIChatAdapter().redact_request(body, Redactor(Vault("s"), redact_images=True))
    new_uri = json.loads(out)["messages"][0]["content"][0]["image_url"]["url"]
    assert new_uri != uri
    assert _no_text_remains(base64.b64decode(new_uri.split(",", 1)[1]))


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_openai_responses_redacts_input_image_when_enabled():
    import base64

    uri = "data:image/png;base64," + base64.b64encode(_text_png("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"model": "gpt-5", "input": [{"type": "message", "role": "user", "content": [{"type": "input_image", "image_url": uri}]}]}
    ).encode()
    out = OpenAIResponsesAdapter().redact_request(body, Redactor(Vault("s"), redact_images=True))
    new_uri = json.loads(out)["input"][0]["content"][0]["image_url"]
    assert new_uri != uri
    assert _no_text_remains(base64.b64decode(new_uri.split(",", 1)[1]))


@pytest.mark.skipif(not _VISION, reason="Apple Vision unavailable (non-macOS)")
def test_gemini_redacts_inline_image_when_enabled():
    import base64

    b64 = base64.b64encode(_text_png("SECRET AKIAIOSFODNN7EXAMPLE")).decode()
    body = json.dumps(
        {"contents": [{"role": "user", "parts": [{"inlineData": {"mimeType": "image/png", "data": b64}}]}]}
    ).encode()
    out = GeminiAdapter().redact_request(body, Redactor(Vault("s"), redact_images=True))
    new_b64 = json.loads(out)["contents"][0]["parts"][0]["inlineData"]["data"]
    assert new_b64 != b64
    assert _no_text_remains(base64.b64decode(new_b64))


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


def test_normalize_does_not_corrupt_secret_free_content():
    # M3: NFKC/Cf normalization is for DETECTION only — a secret-free string must
    # be forwarded byte-for-byte, not silently folded (full-width → ASCII).
    text = "ｆｕｌｌｗｉｄｔｈ note — no secrets here, just a café résumé"
    assert Redactor(Vault("s")).redact_text(text) == text


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
    # high-entropy catch-all: real unprefixed secrets fire; benign high-entropy
    # dev strings (dashed UUID / short SHA / pure-numeric / low-variety) do not.
    # (Full bare hex digests DO fire by design — suppressed via the allowlist, not
    # the validator — so they are NOT listed as negatives here.)
    "high_entropy_string": (
        [
            _j("Xb9KpQ2mZ7vL4nR8", "tY1wC3eF6gH0jK5aB7dN2sV9uW"),
            _j("aZ4kP9mLqW2nX7vR", "8tY3eC6gH1jB5dF0sK4uN9wQ2r"),
            _j("9f8e7d6c5b4a3928", "1706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"),
        ],
        [
            "550e8400-e29b-41d4-a716-446655440000",  # dashed UUID — dashes split it below the floor
            "dcfa623",  # short SHA — below the 20-char floor
            "84920173650192847561",  # 20-digit ID — pure-numeric, dropped unconditionally
            "aaaaaaaaaaaaaaaaaaaaaaaa",  # repeated char — zero entropy
            "abcdefabcdefabcdefabcdefa",  # low-variety run — entropy < limit
        ],
    ),
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
