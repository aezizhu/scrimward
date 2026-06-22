# What we learned from Headroom

[Headroom](https://github.com/headroomlabs-ai/headroom) is a local proxy that wraps coding agents
(incl. Claude Code) to **compress context**. It is the closest prior art to `claude-redact`'s
transport machinery. We studied its source (Rust `crates/headroom-proxy` + Python `headroom/`) to
de-risk our design. **Same plumbing, opposite safety posture** — Headroom is *fail-open by design*
(losing compression is harmless); a redactor must be *fail-closed* (losing a mask leaks a secret).

---

## 🟢 Resolved: subscription/OAuth through a local proxy **works**

Our single biggest open risk is settled, with source evidence:

> Pointing `ANTHROPIC_BASE_URL=http://127.0.0.1:PORT` at a local proxy **keeps Pro/Max subscription
> (OAuth) auth working and does NOT force API-key billing** — *as long as you forward the auth
> headers verbatim and don't fingerprint the traffic.*

How (`headroom/cli/wrap.py`, `headers.rs`, `auth_mode.rs`):
- `wrap claude` only sets `ANTHROPIC_BASE_URL`; it **never** sets `ANTHROPIC_API_KEY`/`AUTH_TOKEN`.
- Claude Code attaches its own `Authorization: Bearer sk-ant-oat-*` on every request; the proxy
  forwards it byte-for-byte to `api.anthropic.com`. Headroom never mints/refreshes/holds a token.
- `authorization`, `x-api-key`, `anthropic-version`, `anthropic-beta`, `user-agent` are **never**
  in any strip list → forwarded verbatim.

➡️ **claude-redact does the same: transparent header reverse-proxy; mutate only the JSON body.**

## 🔴 Mandatory, non-obvious: env var alone is NOT enough (issue #951)

Claude Code's cc-daemon **spawns** conversation/subagent workers that **re-read `settings.json`
fresh** and do **not** inherit the launcher's process env. Headroom had to *also* write
`ANTHROPIC_BASE_URL` into project-local **`.claude/settings.local.json`** (`_write_claude_wrap_base_url`).

> For a compressor, a missed worker = lost savings. **For a redactor, a missed worker = secrets sent
> UNREDACTED.** So writing `settings.local.json` (and restoring it on exit) is a **security
> requirement**, not a nicety. Test that subagent/multi-conversation traffic is also routed.

## 🔴 Invert the whole safety posture: fail-OPEN → fail-CLOSED

Everywhere Headroom hits a problem it **forwards the original bytes** (parse error, serialize error,
`Outcome::Passthrough`, compression exception; `SECURITY.md:61` declares passthrough the default).
For us that is the **leak path**. Inversions:

| Headroom (fail-open) | claude-redact (fail-closed) |
|---|---|
| Body parse error → forward original | Parse error → **block (5xx)**, forward nothing |
| Narrow intercept gate (only POST + compressible + JSON); everything else streams **uninspected** via catch-all | **Default-deny**: buffer & inspect every request body; **block** unknown paths/content-types |
| Unmutated body → forward verbatim | "Unmutated" can still hold secrets → still inspect |
| Lost placeholder → discard + log | Token resolution fail on response → **block/garble-safe**, never emit raw |
| Env opt-in to re-enable fail-open | **No fail-open switch exists** in a privacy tool |

## 🔴 Subscription blocks tool-injection ⇒ inline SSE un-masking is **net-new** work

Headroom restores compressed data via an injected `headroom_retrieve` **tool** — but
`streaming.py:1202` shows **custom tool injection is rejected under Claude Code subscription creds**.
So for our exact target the pull/tool restore model is **unavailable**. We **must** un-mask the
**response stream inline**:

- Scan each `content_block_delta` / `text_delta`; a token like `«EMAIL_1»` can **split across two
  deltas** (`"«EMA"` then `"IL_1»"`). Hold back a trailing partial-token tail until the next delta
  completes (or can't) a match, then swap token→original before re-emitting.
- This **deliberately contradicts** Headroom's "always stream immediately" rule — a small latency
  cost for correctness. Name the tradeoff in the design.
- **Reuse** Headroom's `parse_sse_events_from_byte_buffer` / `sse/framing.rs` byte-buffer event
  splitter for transport-level UTF-8-split safety — **necessary but not sufficient**; it solves
  bytes-split-across-TCP, not placeholders-split-across-deltas. Add a delta-level reassembler on top.

## 🟢 Images need no special transport
Base64 image blocks live **inside the JSON body** (`type:"image"` content blocks), so they hit the
**same buffered-JSON request arm** — just make the gate buffer them and size the body cap for large
base64. No separate image transport path.

---

## Reusable patterns (adopt)

**Transport (Rust, `crates/headroom-proxy`):** axum fallback catch-all + reqwest passthrough +
`Body::from_stream`; ALPN negotiates HTTP/1.1+HTTP/2 automatically; `redirect::none()` (decide
follow/block — a redirect `Location` can exfiltrate). `headers.rs` hop-by-hop/client-managed filtering
+ verbatim auth forwarding. serde_json `preserve_order`+`arbitrary_precision`+`raw_value` for
byte-faithful round-trips of the *unredacted* parts. Pre-consume `Content-Length` 413 cap.

**Launcher (`claude-redact wrap claude`):** Click CLI; set env **and** `settings.local.json`;
`subprocess.run` (not exec) so a `finally:` restores state; pass unknown args via `UNPROCESSED`.
Daemon = `Popen(start_new_session=True)`, **logs to a file not a pipe** (macOS 64KB pipe deadlock),
poll `/readyz`. Fixed default port **8787** + pre-flight bind check ("rerun with --port N+1"); reuse a
healthy same-version proxy via per-PID marker files, kill on last client. Set `ENABLE_TOOL_SEARCH`
when base URL is custom (GH #746) or Claude Code floods its own context with tool schemas.

**Plugin (3 files):** `.claude-plugin/marketplace.json` + `plugins/<name>/.claude-plugin/plugin.json`
+ `plugins/<name>/hooks/hooks.json` (SessionStart `startup|resume` + PreToolUse). Routing lives in the
`init`/`wrap` CLI, **not** the plugin. **Diverge:** make our PreToolUse hook **BLOCKING** — deny the
tool unless the proxy is healthy *and* the effective `ANTHROPIC_BASE_URL` points at it. Fail-closed as
an explicit gate, never Headroom's best-effort `except: return`.

**Vault:** `ContextVar` per-request store → **session-keyed** token↔secret map. `chmod 0600` the vault
file **and `0700` the parent dir** (Headroom forgets the dir). Salted token prefix to avoid collisions
+ "discard + loud ERROR on lost placeholder."
**Invert:** do **not** persist originals as plaintext-on-disk surviving restarts (Headroom does —
wrong for a secrets vault). Prefer **in-memory, session-lifetime** (or encrypt-at-rest). Don't use
creation-anchored TTL (a long session loses early secrets) — session-lifetime or sliding. Don't use
pure content-addressed tokens (same secret→same token across sessions = equality leak) — per-session salt.

**Auth modes:** API-key + subscription = env base URL + verbatim headers. Vertex = set
`ANTHROPIC_VERTEX_BASE_URL`, forward the ADC bearer. **Bedrock = body mutation invalidates the SigV4
signature** → must re-sign (port `crates/.../bedrock/sigv4.rs`) or require a re-signing gateway →
treat as **"gateway-only / not transparently supported"** in v1. Subscription "stealth": never mutate
User-Agent, never add `X-*` headers upstream, preserve `accept-encoding` — or risk the provider
flagging the traffic.

## Testing & trust (adopt early)

1. **Differential network-capture, re-aimed at LEAK detection** (Headroom's crown jewel,
   `docker/differential-network-capture/` + `network-diff-capture.yml`): run real `claude -p` through
   the proxy in Docker, capture egress with mitmproxy as JSONL (sha256 + b64 body). Assert the
   **canary secret is ABSENT**, the **placeholder is PRESENT**, and the **locally-unmasked reply ==
   original**. Gate behind a cheap offline build-smoke job; run nightly/dispatch (real API key).
   *This is the single highest-trust artifact for this product.*
2. **Shim-on-clean-PATH e2e** (`e2e/_lib/harness.py`): drop fake agent executables on a scrubbed
   PATH to test the wrap/launcher hermetically — no network, no key.
3. **One `decide_redaction_failure_action()` pure function** + decision-matrix test (model on
   `test_compression_failure_action.py`) where **every branch asserts BLOCK** (regex error, OCR
   timeout, partial UTF-8 at chunk boundary, classifier crash).
4. **`.gitguardian.yaml` self-allowlist from commit 1** — our test corpus is full of secret-shaped
   fixtures; each allowlist entry names the file + why it carries no privilege.
5. **CONTRIBUTING policy:** "green CI ≠ feature works"; every fix ships a fail-before/pass-after test
   + a "what I did NOT test" note.
6. **NEVER-mask denylist:** `authorization`, `x-api-key`, `cookie`, auth tokens must reach Anthropic
   verbatim (`mitm_capture.py:23` is the exact list) — masking them breaks auth.

---

## Net effect on our plan
- Biggest risk (subscription) → **resolved viable**; Bedrock → **gateway-only in v1**.
- New **hard requirements**: write `settings.local.json` (not just env); **inline SSE un-masking**
  (subscription blocks the tool path); **default-deny** body inspection; **fail-closed everywhere**.
- Large **reuse surface**: transport skeleton, header filtering, SSE byte-framer, launcher/daemon
  lifecycle, plugin shape, vault ContextVar, and an entire **leak-detection test rig** to invert.

*Credits: patterns and file references above are from Headroom (headroomlabs-ai/headroom), studied as
prior art. claude-redact is an independent implementation with the opposite (fail-closed) safety model.*
