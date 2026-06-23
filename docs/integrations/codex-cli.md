# Scrimward integration — OpenAI Codex CLI

![status](https://img.shields.io/badge/status-%E2%9A%A0%EF%B8%8F%20partial-orange) **⚠️ partial** — interceptable over HTTP with caveats; force HTTP transport and refuse if WebSocket/realtime is active.

> Provider API: **OpenAI Responses** (`POST /v1/responses`) — **not** Chat Completions.
> Engine: the shared Scrimward local fail-closed proxy + reversible session vault. This doc only pins the **launcher** and the **Responses body adapter** for Codex.

---

## 1. TL;DR verdict

Codex CLI is **protectable over HTTP**: you can route its inference at `127.0.0.1` via `OPENAI_BASE_URL` (API-key mode) or a global `~/.codex/config.toml` custom `model_provider` (ChatGPT-OAuth mode), and the Responses body adapter redacts the request and un-masks the stream. It is **not** in the ⛔ vendor-backend tier — there is no Codex cloud that assembles your prompt first; the complete outbound payload passes through your machine. The two real caveats that keep it at ⚠️: (a) Codex can negotiate an **opt-in WebSocket/realtime transport** that a body-only HTTP proxy cannot inspect — Scrimward must **force HTTP and refuse if WS is active**, never silently pass it; and (b) the **default ChatGPT-login auth** needs a conditional `requires_openai_auth` flag, which — if set in API-key mode — *breaks* API-key users.

---

## 2. Status badge meaning

| | |
|---|---|
| Badge | ⚠️ partial |
| Why not ✅ | WS/realtime transport is body-opaque to an HTTP proxy; must be forced off + fail-closed. Auth handling is auth-mode-conditional. |
| Why not ⛔ | No vendor backend in the path — `localhost` is reachable; the full payload is built and sent from your machine. |
| Path to ✅ | §7 — a WS frame-relay adapter + an in-session empirical canary pass under both auth modes. |

---

## 3. Launcher — route Codex through `127.0.0.1:PORT`

Codex reads three relevant config surfaces. **Pick by auth mode** (§4). In all cases the proxy base URL is `http://127.0.0.1:PORT/v1` (plaintext loopback is fine).

> **CRITICAL — global only.** `openai_base_url`, `chatgpt_base_url`, `model_provider`, `model_providers`, `experimental_realtime_ws_base_url`, `profile(s)`, `notify`, `otel` are **IGNORED in project-local `.codex/config.toml`** and Codex prints a startup warning. They must live in the **global** `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`). Writing them project-local is a **silent bypass** — the proxy looks installed and leaks everything. Verified against the Codex config reference (2026). [C2]
>
> Note `chatgpt_base_url` only overrides the **ChatGPT login** endpoint, **not inference** — do not rely on it to route model traffic.

### 3a. API-key mode (cleanest) — env var, process-scoped, no file mutation

```bash
# launcher: scrimward-codex
export OPENAI_BASE_URL="http://127.0.0.1:${SCRIMWARD_PORT}/v1"
exec codex "$@"
```

- **Idempotent + auto-restore:** because this is a child-process env var, restore is automatic — the parent shell is never mutated. Nothing to clean up on exit. This is the preferred launcher whenever `auth.json` is API-key mode.
- **Scope:** affects only the launched `codex` process and its children.

### 3b. ChatGPT-OAuth mode — global `~/.codex/config.toml` managed block

OAuth login does not consult `OPENAI_BASE_URL` for the custom-provider account flow; you need a named provider. Write a **marker-delimited managed block** so revert is exact (mirrors Headroom `install.py`). [H1]

```toml
# --- Scrimward managed provider ---
model_provider = "scrimward"
openai_base_url = "http://127.0.0.1:PORT/v1"

[model_providers.scrimward]
name = "Scrimward local proxy"
base_url = "http://127.0.0.1:PORT/v1"
wire_api = "responses"
requires_openai_auth = true     # ONLY in ChatGPT-OAuth mode — see §4
# DO NOT emit supports_websockets — force HTTP transport (§6, the WS leak trap)
# --- end Scrimward managed provider ---
```

**Write idempotently** — read the file, if the start marker exists `re.sub` the whole `START … END` block in place; else append after `existing.rstrip() + "\n\n"`. **Restore on exit** — remove the marker block, then strip orphan top-level keys a crashed write may have left *outside* the block:

```python
# orphan-key sweep on revert (from Headroom install.py)
ORPHAN_MODEL_PROVIDER  = r'(?m)^[ \t]*model_provider[ \t]*=[ \t]*"scrimward"[ \t]*\r?\n'
ORPHAN_OPENAI_BASE_URL = r'(?m)^[ \t]*openai_base_url[ \t]*=[ \t]*"http://127\.0\.0\.1:\d+/v1"[ \t]*\r?\n'
ORPHAN_PROVIDER_TABLE  = r'(?ms)^\[model_providers\.scrimward\][^\[]*?base_url[ \t]*=[ \t]*"http://127\.0\.0\.1:\d+/v1"[^\[]*?(?=^\[|\Z)'
```

- **Scope gotcha:** the block must be in the **global** config (§3 CRITICAL). A project-local copy is ignored → silent leak.
- **Per-OS notes:** `$CODEX_HOME` overrides `~/.codex` if set (honor it for both `config.toml` and `auth.json`). On Windows the path is `%USERPROFILE%\.codex\config.toml`; loopback `127.0.0.1` works identically. The credential store may be the OS keychain instead of `auth.json` (§4) — detect both.

### 3c. WebSocket is OFF by design

Do **not** set `experimental_realtime_ws_base_url` and do **not** emit `supports_websockets = true` (Headroom emits it unconditionally because it ships a WS frame relay — **Scrimward does not**, so copying that line is a silent-leak bug). The provider block above pins `wire_api = "responses"` (HTTP `POST /responses`) and the §6 probe refuses if a WS/realtime route is live. [H1]

---

## 4. Auth handling

Codex stores credentials at `~/.codex/auth.json` (plaintext) **or** the OS credential store. Detect the mode by reading `auth.json`. [C3][C4]

| Mode | Detection | Header(s) on the wire | Proxy action | What breaks / avoidance |
|---|---|---|---|---|
| **API key** (`sk-…`) | `OPENAI_API_KEY` present; `auth_mode != "chatgpt"`; no `tokens.account_id` | `Authorization: Bearer sk-…` | **Forward verbatim.** Use launcher 3a. | Setting `requires_openai_auth = true` here **ignores `env_key`** and forces an OpenAI OAuth login → API-key users break. Never set it in this mode. [C1][H1] |
| **ChatGPT sign-in (OAuth, DEFAULT)** | `auth.json.auth_mode == "chatgpt"`, OR (older files) `tokens.account_id` is a non-empty string; `OPENAI_API_KEY` is null | `Authorization: Bearer <OAuth JWT>` **and** `ChatGPT-Account-ID: <account_id>` (derived from `auth.json`) | **Forward both headers verbatim — never inject, replace, or strip.** Use launcher 3b with `requires_openai_auth = true`. | Without the flag, Codex won't route OAuth through the custom provider; with it set in API-key mode, it breaks them. So set it **conditionally** on the detected mode. [H2][C3] |

**Detection helper** (port of Headroom `codex_uses_chatgpt_auth`): parse `auth.json`; `auth_mode.lower() == "chatgpt"` → OAuth; else if `tokens.account_id` is a non-empty string → OAuth (legacy); else API-key. [H1]

**Refresh/exchange:** none required by the proxy. Codex refreshes its own OAuth token in-process; the proxy only **passes the current `Authorization` (+ `ChatGPT-Account-ID`) through unchanged**. There is no token-exchange step (unlike Copilot's subscription path). If the OS keychain holds the token instead of `auth.json`, Codex still sends the header on the wire — the proxy forwards it regardless of where Codex sourced it.

---

## 5. Provider body adapter — OpenAI Responses (`/v1/responses`)

Request `input` items diverge sharply by `type`; classify each, redact only text-bearing fields, and **preserve every other item byte-for-byte** (re-serializing busts the provider prompt-cache and can break signed/diff payloads). [H3]

### 5a. REQUEST — redact

| JSON path | Why |
|---|---|
| top-level `instructions` (string) | system/developer prompt — high secret density |
| `input[]` item `type:"message"` → `content[]` parts `{type:"input_text", text}` | user/developer message text |
| `input[]` item `type:"function_call_output"` → `output` (string) | tool result = shell stdout / file content / patches — **highest** secret density |
| `input[]` item `type:"local_shell_call_output"` → `output` (string) | command stdout/stderr |
| `input[]` item `type:"apply_patch_call_output"` → `output` (string) | post-apply file content / error text |

> The three `*_output` strings are exactly the live-zone-eligible items in Headroom's classifier (`is_output_item()`), gated by an output floor (`OUTPUT_ITEM_MIN_BYTES = 512`). [H3] Scrimward redacts them regardless of size — secrets don't respect a 512-byte floor — but reuses the same per-item classification.

### 5b. REQUEST — NEVER touch (byte-fidelity; redacting these breaks the request)

| JSON path | Why untouchable |
|---|---|
| `type:"reasoning"` → `encrypted_content` | opaque provider-signed blob; rewriting invalidates it |
| `type:"compaction"` → `encrypted_content` | encrypted, cache-sticky |
| `type:"computer_call_output"` (screenshots) | image bytes; not text; passthrough |
| `type:"apply_patch_call"` → `operation.diff` (V4A unified diff) | re-serializing changes indentation → patch apply fails |
| `type:"local_shell_call"` → `action.command` (argv **array**) | joining/re-encoding changes shell-quoting semantics |
| `type:"function_call"` → `arguments` (JSON-encoded **string**) | the model built it and will parse it; never reparse/rewrite |
| any **unknown** `type` | preserve verbatim (no-silent-fallback contract) — a future OpenAI item type must flow through unchanged |

> Redact the *value of named text fields only*. Everything else — including the JSON envelope, key order, and Unicode escapes — must round-trip byte-identical so the provider prompt-cache keeps hitting.

### 5c. RESPONSE / SSE — un-mask (typed events)

Codex streams typed SSE events. Un-mask the text-bearing fields; the swap is the vault's reverse map (token → real secret). [C5][C6]

| SSE `event` / `type` | Field to un-mask | Notes |
|---|---|---|
| `response.output_text.delta` | `.delta` (string) | incremental assistant text — primary stream |
| `response.output_text.done` | `.text` (full part) | per OpenAI streaming-events sequence (`…delta(xN) → output_text.done`); the `.text` sub-field is standard but **not re-verified byte-for-byte in-session** — un-mask if present |
| `response.function_call_arguments.delta` | `.delta` (string) | streamed tool-call arguments; also carries `item_id`, `output_index`, `sequence_number` [C5] |
| `response.function_call_arguments.done` | `.arguments` (string) | finalized args — un-mask if present (standard, not in-session re-verified) |
| `response.completed` | `.response` (full object) | terminal event — do a **full sweep** of the response object to catch any token that slipped a delta |

**NEVER un-touch / never rewrite on the response path:** any `encrypted_content`, `*.reasoning.*` blobs, screenshot/image fields. Un-masking is text-field-scoped, same discipline as the request.

### 5d. Token-split-across-deltas reassembly (un-mask buffering)

A placeholder (`«EMAIL_1»` or a type-faithful form like `user1@redacted.invalid`) can be split across two `…delta.delta` chunks (`«EMA` then `IL_1»`). The un-masker MUST buffer, not replace per-chunk:

1. Maintain a per-stream **carry buffer** of unflushed tail.
2. On each delta: append to carry; un-mask all **complete** placeholders in carry.
3. **Hold back** a suffix that could be the **prefix of a partial placeholder** — i.e. the longest tail that matches the start of any token sentinel (`«`, or your type-faithful prefix). Flush everything before it to the client.
4. On `…output_text.done` / `response.completed` (stream end), flush the entire carry (any unterminated sentinel is emitted literally).

This keeps streaming smooth while guaranteeing no half-replaced token reaches the user, and no real secret leaks because un-masking is **inbound-only** (provider → user), never re-sent upstream.

---

## 6. Fail-closed gating

Default-deny on transport and on body inspection. **Refuse — never forward unredacted — if any of these fail:**

1. **Route-is-live probe (real round-trip, not "env var set"):** on launcher start, issue one canary `POST http://127.0.0.1:PORT/v1/responses` *through the same config Codex will use* with a planted high-entropy marker in `input[].content[].text`. Assert the proxy (a) received it, (b) parsed the Responses body, (c) the egress to `api.openai.com` had the marker **replaced by a placeholder**. If the proxy never saw it → the route is not active → **block Codex launch**.
2. **WS/realtime refusal:** if Codex negotiates a WebSocket/realtime transport (provider `supports_websockets`, `experimental_realtime_ws_base_url` set, or a `wss://` upgrade observed), the body-only HTTP adapter is blind → **refuse**. The launcher must not emit `supports_websockets` and must not set the realtime WS base URL (§3c).
3. **Unparseable body:** if a `/v1/responses` body can't be parsed/classified, **block** — do not "mask everything," and do not forward raw. (Unknown *item types* inside a parseable body are passed through byte-faithfully per §5b — that's different from an unparseable *envelope*.)
4. **Auth-mode mismatch:** if `requires_openai_auth=true` is configured but `auth.json` is API-key mode (or vice-versa), warn loudly and block until corrected — this is the #406-class breakage.

---

## 7. Caveats & path to ✅

To call Codex CLI **fully supported**, the following must be handled:

1. **WebSocket frame-relay adapter.** Today WS is forced off and refused (§6.2). Full ✅ requires a WS proxy that decodes Responses frames, applies the same §5 redact/un-mask, and re-frames — the analog of Headroom's `supports_websockets = true` path. Until then, HTTP-only is the supported surface.
2. **Empirical canary pass under BOTH auth modes**, in-session: API-key (launcher 3a) and ChatGPT-OAuth (launcher 3b with conditional `requires_openai_auth`). Confirm the `ChatGPT-Account-ID` header survives verbatim and the marker is absent from egress in each.
3. **Re-verify the two unconfirmed SSE sub-fields** (`response.output_text.done.text`, `response.function_call_arguments.done.arguments`) against the live stream and pin them, removing the "not re-verified in-session" caveat in §5c.
4. **Non-inference channels:** confirm whether Codex emits telemetry/update checks that bypass `OPENAI_BASE_URL` (analogous to Claude Code's `DISABLE_TELEMETRY`) and disable them — `OPENAI_BASE_URL`/the provider block covers **inference only**.

> Codex is **not** ⛔. There is no Codex cloud assembling the prompt before the provider call (unlike Cursor/Windsurf) — the payload is built and dispatched from your machine, so the local proxy genuinely sees it first over HTTP.

---

## 8. Test plan — canary-secret leak test

Goal: prove the secret is **ABSENT** from egress, the **placeholder is PRESENT** in egress, and the reply is **un-masked locally**.

```
SETUP
  1. Plant a high-entropy canary, e.g.  CANARY="sk-live-$(openssl rand -hex 24)"
     and a fake email canary  EMAIL="zztop-$(openssl rand -hex 4)@redacted-canary.test".
  2. Start the proxy on PORT with egress capture enabled (mitm/log of the
     outbound POST https://api.openai.com/v1/responses body + headers).
  3. Launch Codex via the mode-appropriate launcher (3a or 3b).

EXERCISE
  4. In Codex, paste a prompt containing CANARY and EMAIL and ask a question
     that forces a streamed reply referencing them
     (e.g. "what provider is this key sk-… for, and email a summary to <EMAIL>?").

ASSERT — on the captured EGRESS body (provider-bound):
  A. ABSENT:   CANARY  NOT in egress bytes        (grep -F "$CANARY"  → no match)
  B. ABSENT:   EMAIL   NOT in egress bytes        (grep -F "$EMAIL"   → no match)
  C. PRESENT:  a typed placeholder IS in egress   (e.g. «AWS_KEY_1»/«EMAIL_1»
               or the type-faithful form) in instructions/input[].content[].text
  D. Headers:  Authorization Bearer forwarded verbatim; in OAuth mode the
               ChatGPT-Account-ID header is present and unchanged.

ASSERT — on the LOCAL reply the user sees (post un-mask):
  E. UN-MASKED: the rendered answer contains the REAL CANARY / EMAIL again
               (vault reversed token → secret on response.output_text.delta).
  F. No half-token: no «…» fragment or split-placeholder artifact in the
               rendered text (validates §5d reassembly).

NEGATIVE / FAIL-CLOSED:
  G. Kill the proxy, relaunch Codex → launch is BLOCKED (probe §6.1 fails),
     not a silent direct-to-openai.com call.
  H. Force a WS/realtime route → BLOCKED (§6.2), not forwarded.
  I. Send a deliberately malformed /v1/responses body → BLOCKED (§6.3),
     never forwarded raw.

PASS = A∧B∧C∧D∧E∧F∧G∧H∧I.
```

The canary must be **high-entropy and unique per run** so a match in egress is unambiguous proof of leak (no false negatives from coincidental substrings).

---

## 9. Citations

**Official OpenAI / Codex docs (verified 2026-06-22):**
- [C1] Codex — Advanced configuration (`model_providers.<id>`, `base_url`, `wire_api`, `env_key`, `requires_openai_auth`, `[…].auth` command-backed auth; "Don't combine `[…].auth]` with `env_key`/`requires_openai_auth`"): https://developers.openai.com/codex/config-advanced
- [C2] Codex — Configuration reference (keys **ignored in project-local** `.codex/config.toml`: `openai_base_url`, `chatgpt_base_url`, `model_provider(s)`, `experimental_realtime_ws_base_url`, `profile(s)`, `notify`, `otel`): https://developers.openai.com/codex/config-reference
- [C3] Codex — Authentication (`~/.codex/auth.json` or OS credential store; ChatGPT sign-in is the default; API-key vs OAuth modes): https://developers.openai.com/codex/auth
- [C4] Codex — Config basics: https://developers.openai.com/codex/config-basic
- [C5] OpenAI API — Responses streaming events (`response.output_text.delta`, `response.function_call_arguments.delta` with `delta`/`item_id`/`output_index`/`sequence_number`, `response.completed`): https://developers.openai.com/api/reference/resources/responses/streaming-events
- [C6] OpenAI API — Streaming responses guide (event sequence `output_text.delta(xN) → output_text.done → … → response.completed`): https://developers.openai.com/api/docs/guides/streaming-responses
- OpenAI — Responses API reference (`POST /v1/responses`): https://platform.openai.com/docs/api-reference/responses

**Public issue corroboration (auth-flag breakage):**
- API-key/custom-provider still forces ChatGPT login or key — openai/codex #5555: https://github.com/openai/codex/issues/5555
- Desktop mixes local custom-provider base_url with remote auth.json key — openai/codex #24457: https://github.com/openai/codex/issues/24457
- (Headroom code comment references codex **#406** as the `requires_openai_auth`-breaks-api-key issue; the exact upstream number was not independently confirmable in-session — the *mechanism* is the verified fact.)
- Headroom feature issue confirming OAuth + `ChatGPT-Account-ID` passthrough for Codex Responses traffic — chopratejas/headroom #773: https://github.com/chopratejas/headroom/issues/773

**Headroom reference repo (`/tmp/headroom-ref`):**
- [H1] `headroom/providers/codex/install.py` — marker-block write/revert, orphan-key regexes, `codex_uses_chatgpt_auth`, conditional `requires_openai_auth`, `build_provider_section` (note: emits `supports_websockets = true` — **Scrimward omits this**).
- [H2] `headroom/providers/codex/runtime.py` — `proxy_base_url(port)` = `http://127.0.0.1:{port}/v1`; `build_launch_env` sets `OPENAI_BASE_URL`.
- [H3] `crates/headroom-proxy/src/responses_items.rs` — per-`type` classifier: `Message`/`content` parts, `*_call_output` `output` strings (redact-eligible), `reasoning`/`compaction` `encrypted_content`, `apply_patch` `diff`, `local_shell_call.action.command` argv array, `function_call.arguments` string (NEVER touch); `is_output_item()`, `OUTPUT_ITEM_MIN_BYTES = 512`, unknown-type byte-faithful passthrough.
- `tests/test_openai_codex_routing.py` — routing test reference.

**Scrimward internal:**
- `docs/REDACTION-POLICY.md` — redact value / preserve structure / restore on response; token format; fail-closed-is-transport-not-aggression.
- `docs/SUPPORTED-TOOLS.md` — Codex CLI row (⚠️ partial; Responses adapter; NEVER touch reasoning `encrypted_content`).
- `docs/VERIFICATION.md` — fail-closed probe + canary discipline (real round-trip, not "env var set").
