# Scrimward Integration — Google Gemini CLI

> **Status:** ⚠️ **PARTIAL → path-to-supported**
> Fully protectable for all three auth modes via a local fail-closed proxy. The "partial" is driven by *operational* gaps (`--sandbox` does not propagate the base-URL env vars — gemini-cli #2168 — and the 3-mode env matrix), **not** by an unprotectable data path. Google is the provider here; the CLI talks straight to Google's own endpoints with no intermediate vendor backend, so the local proxy genuinely guards the retained copy.

---

## 1. TL;DR verdict

Gemini CLI is **protectable** with the standard Scrimward local fail-closed proxy. There is no "own vendor backend" hazard: Google *is* the provider, and the CLI's only network egress for inference is to Google endpoints (`cloudcode-pa.googleapis.com` for OAuth, `generativelanguage.googleapis.com` for API-key, Vertex `aiplatform` for ADC) — a 127.0.0.1 proxy sits directly in that path and redacts the retained copy. The catch is routing: the **default OAuth "Login with Google"** path **ignores `GOOGLE_GEMINI_BASE_URL`** (verified: gemini-cli #15430 and source `createContentGeneratorConfig`) and must instead be pointed with **`CODE_ASSIST_ENDPOINT`** (verified base-URL override in `code_assist/server.ts`). It is ⚠️ rather than ✅ only because `--sandbox` drops these env vars (#2168) — so the hard precondition is **`--sandbox=false`** until that's handled.

---

## 2. Three modes at a glance (this is the whole integration)

| Mode | Trigger | Egress endpoint | Route override env | Body envelope | Auth header |
|---|---|---|---|---|---|
| **A. OAuth "Login with Google"** (DEFAULT) | no API key set; `gemini` after `/auth` | `POST https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse` | **`CODE_ASSIST_ENDPOINT`** (NOT `GOOGLE_GEMINI_BASE_URL`) | **wrapped** — `body.request.contents[]` + `body.request.systemInstruction`; routing IDs `body.model`, `body.project` | `Authorization: Bearer <oauth>` |
| **B. Gemini API key** | `GEMINI_API_KEY` / `GOOGLE_API_KEY` set | `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` (or `:streamGenerateContent?alt=sse`) | **`GOOGLE_GEMINI_BASE_URL`** | **native** — `body.contents[]` + `body.systemInstruction` | `x-goog-api-key: <key>` (default) — see §4 |
| **C. Vertex AI (ADC)** | `GOOGLE_GENAI_USE_VERTEXAI=true` + ADC | Vertex `aiplatform` `:generateContent` / `:streamGenerateContent` | **`GOOGLE_VERTEX_BASE_URL`** | **native** (same as B) | ADC `Authorization: Bearer` (gcloud-minted) |

Verified source anchors (gemini-cli `main`, fetched 2026-06-22):
- `packages/core/src/code_assist/server.ts:73-74` — `CODE_ASSIST_ENDPOINT='https://cloudcode-pa.googleapis.com'`, `CODE_ASSIST_API_VERSION='v1internal'`; `:521-525` `${endpoint}/${version}` base-URL composition; `:475` `alt:'sse'`.
- `packages/core/src/core/contentGenerator.ts:84-87` — `GOOGLE_GENAI_USE_VERTEXAI` and `GOOGLE_GEMINI_BASE_URL` gating; `:124-130` `validateBaseUrl` (only `new URL()`, **no HTTPS guard**); `:360` explicit `http://` branch; `:264-265` `GEMINI_API_KEY_AUTH_MECHANISM` default `x-goog-api-key`.

---

## 3. Launcher — route the CLI through 127.0.0.1:PORT

The Scrimward proxy listens on `http://127.0.0.1:PORT`. **Plain HTTP on loopback is accepted** — `validateBaseUrl` does only `new URL()` with no scheme guard, and the CLI explicitly branches on `baseUrl.startsWith('http://')` (`contentGenerator.ts:360`). **No TLS needed.** (Loopback only — do not bind a LAN IP; the docs scope these overrides to `localhost`/`127.0.0.1`/`[::1]`.)

### 3.1 Env vars to set (per mode)

```bash
PORT=8788   # Scrimward proxy port

# --- Mode A: OAuth (DEFAULT). GOOGLE_GEMINI_BASE_URL is IGNORED here. ---
export CODE_ASSIST_ENDPOINT="http://127.0.0.1:${PORT}"
# CLI appends "/v1internal:streamGenerateContent?alt=sse" itself.

# --- Mode B: Gemini API key ---
export GOOGLE_GEMINI_BASE_URL="http://127.0.0.1:${PORT}"
# CLI appends "/v1beta/models/{model}:...".

# --- Mode C: Vertex AI (ADC) ---
export GOOGLE_GENAI_USE_VERTEXAI=true
export GOOGLE_VERTEX_BASE_URL="http://127.0.0.1:${PORT}"
```

Set **only the var for the mode in use** — setting `CODE_ASSIST_ENDPOINT` while on the API-key path is harmless (unused), but mixing can mask a mis-route. The fail-closed probe (§6) catches the wrong-var case.

> Do **not** use `--proxy` for this. `--proxy` / `HTTPS_PROXY` is a *forward/CONNECT* proxy (`HttpProxyAgent`/`HttpsProxyAgent`, `contentGenerator.ts:360-363`) that tunnels TLS to Google opaquely — it does **not** terminate or expose the body, so Scrimward cannot inspect/redact it. The base-URL env vars are the only content hook.

### 3.2 Idempotent write + restore-on-exit (wrapper script)

Wrap, don't pollute the user's shell rc. `scrimward-gemini` launcher:

```bash
#!/usr/bin/env bash
set -euo pipefail
PORT="${SCRIMWARD_PORT:-8788}"
BASE="http://127.0.0.1:${PORT}"

# Snapshot prior values so an interactive session restores cleanly on exit.
_save() { eval "_OLD_$1=\"\${$1-__UNSET__}\""; }
_restore() {
  local v="$1"; local old; eval "old=\"\$_OLD_$v\""
  if [ "$old" = "__UNSET__" ]; then unset "$v"; else export "$v=$old"; fi
}
for v in CODE_ASSIST_ENDPOINT GOOGLE_GEMINI_BASE_URL GOOGLE_VERTEX_BASE_URL; do _save "$v"; done
trap 'for v in CODE_ASSIST_ENDPOINT GOOGLE_GEMINI_BASE_URL GOOGLE_VERTEX_BASE_URL; do _restore "$v"; done' EXIT

# Pick the mode from how the user is authed.
if [ "${GOOGLE_GENAI_USE_VERTEXAI:-}" = "true" ]; then
  export GOOGLE_VERTEX_BASE_URL="$BASE"                      # Mode C
elif [ -n "${GEMINI_API_KEY:-}${GOOGLE_API_KEY:-}" ]; then
  export GOOGLE_GEMINI_BASE_URL="$BASE"                      # Mode B
else
  export CODE_ASSIST_ENDPOINT="$BASE"                        # Mode A (default OAuth)
fi

# HARD precondition: sandbox drops these env vars (gemini-cli #2168).
exec gemini --sandbox=false "$@"
```

The simplest **idempotent** wiring is process-scoped env (subprocess only) — nothing to clean up because it never touches the parent shell or any file. If a settings-file route is desired instead, write to **project-local** `./.gemini/.env` (preferred — scoped to the repo) rather than `~/.gemini/.env` (global, leaks into every project). Make it idempotent by rewriting the whole managed block between sentinel comments:

```
# >>> scrimward managed (do not edit) >>>
CODE_ASSIST_ENDPOINT=http://127.0.0.1:8788
# <<< scrimward managed <<<
```
…and remove exactly that block on teardown (sed between sentinels). gemini-cli loads `.env` from the project tree, falling back to `~/.gemini/.env` then `~/.env`.

### 3.3 Scope gotchas

- **Global vs project-local:** `~/.gemini/.env` / `~/.env` are global and apply to **every** invocation (including non-redacted ones you didn't intend to wrap) — prefer the subprocess-env wrapper or `./.gemini/.env`.
- **`--sandbox` (CRITICAL):** with `sandbox: true` / `GEMINI_SANDBOX=true`, **`GOOGLE_*_BASE_URL` are NOT propagated into the container** (#2168) → the CLI silently falls back to Google's real endpoint and **leaks unredacted**. Mitigation today: force `--sandbox=false` (verified workaround). This is the #1 path-to-✅ item (§7). `CODE_ASSIST_ENDPOINT` is also not guaranteed to cross the sandbox boundary — treat all three as sandbox-incompatible until proven.
- **Cloud Shell:** Cloud Shell injects its own `GOOGLE_CLOUD_PROJECT` and may force auth; treat as out-of-scope for a local proxy.

### 3.4 Per-OS notes

- **macOS / Linux:** `export VAR=...` as above. macOS default sandbox is Seatbelt (`sandbox-exec`); same #2168 caveat applies → `--sandbox=false`.
- **Windows (PowerShell):** `$env:CODE_ASSIST_ENDPOINT="http://127.0.0.1:8788"`; restore with `Remove-Item Env:\CODE_ASSIST_ENDPOINT`. The docs give PowerShell forms for every var.
- **WSL/Docker/CI:** loopback is per-namespace — the proxy must listen inside the **same** network namespace as the CLI, or use that namespace's host alias. (Sandbox is a container, hence #2168.)

---

## 4. Auth handling

Scrimward **forwards the inbound auth credential verbatim** — it never mints, exchanges, or refreshes Google tokens. The CLI's own credential cache/refresh keeps working; the proxy only swaps the *request body*, leaving auth headers untouched end to end.

| Mode | Credential | Header on the wire | Scrimward action | What breaks / avoid |
|---|---|---|---|---|
| **A. OAuth** | OAuth2 access token (from `~/.gemini/oauth_creds.json`, refreshed by CLI) | `Authorization: Bearer <token>` | **Forward verbatim.** Do not strip/rewrite `Authorization`. | If you drop the header → 401. The CLI refreshes the token itself before each call; the proxy must not cache or pin a token. |
| **B. API key** | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | **`x-goog-api-key: <key>`** by default; **`Authorization: Bearer <key>`** if `GEMINI_API_KEY_AUTH_MECHANISM=bearer` (`contentGenerator.ts:264-279`) | **Forward whichever header is present, verbatim.** Detect both; do not hardcode `x-goog-api-key`. | Hardcoding only `x-goog-api-key` drops the bearer variant → 401. Also pass through the `?key=` query param if the CLI uses it on some paths. |
| **C. Vertex (ADC)** | Application Default Credentials (gcloud / SA / metadata server) → short-lived bearer | `Authorization: Bearer <adc>` | **Forward verbatim.** | ADC tokens are minted by Google's auth client *inside* the CLI before egress; the proxy must not attempt its own token mint. `GOOGLE_CLOUD_PROJECT` / `GOOGLE_CLOUD_LOCATION` ride in the URL path / body — pass through. |

**Header hygiene (all modes):** strip hop-by-hop headers (`host`, `content-length`, `accept-encoding`) before re-emitting upstream and recompute `content-length` after redaction (the body length changes). Never strip `Authorization` / `x-goog-api-key`. Decompress any gzip request body before parsing (default-deny if you can't, §6).

---

## 5. Provider body adapter

Two body envelopes only. Detect by route/shape, not by guesswork:
- **Envelope A (native):** path `…:generateContent` / `…:streamGenerateContent`; top-level `contents` + `systemInstruction`. Used by **Mode B (API key)** and **Mode C (Vertex)**.
- **Envelope B (Cloud Code Assist, wrapped):** path `/v1internal:streamGenerateContent`; top-level `request` wrapper. Used by **Mode A (OAuth)**. Detected exactly as Headroom does (`body.get("request")` is a dict → `gemini.py:767`).

### 5.1 REQUEST fields to REDACT (real secret → stable token, e.g. `«EMAIL_1»`)

**Envelope A (native):**
- `body.contents[].parts[].text` — all conversation text (user + model turns).
- `body.systemInstruction.parts[].text` (also accept snake_case `system_instruction`, which the CLI tolerates — `gemini.py:303`).

**Envelope B (Cloud Code Assist, wrapped):**
- `body.request.contents[].parts[].text`
- `body.request.systemInstruction.parts[].text`

Apply the same per-turn text redactor to both; the only difference is the `.request.` prefix.

### 5.2 Fields to NEVER touch (pass through byte-for-byte)

- **Routing / identity IDs:** `body.model`, and (Envelope B) `body.project` — GCP project/model routing keys; mangling them breaks the call. Also `body.request.model` if present, `generationConfig`, `safetySettings`, `tools` / `toolConfig` declarations, `cachedContent`, `labels`.
- **Non-text parts** (any envelope), exactly per Headroom's `_has_non_text_parts` (`gemini.py:53-75`): `inlineData` (base64 media), `fileData` (URI+MIME), `functionCall`, `functionResponse`. Redacting structured tool args/results corrupts tool execution — leave them intact. (If a deployment needs tool-arg redaction, that's a separate typed-field redactor, out of scope here.)
- All auth headers (§4).

### 5.3 RESPONSE / SSE fields to UN-MASK (token → real secret, locally)

Both modes stream **`alt=sse`** — verified `params:{alt:'sse'}` at `code_assist/server.ts:475`. The wire is **bare `data:` SSE frames with NO `event:` names**. Each frame's payload, after the CLI joins buffered `data: ` lines and `JSON.parse`s them (`server.ts:489-520`), is a `GenerateContentResponse` JSON object.

Un-mask field path (identical in both envelopes — the response is native even when the *request* was wrapped):
- `candidates[].content.parts[].text`

For each outbound SSE frame the proxy emits to the CLI:
1. Parse the JSON after `data: `.
2. Walk `candidates[].content.parts[]`, and for every part containing `text`, swap tokens → secrets via the session vault.
3. Re-serialize and emit as a well-formed `data: {json}\n\n` frame.

**NEVER touch in the response:** `candidates[].finishReason`, `safetyRatings`, `citationMetadata`, `groundingMetadata`, `usageMetadata` (`promptTokenCount` / `candidatesTokenCount` / `totalTokenCount`), `modelVersion`, `responseId`, and any non-text part. Only `parts[].text` carries secrets to restore.

**Framing discipline (fail-closed-adjacent):** the CLI **silently drops a malformed JSON chunk** (`logInvalidChunk`, content deliberately not logged — `server.ts:505-512`). So a re-serialization error = invisible content loss, not a visible error. The adapter must emit only valid JSON frames; on a serialization failure, fail closed (abort the stream with an error) rather than forward a broken frame.

### 5.4 Token split across deltas (reassembly) — *design, not Headroom-verified*

A placeholder token (`«EMAIL_1»`) can be split across two consecutive SSE deltas (`…«EMA` then `IL_1»…`). Naïve per-delta replacement misses it. Scrimward reassembly (Scrimward-specific; Headroom's `streaming.py` buffering is compression-oriented and not assumed here):
1. Maintain a per-stream rolling **tail buffer** of un-emitted trailing text whose suffix could be the start of a placeholder (longest possible partial-token prefix, e.g. `len(longest placeholder) - 1` chars).
2. On each delta, concatenate `tail + new_text`, run the token→secret replacement, then emit everything **up to the last safe boundary** (the last index that cannot be the start of a partial placeholder); retain the remainder as the new tail.
3. On stream end (or `finishReason` present), flush the tail through replacement and emit.
4. Placeholders are a fixed grammar (`«TYPE_N»` with sentinel delimiters), so the "could-be-partial" test is a cheap suffix check against that grammar — not a full scan.

This is deterministic and content-hash cacheable, preserving Google's prompt-cache hit rate (same skeleton bytes per identical input).

---

## 6. Fail-closed gating

**Default-deny body inspection.** The proxy forwards a body **only** when it has parsed it and applied the matching redactor. If any of these hold, **BLOCK with a local 4xx/5xx (do not forward upstream):**

- Body is not valid JSON / not decompressible / exceeds the inspect size cap.
- Route is unrecognized (path is neither `…:generateContent`/`…:streamGenerateContent` nor `/v1internal:streamGenerateContent`).
- Envelope expected wrapped (`/v1internal…`) but `body.request` is absent/not a dict (Headroom returns 400 "missing request payload" here — `gemini.py:767-779`; Scrimward should likewise refuse, not forward).
- The redactor couldn't be applied to every text field it found.

### 6.1 Route-live probe (run before declaring the session protected)

The danger is a *silent mis-route* (wrong env var for the mode, or sandbox stripping it → CLI hits Google directly, unredacted). Verify positively:

1. **Proxy up:** `GET http://127.0.0.1:PORT/healthz` (Scrimward health endpoint) returns 200 with the proxy's build id.
2. **CLI actually points at us:** run a one-shot through the wrapper with a unique **canary** prompt and assert the proxy's request log shows that canary arriving on the expected route (`/v1internal:streamGenerateContent` for Mode A, `/v1beta/models/*:streamGenerateContent` for B/C). If the canary does **not** hit the proxy within the timeout → the route is dead (wrong var / sandbox) → **refuse to proceed**, surface "route not active — unredacted egress possible."
3. **Sandbox assertion:** if `--sandbox` is on / `GEMINI_SANDBOX` is set and not `false`, **refuse** (known #2168 leak).

Treat "I configured the env var" as **not** proof — only a captured request arriving at the proxy proves the route is live (this mirrors the user-vantage verification rule).

---

## 7. Caveats & path to ✅ (this is a ⚠️ tool)

To call Gemini CLI **fully supported**, handle each concretely:

1. **Sandbox propagation (#2168) — primary blocker.** Today: hard-require `--sandbox=false`. To reach ✅: either (a) inject the base-URL env vars into the sandbox profile (mount/whitelist `CODE_ASSIST_ENDPOINT` / `GOOGLE_*_BASE_URL` into the Docker/Podman/Seatbelt env), or (b) run the Scrimward proxy *inside* the sandbox's network namespace and point the CLI at it there, or (c) gate-and-refuse when sandbox is on (current behavior). Verify by canary probe from *inside* the sandbox.
2. **Three-mode auto-detection.** The wrapper picks the env var from auth state; harden it so a user who switches auth mid-session (e.g. exports `GEMINI_API_KEY` after starting on OAuth) doesn't end up with a stale/ignored override. The §6 probe is the safety net — keep it mandatory.
3. **API-key auth-mechanism variants.** Forward both `x-goog-api-key` and `Authorization: Bearer` (`GEMINI_API_KEY_AUTH_MECHANISM=bearer`) and the `?key=` query form; add a regression test per variant.
4. **Tool-call payloads.** Text redaction leaves `functionCall`/`functionResponse` args untouched by design. If a deployment requires redacting secrets *inside* tool args, add a typed structured-field redactor and re-test tool execution — otherwise document that tool-arg content is out of scope.
5. **`countTokens` path.** `…:countTokens` also carries `contents[].parts[].text`. Redact it too (or block) so token-count calls don't leak; it returns no text to un-mask.

When 1–5 are handled and the §8 canary test passes for all three modes (incl. inside the sandbox for #1), this graduates to ✅.

---

## 8. Test plan — canary-secret leak test

Goal: prove the **retained copy at Google never contains the secret**, the provider sees a faithful **placeholder**, and the **user's local reply is fully un-masked**. Run once per mode (A/B/C).

**Setup**
1. Start the Scrimward proxy on `127.0.0.1:8788` with egress capture enabled (the proxy logs the exact bytes it forwards upstream — that captured upstream body is the ground truth, not a `mitmproxy` of TLS-to-Google).
2. Plant a high-entropy canary in the vault domain, e.g. `CANARY_SECRET="SCRIMWARD-CANARY-$(openssl rand -hex 16)"` mapped to a stable token like `«CANARY_1»`. Use a value that is **not** a natural language word so a false "absent" can't be a tokenizer artifact.

**Exercise (per mode)**
3. Launch via the §3.2 wrapper for that mode (`CODE_ASSIST_ENDPOINT` / `GOOGLE_GEMINI_BASE_URL` / `GOOGLE_VERTEX_BASE_URL`), `--sandbox=false`.
4. Prompt: `Repeat this exactly: my key is SCRIMWARD-CANARY-<hex>` (forces the secret into both request *and* the model's streamed reply).

**Assert**
5. **Egress redaction (request):** in the captured upstream body, assert `CANARY_SECRET` is **ABSENT** and the placeholder `«CANARY_1»` is **PRESENT** at the right path:
   - Mode A: `request.contents[].parts[].text`
   - Modes B/C: `contents[].parts[].text`
6. **Local un-mask (response):** in the CLI's rendered output, assert the **real** `CANARY_SECRET` is **PRESENT** (vault restored it) and the placeholder `«CANARY_1»` is **ABSENT** in what the user sees.
7. **Split-delta robustness:** repeat with a prompt that makes the model echo the secret mid-sentence so the placeholder likely spans SSE deltas; assert §6 still holds (no half-tokens like `«CANARY` or `_1»` in either egress or local output).
8. **Route-live negative test:** unset the override env var (or set `--sandbox=true`) and re-run; assert the proxy's request log shows **no** canary arriving (CLI bypassed us) and that the §6 probe **refuses** to declare the session protected. This proves fail-closed catches the leak path rather than silently allowing it.
9. **Never-touch integrity:** assert `usageMetadata`, `finishReason`, `model`/`project`, and any `inlineData`/`functionCall` parts are byte-identical pre/post proxy.

Pass criteria: steps 5–9 green for all three modes. Any secret leaked to egress, any placeholder left in the user's reply, or any route that bypasses the proxy without §6 refusing = **FAIL** (regardless of the chart "drawing").

---

## 9. Citations

**Official Gemini CLI docs & source (verified 2026-06-22, repo `google-gemini/gemini-cli@main`)**
- Configuration reference (env vars: `CODE_ASSIST_ENDPOINT`, `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_VERTEX_BASE_URL`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `GOOGLE_GENAI_USE_VERTEXAI`, `GEMINI_SANDBOX`): https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md
- Configuration (hosted): https://google-gemini.github.io/gemini-cli/docs/get-started/configuration.html
- Authentication setup: https://google-gemini.github.io/gemini-cli/docs/get-started/authentication.html
- Sandboxing (profiles, `--sandbox` semantics): https://google-gemini.github.io/gemini-cli/docs/cli/sandbox.html
- `packages/core/src/code_assist/server.ts` — `CODE_ASSIST_ENDPOINT` base-URL override (`:73-74`, `:521-525`), `alt:'sse'` (`:475`), SSE `data:` line parser (`:489-520`): https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/code_assist/server.ts
- `packages/core/src/core/contentGenerator.ts` — `GOOGLE_GEMINI_BASE_URL`/`USE_VERTEXAI` gating (`:84-87`), `validateBaseUrl` no-HTTPS-guard (`:124-130`), `http://` branch (`:360`), `GEMINI_API_KEY_AUTH_MECHANISM` (`:264-279`): https://github.com/google-gemini/gemini-cli/blob/main/packages/core/src/core/contentGenerator.ts

**Verified issues (the ⚠️ drivers)**
- #15430 — CLI ignores `GOOGLE_GEMINI_BASE_URL` and forces Cloud Auth/Endpoints (→ must use `CODE_ASSIST_ENDPOINT` for the OAuth path): https://github.com/google-gemini/gemini-cli/issues/15430
- #2168 — `GOOGLE_*_BASE_URL` not propagated to sandbox (→ require `--sandbox=false`): https://github.com/google-gemini/gemini-cli/issues/2168

**Headroom reference (real handler this adapter mirrors)**
- `headroom/proxy/handlers/gemini.py` — two-envelope handling: native `:generateContent` (`handle_gemini_generate_content` / `handle_gemini_stream_generate_content`), wrapped Cloud Code Assist (`handle_google_cloudcode_stream`, `body["request"]` at `:767`, base URL `{base}/v1internal:streamGenerateContent` at `:888`), `_has_non_text_parts` (`:53-75`).
- `headroom/providers/registry.py` — target routing (`:60-78`: `x-goog-api-key` → gemini target; `cloudcode` target), `CLOUDCODE_TARGET_API_URL` / `GEMINI_TARGET_API_URL` env overrides (`:106-124`).
- `headroom/providers/proxy_routes.py` — route registration: `/v1beta/models/{model}:generateContent|:streamGenerateContent|:countTokens` (`:631-641`), `/v1internal:streamGenerateContent` (`:643-649`).
- `headroom/providers/gemini/runtime.py` — `DEFAULT_API_URL = "https://generativelanguage.googleapis.com"`.
