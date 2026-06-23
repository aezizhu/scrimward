# Scrimward integration: GitHub Copilot (CLI + IDE)

![status](https://img.shields.io/badge/status-%E2%9A%A0%EF%B8%8F%20partial-orange) **⚠️ Partial** — CLI BYOK is clean today; CLI subscription needs a token discovery/exchange module; the VS Code/IDE chat path is the weakest and is effectively *not protectable* for the **subscription** model path.

> Scope of this doc: the [shared Scrimward architecture](../../README.md) — one local fail-closed proxy on `127.0.0.1` plus a reversible session vault — applied to GitHub Copilot. Per tool we add (a) a **launcher** that points Copilot's base-URL knob at the proxy and forwards auth, and (b) a per-**provider** body **adapter** that redacts the request and un-masks the streamed reply.

---

## 1. TL;DR verdict

GitHub Copilot has **two** very different surfaces. The **CLI** exposes a real provider-override hook (`COPILOT_PROVIDER_BASE_URL`, added 2026-04-07) that points at `127.0.0.1` and works: in **BYOK** mode the request is a plain OpenAI-compatible Chat Completions call with *your* provider key forwarded verbatim — clean and fully interceptable today. The **subscription** path (use the Copilot seat you already pay GitHub for, with no separate key) is also interceptable through the same knob, but it needs an extra module that discovers the GitHub OAuth token from the OS secret store and exchanges it for a short-lived Copilot API token, then points the proxy back at `api.githubcopilot.com`. The **VS Code / IDE** path is the weakest: its "OpenAI Compatible" custom endpoint protects only that BYOK provider, while the **Copilot subscription** model traffic still routes through GitHub's CAPI (`api.githubcopilot.com` / `api.individual.githubcopilot.com`) with **no usable base-URL override** (`debug.overrideCapiUrl` is ignored — microsoft/vscode-copilot-release#7802), so for that path a local proxy can only sit in front via HTTPS MITM, not a clean override.

---

## 2. Surfaces at a glance

| Surface | Auth mode | Hook | Scrimward status |
|---|---|---|---|
| **Copilot CLI** | BYOK (your provider key) | `COPILOT_PROVIDER_BASE_URL` → `127.0.0.1` | ✅ clean (ship first) |
| **Copilot CLI** | GitHub subscription (no key) | same knob + token discovery/exchange + point proxy back at `api.githubcopilot.com` | ⚠️ partial — needs the auth module |
| **VS Code / IDE chat** | BYOK "OpenAI Compatible" custom endpoint | *Chat: Manage Language Models* → custom endpoint base URL | ⚠️ partial — only that BYOK provider; UI step, weakest UX |
| **VS Code / IDE chat** | Copilot **subscription** model | none (`debug.overrideCapiUrl` ignored, #7802) | ⛔ not protectable via override (only HTTPS MITM) |

---

## 3. Launcher

### 3.1 CLI — BYOK (ship this first; clean)

The Copilot CLI reads provider config from **environment variables** at process start (no project config file for BYOK). The canonical, documented set (GitHub Docs, *Using your own LLM models in GitHub Copilot CLI*; BYOK landed in the [2026-04-07 changelog](https://github.blog/changelog/2026-04-07-copilot-cli-now-supports-byok-and-local-models/)):

| Var | Required | Meaning |
|---|---|---|
| `COPILOT_PROVIDER_BASE_URL` | yes | Base URL of the provider endpoint. **Point at the proxy.** Works with plain `http://127.0.0.1:PORT` (verified by Headroom + Ollama localhost examples in the docs). |
| `COPILOT_PROVIDER_TYPE` | optional | `openai` (default) · `azure` · `anthropic`. Verified accepted values per GitHub Docs. |
| `COPILOT_PROVIDER_API_KEY` | optional | Your provider key. **Forwarded verbatim** to the upstream — see §4. |
| `COPILOT_MODEL` | yes (BYOK) | Concrete model name. `--model auto` is a Copilot-internal routing token and is **rejected** by BYOK endpoints with `400 The requested model is not supported` — strip it. |
| `COPILOT_OFFLINE` | recommended | `COPILOT_OFFLINE=true` stops the CLI contacting GitHub's servers and disables telemetry; the CLI then talks only to your configured provider. Set it so non-inference channels don't bypass the proxy. |

**Launcher recipe (idempotent, restore-on-exit).** Scrimward launches Copilot as a child with a *scoped* environment — never mutating the user's global shell — and tears the proxy down on exit. Pseudocode:

```sh
# scrimward wrap copilot -- --model gpt-4o
PORT=8787
# 1. stand up the proxy (fail-closed); abort if it isn't live (see §6)
scrimward-proxy --port "$PORT" --provider openai &  PROXY_PID=$!
scrimward-proxy-wait "$PORT" || { echo "proxy not live — refusing"; exit 1; }

# 2. launch Copilot with a SCOPED env (child only — nothing leaks to the parent shell)
env \
  COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:${PORT}/v1" \
  COPILOT_PROVIDER_TYPE="openai" \
  COPILOT_PROVIDER_API_KEY="${OPENAI_API_KEY:?BYOK needs a provider key}" \
  COPILOT_MODEL="${COPILOT_MODEL:-gpt-4o}" \
  COPILOT_OFFLINE="true" \
  copilot "$@"

# 3. always restore: kill the proxy on exit (trap covers Ctrl-C / errors)
trap 'kill "$PROXY_PID" 2>/dev/null' EXIT INT TERM
```

- **Note the `/v1` suffix** on the base URL for the OpenAI/Chat-Completions path. The CLI appends `/chat/completions` (or `/responses`) to it; the proxy then forwards to the real provider. (Mirrors Headroom's `build_launch_env`, which uses `http://127.0.0.1:{port}/v1` for the openai type and a bare `http://127.0.0.1:{port}` for the anthropic type.)
- **Anthropic BYOK:** set `COPILOT_PROVIDER_TYPE=anthropic`, `COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:PORT` (no `/v1`), `COPILOT_PROVIDER_API_KEY=$ANTHROPIC_API_KEY`. The proxy runs its Anthropic Messages adapter.
- **Azure BYOK:** `COPILOT_PROVIDER_TYPE=azure`, base URL points at the proxy which forwards to `https://<resource>.openai.azure.com/openai/deployments/<deployment>`; treat as the OpenAI Chat Completions shape downstream.

**Idempotency / scope gotchas.**
- **Scope: child env, not global.** Because BYOK config is *environment only*, the cleanest launcher sets these vars **only in the spawned child** (the `env …  copilot` form above). There is nothing to "write idempotently and restore" if you never touch the parent shell or any dotfile — exit restoration is just killing the proxy. **Prefer this.**
- If a user insists on a persistent shell export (`~/.zshrc`/`~/.bashrc`), write a **marker-delimited block** (`# >>> scrimward copilot >>>` … `# <<< scrimward copilot <<<`), snapshot the prior values into a sibling `# was: …` comment, and provide `scrimward unwrap copilot` that removes the block byte-for-byte. This is strictly worse than child-env scoping because a stranded `COPILOT_PROVIDER_BASE_URL` silently reroutes *all* future `copilot` runs to a dead proxy port (fail-closed will then refuse — annoying but safe).
- **Per-OS:** the env-var mechanism is identical on macOS / Linux / Windows. On Windows use `setx` only for the persistent variant (and document the `reg delete` undo); prefer the per-invocation `cmd /c "set VAR=… && copilot …"` or PowerShell `$env:` scoped block.

### 3.2 CLI — subscription (no provider key)

Same `COPILOT_PROVIDER_BASE_URL` knob, but the launcher must additionally (a) discover/exchange a token (§4.2), (b) hand the proxy the validated token, and (c) point the proxy's **upstream** back at GitHub's Copilot host so the request actually reaches the model. Verified against Headroom's working implementation (`headroom/cli/wrap.py`, the `--subscription` branch):

```sh
# resolved by the auth module (§4.2): a usable Copilot API token + the upstream host
COPILOT_TOKEN="$(scrimward-copilot-auth resolve-token)"       # tid_… (already exchanged)
UPSTREAM="$(scrimward-copilot-auth resolve-api-url)"          # default https://api.githubcopilot.com

env \
  COPILOT_PROVIDER_TYPE="openai" \
  COPILOT_PROVIDER_BASE_URL="http://127.0.0.1:${PORT}/v1" \
  COPILOT_PROVIDER_WIRE_API="completions" \
  COPILOT_PROVIDER_BEARER_TOKEN="${COPILOT_TOKEN}" \
  GITHUB_COPILOT_USE_TOKEN_EXCHANGE="false" \
  copilot "$@"
# …and the PROXY is configured with its UPSTREAM = $UPSTREAM and pinned token = $COPILOT_TOKEN
```

- Headroom forwards the validated bearer to the CLI as `COPILOT_PROVIDER_BEARER_TOKEN`, sets `GITHUB_COPILOT_USE_TOKEN_EXCHANGE=false` (the token is *already* the exchanged Copilot API token, so the CLI/proxy must not re-exchange), and pins the same token on the proxy as `GITHUB_COPILOT_API_TOKEN` plus `GITHUB_COPILOT_API_URL=$UPSTREAM`. Pinning it as a launch arg — not in the parent's `os.environ` — keeps the secret off shared state.
- **`--model auto`** must be **stripped** in subscription mode too (Copilot then uses its own native auto-routing on the real host); forwarding `auto` to a BYOK-shaped endpoint 400s.
- **Wire API:** `completions` by default; for reasoning models the wire API flips to `responses` (see §5).
- **Enterprise / data-residency:** if the org is pinned to a dedicated host, set `GITHUB_COPILOT_API_URL=https://api.<your-host>.githubcopilot.com`; the override flows through to the proxy's upstream. Do **not** auto-select a per-account host from `/copilot_internal/user` — it advertises a segmented host (`api.individual.githubcopilot.com`) that does not serve newer models on the responses API (Headroom regressed on this — issue #610).

### 3.3 VS Code / IDE

- **BYOK custom endpoint (partial):** Command Palette → **Chat: Manage Language Models** → **OpenAI Compatible** provider → set **Base URL** to `http://127.0.0.1:PORT/v1` and a model id. The provider probes `GET /models` to populate the dropdown, so the proxy **must** answer `GET /v1/models` with a non-empty list or the UI shows *"Failed to fetch model list"*. This is a **manual UI step** (no idempotent file write Scrimward can own reliably across VS Code versions; the BYOK config currently lives in VS Code's storage and was Insiders-gated through May 2026, reaching the stable channel only recently — re-confirm the exact settings key before automating).
- **Subscription model path (not protectable via override):** Copilot's own (subscription) models route to GitHub CAPI with no honored base-URL override — `debug.overrideCapiUrl` is **ignored** (microsoft/vscode-copilot-release#7802). The only way a local proxy sees that traffic is transparent **HTTPS MITM** (`HTTPS_PROXY` + a trusted local CA via `NODE_EXTRA_CA_CERTS`), which is brittle, pins to certificate trust, and is out of scope for the clean-override architecture. **Treat the IDE subscription path as ⛔ for the override design.** See §7.

---

## 4. Auth handling

### 4.1 BYOK — forward verbatim (clean)

`COPILOT_PROVIDER_API_KEY` is **your own provider key** (OpenAI `sk-…`, Anthropic, Azure). The CLM sends it as the standard provider auth header (`Authorization: Bearer …` for OpenAI, `x-api-key` for Anthropic). The proxy **forwards it verbatim** to the upstream provider — Scrimward never needs to mint, exchange, or refresh anything. Nothing breaks. This is why BYOK ships first.

> Honest note: BYOK means you pay your provider directly and the request bypasses GitHub's Copilot backend entirely. The retained copy is at *your provider* — exactly what Scrimward is built to protect, because the proxy sits in front of it.

### 4.2 Subscription — discover → exchange → refresh (not verbatim)

In subscription mode the Copilot bearer is **not** something the user typed — it must be discovered from the OS and exchanged. Verified end-to-end against Headroom's `copilot_auth.py`:

**Discovery order (safest-first):**
1. Explicit env: `GITHUB_COPILOT_API_TOKEN` / `COPILOT_PROVIDER_BEARER_TOKEN` (already-exchanged Copilot API token — `tid_…`).
2. Copilot OAuth env: `GITHUB_COPILOT_GITHUB_TOKEN`, `GITHUB_COPILOT_TOKEN`, `COPILOT_GITHUB_TOKEN`.
3. **OS secret store** (the normal case after `copilot` device-login):
   - **macOS Keychain:** generic password, service `copilot-cli` → `security find-generic-password -s copilot-cli -w` (Headroom also tries `GitHub Copilot`, `github-copilot`, `GitHub CLI`, and internet-password variants; resolves the login from `~/.copilot/config.json` → `lastLoggedInUser.login`).
   - **Linux libsecret:** `secret-tool lookup service copilot-cli` (also tries `application copilot-cli`, service names `GitHub Copilot CLI`/`github-copilot`/`copilot`, with account = `https://github.com:<login>` etc.).
   - **Windows Credential Manager:** enumerate creds, match `gh:github.com:` and `copilot-cli/…` target prefixes (ctypes `CredEnumerateW`).
4. Credential **files**: `~/.config/github-copilot/{apps.json,hosts.json}` (and `%LOCALAPPDATA%\github-copilot\…` on Windows) — filter entries whose key contains the GitHub host, skip expired entries.
5. Generic GitHub token env (`GH_TOKEN`, `GITHUB_TOKEN`) and `gh auth token` as last resorts.

**Token kind matters.** A discovered token is either:
- a **Copilot API token** (prefix `tid_…`) → already short-lived; use directly (validate via `GET https://api.github.com/copilot_internal/user` returning 200), **do not** re-exchange; or
- a **GitHub OAuth token** (`gho_`, `ghs_`, `ghp_`, `github_pat_`) → **must be exchanged**, never forwarded directly.

**Exchange** (for OAuth tokens): `GET https://api.github.com/copilot_internal/v2/token` with `Authorization: Bearer <oauth_token>` plus Copilot client headers (`User-Agent: GitHubCopilotChat/…`, `Editor-Version: vscode/…`, `Editor-Plugin-Version: copilot-chat/…`, `Copilot-Integration-Id: vscode-chat`). Response yields `{ token: "tid_…", expires_at, refresh_in, endpoints.api, sku }`.

**Refresh:** the exchanged token is short-lived (~minutes). Cache it and re-exchange when `time.time() >= expires_at - 60s` (Headroom's `_TOKEN_EXPIRY_BUFFER_S = 60`). Hold an async lock so concurrent requests don't stampede the exchange.

**Device login (first run):** if nothing is discoverable, run the GitHub device-code flow — `POST https://github.com/login/device/code` then poll `POST https://github.com/login/oauth/access_token` (client id `Iv1.b507a08c87ecfe98`, scope `read:user`, grant `urn:ietf:params:oauth:grant-type:device_code`), persist the OAuth token to a `0600` file. (Verified constants from `copilot_auth.py`.)

**What breaks & how to avoid it.**
- **Forwarding a `gho_`/`ghs_` token to the Copilot API → 401/403.** Always classify by prefix and exchange OAuth tokens first.
- **Re-exchanging an already-`tid_` token → wasted call / possible 401.** Detect `tid_` and pass through.
- **Auto-selecting `endpoints.api` from `/copilot_internal/user` → routes to `api.individual.githubcopilot.com`, which lacks newer models on the responses API (#610).** Default to the generic host `api.githubcopilot.com`; only honor a host pinned via `GITHUB_COPILOT_API_URL`.
- **Discovery returning the *first* candidate the proxy didn't validate → environment-dependent 401s.** Resolve & validate the token in the launcher, then **pin** it for the proxy instance (`GITHUB_COPILOT_API_TOKEN`) so upstream auth is deterministic.

---

## 5. Provider body adapter

Route by `COPILOT_PROVIDER_TYPE` and request **path**, then apply the standard per-format field maps. The proxy already ships these adapters for the other tools; Copilot reuses them.

### Routing
| Provider type | Wire API | Path the CLI calls | Adapter |
|---|---|---|---|
| `openai` (default) | `completions` | `/v1/chat/completions` | OpenAI Chat Completions |
| `openai` | `responses` (gpt-5/o1/o3) | `/v1/responses` | OpenAI Responses |
| `anthropic` | — | `/v1/messages` (base without `/v1` prefix) | Anthropic Messages |
| `azure` | completions-shaped | `…/chat/completions?api-version=…` | OpenAI Chat Completions |

> Confidence note: `COPILOT_PROVIDER_TYPE ∈ {openai, azure, anthropic}` is **verified** (GitHub Docs). The **`responses` wire-API selection for gpt-5/o1/o3** is **Headroom-derived** (`model_prefers_responses_api`: model name starts with `gpt-5`/`o1`/`o3`), *not* stated in GitHub's BYOK docs — treat as a heuristic and confirm against a live request before relying on it. GitHub's BYOK docs do not pin exact endpoint paths per type; the `/chat/completions` vs `/messages` split is inferred from each provider's standard wire format and Headroom's base-URL construction.

### OpenAI Chat Completions (`/v1/chat/completions`)
- **REDACT (request):** every `messages[].content` — both the string form and the array form (`messages[].content[].text` for `type:"text"` parts); `tools[].function.description`/`parameters` only if they carry user data; **`tool` role messages** (`messages[].content` of tool results) — these carry command/file output and are a top leak source.
- **UN-MASK (response/SSE):** streamed deltas `choices[].delta.content`; **tool-call argument fragments** `choices[].delta.tool_calls[].function.arguments` (args carry content and arrive **split across many deltas** — reassemble per `tool_calls[].index` before un-masking so a token split mid-placeholder doesn't corrupt). Non-stream: `choices[].message.content` and `choices[].message.tool_calls[].function.arguments`.
- **NEVER touch:** `model`, `id`, `created`, `usage`, `finish_reason`, `role`, `tool_calls[].id`, `index`, the SSE framing (`data:` lines, `[DONE]` sentinel).

### OpenAI Responses (`/v1/responses`, gpt-5/o1/o3)
- **REDACT (request):** `input` (string or the array of `input_text`/`message` items → their `text`); `instructions`.
- **UN-MASK (response/SSE):** `response.output_text.delta` events (the `.delta` field); function-call argument deltas `response.function_call_arguments.delta`. Non-stream: `output[].content[].text`.
- **NEVER touch:** reasoning items' **`encrypted_content`** (opaque, provider-signed — touching it breaks reasoning continuity), `response.id`, `usage`, item `type`/`role`/`status`, SSE event names.

### Anthropic Messages (`/v1/messages`)
- **REDACT (request):** `system` (string or blocks); every `messages[].content[].text` for `type:"text"`; `tool_result` block `content`; `tool_use` block `input` if it carries user data.
- **UN-MASK (response/SSE):** `content_block_delta.delta.text` (text deltas) and `content_block_delta.delta.partial_json` (tool-input deltas — reassemble per `index`). Non-stream: `content[].text`.
- **NEVER touch:** `anthropic-version` / `anthropic-beta` headers, `message_start`/`message_delta`/`content_block_start` envelope fields, `id`, `usage`, `stop_reason`.

### Cross-cutting
- **Token-split reassembly is mandatory.** A placeholder like `«EMAIL_1»` can arrive as `«EMAIL` + `_1»` across two deltas. Buffer per stream index, un-mask only on complete tokens, and flush any tail at `finish_reason`/`message_stop`/`[DONE]`.
- **Deterministic + content-hash cached** placeholders (per the shared architecture) keep the provider prompt-cache hitting across turns.
- **Auth/identity headers pass through untouched** — only bodies are inspected and rewritten.

---

## 6. Fail-closed gating

The proxy is **default-deny on body inspection**: if it cannot parse-and-redact a request body, or the route isn't actually active, it **blocks** — it never forwards an unredacted body.

**Route-live probe before launch.** The launcher must confirm the proxy is up *and is the redacting proxy* before spawning Copilot:

```sh
scrimward-proxy-wait() {  # returns non-zero unless the redacting proxy answers
  for i in $(seq 1 30); do
    body="$(curl -fsS "http://127.0.0.1:$1/health" 2>/dev/null)" || { sleep 0.2; continue; }
    case "$body" in *'"scrimward"'*|*'"redact":true'*) return 0;; esac
    sleep 0.2
  done
  return 1
}
```

(Headroom uses the same shape — `GET http://127.0.0.1:PORT/health` returning a JSON `config` block. Scrimward's `/health` must additionally assert redaction is **enabled**, not merely that *a* server answered, so a stray plain proxy on the port can't masquerade as protected.)

**Refuse if not live.** If the probe fails, the launcher prints the reason and exits non-zero **without** setting `COPILOT_PROVIDER_BASE_URL` to a dead port — Copilot must never run in a state where it *thinks* it's pointed at the proxy but the proxy isn't redacting.

**Belt-and-braces in the proxy:** on any body it can't fully parse into a known envelope (unknown `provider_type`/path, malformed JSON, an SSE shape it doesn't recognize), respond `4xx` to Copilot rather than proxying. A refused request is a safe request.

**Subscription extra-gate:** if subscription token resolution fails (no `tid_` token resolvable), **refuse to launch** — do not silently fall back to a path that contacts GitHub directly. Also set `COPILOT_OFFLINE=true` where possible so the CLI's own GitHub/telemetry calls don't egress around the proxy.

---

## 7. Caveats & path to ✅ (and the ⛔ corner)

**To call the CLI fully supported (✅), concretely handle:**
1. **The subscription auth module** (§4.2): OS-keychain/libsecret/Credential-Manager discovery + `tid_` detection + `copilot_internal/v2/token` exchange + ~60s-buffer refresh + device-login bootstrap. Port Headroom's `copilot_auth.py` shape; it is the reference implementation and is already cross-platform (macOS verified; Linux/Windows discovery "expected", needs field-confirmation of the exact secret-store schema on each OS).
2. **Point the proxy upstream back at `api.githubcopilot.com`** (and honor `GITHUB_COPILOT_API_URL` for enterprise/data-residency), *not* the segmented per-account host (#610).
3. **Responses-API routing** for gpt-5/o1/o3 — confirm the wire-API/path split against a live subscription request rather than trusting the name heuristic.
4. **Tool-call argument reassembly + un-masking** across split deltas in all three envelopes.
5. **`GET /v1/models`** answered by the proxy (needed by both the CLI's discovery and the VS Code OpenAI-Compatible provider's dropdown probe).

Once 1–5 are in and a canary test (§8) passes on macOS **and** at least one of Linux/Windows, the **CLI** (BYOK + subscription) is ✅. BYOK alone is ✅ **today**.

**Honest reality — the IDE subscription path (⛔ via override):**
- For Copilot's **own subscription models in VS Code**, there is **no honored base-URL override** (`debug.overrideCapiUrl` ignored, microsoft/vscode-copilot-release#7802). The request is assembled in the extension and sent to GitHub CAPI; a *clean* local proxy can't sit in that path.
- What *partially* helps: transparent **HTTPS MITM** (`HTTPS_PROXY` + a locally-trusted CA via `NODE_EXTRA_CA_CERTS`) can intercept that TLS, but it's brittle (breaks on cert-pinning/updates, taints the whole machine's trust store, and is hostile to the fail-closed model). Scrimward does **not** ship this as a supported path.
- **Use a supported path instead:** for IDE work, configure VS Code's **"OpenAI Compatible" BYOK** provider pointed at the Scrimward proxy (then it's the ⚠️→✅ BYOK story, same as the CLI). For agentic/CLI work, use **`scrimward wrap copilot`** (CLI). If you must use the GitHub-subscription models specifically and only inside the IDE, Scrimward **cannot** protect that content — say so plainly rather than imply coverage.

---

## 8. Test plan — canary-secret leak test

Goal: prove the real secret is **absent** from egress, the **placeholder is present** in egress, and the reply is **un-masked locally**. Run per surface that claims support (CLI BYOK; CLI subscription).

1. **Plant** a high-entropy canary that the detectors must catch, e.g. a fake AWS key:
   `CANARY="AKIA$(head -c 24 /dev/urandom | base64 | tr -dc A-Z0-9 | head -c 16)"`
   (Or a synthetic email / Anthropic `sk-ant-…` shaped token — pick one each detector owns.)
2. **Capture egress** at the proxy's upstream boundary. Easiest: point the proxy's *upstream* at a local echo/recorder (`mitmdump -w egress.flows` or a tiny HTTP sink) for the test, OR add a proxy debug mode that tees the exact outbound body to `egress.jsonl`. Capture the wire body **after** redaction, **before** the provider.
3. **Drive a request** through the launcher:
   `scrimward wrap copilot -- --model gpt-4o -p "Echo this verbatim and explain: $CANARY"`
4. **Assertions:**
   - **ABSENT:** `! grep -qF "$CANARY" egress.jsonl` — the raw canary must **never** appear in any outbound body. (Hard-fail the test if it does.)
   - **PRESENT (placeholder):** `grep -qE '«[A-Z_]+_[0-9]+»' egress.jsonl` — a stable typed token (e.g. `«AWS_KEY_1»`/`«EMAIL_1»`) replaced it.
   - **UN-MASKED locally:** the terminal/answer the user sees contains the **real** `$CANARY` again (vault restored it) — assert the captured local reply matches `$CANARY`, confirming reversibility round-trips even across split SSE deltas.
   - **Determinism/cache:** run twice; the same canary maps to the **same** placeholder both times (content-hash cache holds).
5. **Negative/fail-closed:** kill the proxy and re-run the launcher → it must **refuse** (non-zero exit, no GitHub contact), and `egress.jsonl` must gain **zero** new bytes.
6. **Subscription extra:** with a real Copilot seat, confirm the token resolved is a `tid_…` (not a forwarded `gho_…`) and that upstream host is `api.githubcopilot.com` (or the pinned enterprise host) — and that the canary assertions above still hold on that path.

A surface is only marked ✅ after assertions 4–5 pass on it.

---

## 9. Citations

**Official docs (verified 2026-06):**
- GitHub Docs — *Using your own LLM models in GitHub Copilot CLI* (env vars `COPILOT_PROVIDER_BASE_URL`, `COPILOT_PROVIDER_TYPE` ∈ {openai, azure, anthropic}, `COPILOT_PROVIDER_API_KEY`, `COPILOT_MODEL`, `COPILOT_OFFLINE`): https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models
- GitHub Changelog — *Copilot CLI now supports BYOK and local models* (added 2026-04-07): https://github.blog/changelog/2026-04-07-copilot-cli-now-supports-byok-and-local-models/
- GitHub Docs — *Authenticating GitHub Copilot CLI*: https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli
- DeepWiki — *github/copilot-cli — Environment Variables* (incl. `COPILOT_OFFLINE`): https://deepwiki.com/github/copilot-cli/5.2-environment-variables
- VS Code Docs — *AI language models in VS Code* (OpenAI-Compatible custom endpoint, *Chat: Manage Language Models*, `GET /models` probe, `/v1` requirement): https://code.visualstudio.com/docs/agent-customization/language-models
- VS Code Blog — *Expanding Model Choice in VS Code with Bring Your Own Key* (2025-10-22): https://code.visualstudio.com/blogs/2025/10/22/bring-your-own-key
- microsoft/vscode-copilot-release#7802 — `debug.overrideCapiUrl` ignored (IDE subscription path not overridable): https://github.com/microsoft/vscode-copilot-release/issues/7518 (related custom-endpoint request) and #7802 (override-ignored).

**Headroom reference (cloned at `/tmp/headroom-ref`) — real working launchers/auth:**
- `headroom/copilot_auth.py` — OAuth discovery, `tid_` classification, `copilot_internal/v2/token` exchange, 60s refresh buffer, device-code flow, host policy (#610). Constants: `DEFAULT_API_URL`, `DEFAULT_TOKEN_EXCHANGE_URL`, `COPILOT_CHAT_OAUTH_CLIENT_ID`.
- `headroom/copilot_macos_keychain.py` — `security find-generic-password -s copilot-cli -w` and fallbacks.
- `headroom/copilot_linux_secret.py` — `secret-tool lookup service copilot-cli` and fallbacks.
- `headroom/providers/copilot/wrap.py` — `build_launch_env` (`/v1` for openai, bare for anthropic), `--model auto` stripping, responses-API model heuristic.
- `headroom/cli/wrap.py` — `--subscription` launch flow (`COPILOT_PROVIDER_BEARER_TOKEN`, `GITHUB_COPILOT_USE_TOKEN_EXCHANGE=false`, pin `GITHUB_COPILOT_API_TOKEN`/`GITHUB_COPILOT_API_URL` on the proxy).
- `TESTING-copilot-subscription.md` — cross-platform discovery status (macOS verified; Linux/Windows schema needs confirmation), enterprise host pinning via `GITHUB_COPILOT_API_URL`.

**Scrimward internal:**
- `../../README.md`, `../SUPPORTED-TOOLS.md` (Copilot row), `../LEARNINGS-headroom.md`, `../VERIFICATION.md`.

> **Unverified / flagged:** (a) exact per-`provider_type` endpoint *paths* are inferred from each provider's standard wire format + Headroom's base-URL construction, not stated in GitHub's BYOK docs; (b) the `responses` wire-API selection for gpt-5/o1/o3 is a Headroom name-heuristic, not GitHub-official; (c) Linux/Windows secret-store discovery is "expected" in Headroom but not yet field-verified on those OSes; (d) the VS Code BYOK settings storage key was Insiders-gated through May 2026 — re-confirm before automating any IDE-side file write.
