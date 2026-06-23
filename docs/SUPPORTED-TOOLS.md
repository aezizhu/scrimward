# 🧰 Scrimward — supported tools

**Which AI coding tools can Scrimward protect, and exactly how.**

> 🔧 Implementing a tool? **Build-ready per-tool specs** (launcher, auth, body adapter, fail-closed
> gating, canary leak test) live in [`docs/integrations/`](integrations/).

Scrimward is a privacy redaction proxy for AI coding tools *generally* — not Claude Code only.
One local, fail‑closed proxy plus a reversible session vault sits between your tool and the cloud.
For each tool you (a) point that tool's **base‑URL env/config** at the local proxy and forward the
auth headers verbatim, and (b) the proxy uses a per‑**provider** body adapter to redact the outbound
request and un‑mask the streamed response.

> ### ⚠️ Status — early development
> **Design and feasibility are verified; implementation is in progress.** Do **not** yet rely on
> Scrimward to protect real secrets. This document describes the intended interception points and the
> honest limits of each one, grounded in current (2026) per‑tool research.

---

## Why retention is the thing we fight

Providers can **retain inputs (e.g. ~30 days)** for trust‑and‑safety review. Scrimward sanitizes the
copy that leaves your machine, so the **retained copy carries no secrets/PII** — for any *supported*
tool. Where available, an enterprise **Zero‑Data‑Retention** agreement removes retention entirely, but
that's vendor‑ and plan‑gated. Scrimward is the accessible, **you‑control‑it** layer that also works for
subscription users and as defense‑in‑depth. The two compose.

The architecture generalizes because the proxy and vault are **shared across tools** — only the thin
*body adapter* is per‑provider:

| Provider API | Request fields the adapter redacts | Streamed‑response fields it un‑masks |
|---|---|---|
| **Anthropic Messages** (`/v1/messages`) | `system` + `messages[].content[].text` | SSE `content_block_delta.delta.text` |
| **OpenAI Chat Completions** (`/chat/completions`) | `messages[].content` | SSE `choices[].delta.content` |
| **OpenAI Responses** (`/v1/responses`) | `instructions` + `input[]` (message parts + `*_call_output` strings) | SSE `response.output_text.delta` — **NEVER** touch reasoning `encrypted_content` |
| **Google Gemini** | `contents[].parts[].text` (incl. Cloud Code Assist–wrapped `request.contents`) | streamed text un‑masked symmetrically (response path not pinned here — see note) |

---

## Summary matrix

| Tool | Provider API | Status | Base‑URL hook |
|---|---|---|---|
| **Claude Code** | Anthropic Messages | ✅ supported | `ANTHROPIC_BASE_URL` + `.claude/settings.local.json` |
| **Aider** | OpenAI Chat Completions + Anthropic Messages (via LiteLLM) | ✅ supported | `OPENAI_API_BASE` + `ANTHROPIC_BASE_URL` |
| **Cline** (VS Code) | OpenAI Chat Completions *or* Anthropic Messages | ✅ supported | Provider **Base URL** field (manual UI) |
| **Codex CLI** | OpenAI Responses | ⚠️ partial | `OPENAI_BASE_URL` or `~/.codex/config.toml` (global) |
| **Gemini CLI** | Google Gemini | ⚠️ partial | `GOOGLE_GEMINI_BASE_URL` *or* `CODE_ASSIST_ENDPOINT` |
| **GitHub Copilot** | OpenAI‑style Chat Completions (BYOK) | ⚠️ partial | `COPILOT_PROVIDER_BASE_URL` / VS Code Custom Endpoint |
| **Cursor** | — | ⛔ not protectable | none (vendor backend) |
| **Windsurf** (Codeium / Devin Desktop) | — | ⛔ not protectable | none (vendor backend) |

Legend: ✅ **supported** = clean local base‑URL hook, no vendor backend in the path.
⚠️ **partial** = interceptable, with caveats. ⛔ **not protectable** = the tool's own cloud assembles and
sends your content *before* any provider call, so a local proxy can never see it first.

---

## ✅ Fully supported

### Claude Code (Anthropic)

- **Base‑URL mechanism:** set `ANTHROPIC_BASE_URL` to the local proxy (plaintext `http://127.0.0.1` is
  accepted), and pin it per‑project in `.claude/settings.local.json`.
- **Auth modes:** API‑key mode is clean. **Subscription (OAuth)** works — the tool forwards its bearer
  token, which the proxy passes through verbatim to `api.anthropic.com`.
- **Adapter (Anthropic Messages):** redacts `system` and every `messages[].content[].text`; un‑masks the
  streamed `content_block_delta.delta.text`. `anthropic-version` / `anthropic-beta` headers are
  preserved so features don't break.
- **Caveat:** `ANTHROPIC_BASE_URL` covers inference only. Non‑inference channels (telemetry, error
  reporting) bypass the proxy and must be disabled separately.

### Aider (CLI)

- **Base‑URL mechanism:** `OPENAI_API_BASE` and `ANTHROPIC_BASE_URL` both point at the proxy; Aider
  reaches providers through **LiteLLM**, which routes by the selected model.
- **Auth modes:** local, bring‑your‑own‑key — **100% interceptable**.
- **Adapter (dual):** because LiteLLM routes by model, Scrimward engages **two** provider adapters:
  - **OpenAI Chat Completions** for GPT‑family models — redacts `messages[].content`, un‑masks SSE
    `choices[].delta.content`.
  - **Anthropic Messages** for Claude‑family models — redacts `system` + `messages[].content[].text`,
    un‑masks SSE `content_block_delta.delta.text`.
- **Caveat:** make sure the env var matching the *model you actually run* is wired; a Claude model still
  needs `ANTHROPIC_BASE_URL`, a GPT model still needs `OPENAI_API_BASE`.

### Cline (VS Code)

- **Base‑URL mechanism:** in Cline's provider settings, set the **Base URL** field of the
  **"OpenAI Compatible"** or **"Anthropic"** provider to the proxy. This is a **manual UI** step.
- **Auth modes:** BYO API key per provider.
- **Adapter:** **OpenAI Chat Completions** under the "OpenAI Compatible" provider
  (`messages[].content` / SSE `choices[].delta.content`), or **Anthropic Messages** under the
  "Anthropic" provider (`system` + `messages[].content[].text` / SSE `content_block_delta.delta.text`).
- **Caveat:** the default **"Cline" account provider is NOT interceptable** — it routes through Cline's
  own backend and exposes no base‑URL field. You must select an OpenAI‑Compatible or Anthropic provider.

---

## ⚠️ Partial — interceptable, with caveats

### Codex CLI (OpenAI)

- **Base‑URL mechanism:** `OPENAI_BASE_URL`, or a `model_provider` entry in `~/.codex/config.toml`.
  Note this config is **global, not project‑local**.
- **Auth modes:** **API‑key mode is clean.** The **default ChatGPT‑login mode** needs a custom
  `model_provider` with conditional `requires_openai_auth` so the CLI forwards its session auth instead
  of demanding an OpenAI API key.
- **Adapter (OpenAI Responses):** Codex uses the **Responses API**, not Chat Completions. The adapter
  redacts `instructions` and the `input[]` array (message parts **and** `*_call_output` strings) and
  un‑masks SSE `response.output_text.delta`. It **NEVER** touches the reasoning `encrypted_content`
  field — that is opaque, signed by the provider, and rewriting it would break the request.

### Gemini CLI (Google)

- **Base‑URL mechanism:** `GOOGLE_GEMINI_BASE_URL` for API‑key mode; the default **"Login with Google"**
  OAuth path instead uses `CODE_ASSIST_ENDPOINT` and **ignores `GOOGLE_GEMINI_BASE_URL`** entirely.
- **Auth modes:** API‑key (clean redirect) vs. Google OAuth (must override `CODE_ASSIST_ENDPOINT`).
- **Adapter (Google Gemini), two envelope shapes:**
  - Plain Gemini API: redact `contents[].parts[].text`.
  - **Cloud Code Assist** (OAuth path): the same text is wrapped one level deeper as
    `request.contents[].parts[].text` — the adapter must reach into the wrapper.
  The streamed reply is un‑masked symmetrically; we don't pin an exact verified response field path
  here, consistent with our no‑fabrication stance.
- **Caveat:** pick the env var matching your login mode, or the proxy is silently bypassed for the
  OAuth path.

### GitHub Copilot

- **Base‑URL mechanism:** `COPILOT_PROVIDER_BASE_URL` (CLI) or the **Custom Endpoint** setting (VS Code).
- **Auth modes:**
  - **BYOK (bring‑your‑own‑key) is clean** — the request looks like an OpenAI‑compatible Chat
    Completions call and the proxy can forward auth verbatim.
  - The **paid subscription path** is harder: the token lives in the OS keychain and the request needs a
    **token‑exchange** step (not verbatim header forwarding), so the proxy must discover and exchange it.
  - The **IDE chat path is the weakest** — least amenable to a clean base‑URL override.
- **Adapter:** the BYOK path is OpenAI‑style **Chat Completions**, so the Chat Completions adapter
  (`messages[].content` / SSE `choices[].delta.content`) is the natural fit. *We are not publishing
  exact verified field paths for the subscription/IDE envelopes here — they vary and the research does
  not yet pin them; Scrimward will not fabricate a field‑map it hasn't verified.*

---

## ⛔ Not protectable — and why

These tools route through the **vendor's own backend** *before* any provider call. The prompt is
assembled and the request is sent from the vendor's cloud, so a local proxy never sees the content
first. The tool itself is the retention point — Scrimward **cannot** protect these, and we won't pretend
otherwise.

### Cursor

> **Why Scrimward can't protect this.** Cursor assembles your prompt **on Cursor's cloud**, not on your
> machine. Even with "bring your own key", the base‑URL override is dialed **server‑side** — your
> request is built and dispatched from Cursor's backend, where `localhost` (and therefore the Scrimward
> proxy) is simply unreachable. There is no point in the path where the complete outbound payload
> passes through your machine before reaching the model provider.

- **Base‑URL hook:** none usable (the BYOK override is applied in Cursor's cloud).
- **Status:** ⛔ not protectable.

### Windsurf (Codeium / now Devin Desktop)

> **Why Scrimward can't protect this.** Everything goes through **Codeium's backend** — context
> gathering, prompt assembly, and the provider call all happen server‑side. There is **no base‑URL
> hook** to redirect at the client, so the proxy can never intercept the request before it leaves for
> the vendor.

- **Base‑URL hook:** none.
- **Status:** ⛔ not protectable.

---

> 📌 This matrix is grounded in current (2026) per‑tool research and will be kept updated as tools and
> their interception surfaces change.
