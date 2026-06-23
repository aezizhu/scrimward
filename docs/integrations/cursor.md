# Scrimward × Cursor — integration spec

![status](https://img.shields.io/badge/status-%E2%9B%94%20NOT%20PROTECTABLE-red)

> **Status: ⛔ NOT PROTECTABLE.** A local fail-closed redaction proxy cannot protect Cursor.
> Cursor assembles your prompt **on its own cloud** before any model-provider call, so there is no
> point in the path where the complete outbound payload passes through your machine first. This
> document is intentionally *not* a "make it work behind a tunnel" recipe — that would leak. It is the
> honest explanation of why the premise is structurally defeated, plus where to go instead.

---

## 1. TL;DR verdict

Cursor routes **every** request through Cursor's servers "for final prompt building" — your prompt,
the open files, and the gathered codebase context are ingested by Cursor's cloud in **cleartext**
before any provider (OpenAI/Anthropic/etc.) is called. The only client-side BYOK lever, *Override
OpenAI Base URL*, is dialed **from Cursor's backend**, requires a **public HTTPS** URL, and only
affects **chat models** — so a `127.0.0.1` Scrimward proxy is structurally unreachable, and even a
public tunnel only sanitizes the **cloud→provider** leg *after* Cursor already retained the raw text.
Worse, turning that BYOK lever on **voids Cursor's Zero-Data-Retention policy** (verified, §4/§7). If
you need real pre-provider redaction, use a **supported** tool — **Claude Code**, **Aider**, or
**Cline** (§7). For Cursor itself, the only privacy lever is **Cursor's own Privacy Mode** (§7).

---

## 2. Why the Scrimward premise is structurally defeated

Scrimward's whole model is: *the tool emits the outbound HTTPS request from your machine; we intercept
it on `127.0.0.1` before it leaves.* That requires the **complete payload to exist client-side** at
some interceptable moment. Cursor breaks this at the root:

```
  SUPPORTED tool (e.g. Claude Code)            CURSOR
  ─────────────────────────────────            ───────────────────────────────────────────
  you ─▶ tool (local)                          you ─▶ Cursor client (local)
          │ builds full request locally                │ ships prompt + files + context
          ▼                                            ▼   IN CLEARTEXT to Cursor's cloud
   127.0.0.1  ← Scrimward intercepts HERE       Cursor CLOUD  ← assembles the final prompt
          │ redacted                                   │      (already has your raw secrets;
          ▼                                            │       this is the retention point)
     provider API (cloud)                              ▼
                                              provider API  ← BYOK base-URL applied HERE,
                                                              server-side, NOT on your machine
```

There is **no client-side moment** where Cursor hands the full assembled request to the local network
stack. The assembly happens after the data has already left for Cursor's cloud. A local proxy can
only sit on `127.0.0.1`; nothing Cursor does ever traverses it.

**Corroboration from the Headroom reference implementation** (`/tmp/headroom-ref`): Headroom ships
real base-URL *wrap launchers* (genuine proxy interception) for `claude`, `codex`, `copilot`,
`aider`, `continue`, `goose`, `openhands`, `vibe` — and has **none** for Cursor. Its only Cursor
touchpoints are (a) `headroom/memory/writers/cursor_writer.py`, a `.cursor/rules/*.mdc` memory writer,
and (b) `headroom/providers/cursor/runtime.py`, whose `render_setup_lines()` merely *prints*
`Base URL: http://127.0.0.1:<port>/…` for the user to paste into "Override OpenAI Base URL".
Headroom is a **token-compression** proxy, where a *partial* hit (chat-only, best-effort) is still a
win and **security is not the goal** — so it tolerates that localhost paste. For Scrimward, a
**fail-closed security** proxy, the identical paste is a silent-leak trap (the route can't actually
carry Cursor's cloud traffic), which is exactly why Cursor is ⛔ here and not ⚠️.

---

## 3. Launcher — **N/A (no usable route), and why**

There is **no Scrimward launcher for Cursor.** Stating the structural reason rather than shipping a
recipe is the deliverable here.

- **No client-side base-URL hook reaches the proxy.** Cursor's only override is *Settings → Models →
  OpenAI API Key → Override OpenAI Base URL*. That value is consumed by **Cursor's backend**, which
  makes the outbound provider call. Cursor's docs require the URL be **publicly accessible and HTTPS**;
  `http://127.0.0.1:PORT` is rejected/unreachable by design (a browser/IDE-class anti-localhost guard).
  So the canonical Scrimward move — `export ANTHROPIC_BASE_URL=http://127.0.0.1:PORT` / a project
  `settings.local.json` — **has no analogue** in Cursor.
- **A public HTTPS tunnel does NOT rescue it (no "tunnel theater").** You *could* expose the proxy via
  `https://<id>.ngrok.io` and Cursor's backend would reach it. But by then **Cursor's cloud has already
  ingested and (absent Privacy Mode) retained your raw prompt + files in cleartext** — the tunnel only
  sanitizes the **Cursor-cloud → provider** leg, which is *after* the leak you care about. It also
  protects only **chat models** (Composer/Apply/Tab are excluded — see below). Scrimward will **not**
  document this as an install path; it provides false assurance.
- **Agent / Composer / Inline-Edit / Apply / Tab have no BYOK at all.** Per Cursor docs, "Custom API
  keys only work with chat models. Tab completion continues using Cursor's built-in models." The agentic
  surfaces are locked to Cursor's own backend/models — there is not even a base-URL knob to misuse.

**Idempotent write / restore-on-exit:** not applicable — there is nothing to set or unset. (For
contrast, a *supported* tool's launcher writes one scoped key, e.g. project
`.claude/settings.local.json`, and restores it on exit. Cursor exposes no such file-or-env surface to
the redaction path.)

**Per-OS notes:** identical on macOS / Linux / Windows — the blocker is architectural (server-side
prompt assembly), not OS-specific. The anti-localhost requirement on the override field holds on all
platforms.

---

## 4. Auth handling — **N/A, with the verified gotcha that matters**

Scrimward's auth model is *forward the tool's auth header verbatim* from the local proxy to the
provider. Cursor never presents its auth to anything on your machine, so there is nothing to forward.

- **BYOK (chat models only):** your OpenAI/Anthropic API key is **uploaded to Cursor's backend** —
  Cursor's docs: *"Your API key is sent to our backend with every request because all requests are
  routed through Cursor's servers for final prompt building."* The key is used **server-side**; no
  verbatim-forward interception point exists locally.
- **Cursor subscription auth (Agent/Composer/Tab):** a Cursor session token, used entirely within
  Cursor's cloud. No client-emitted provider request, no header to forward, nothing to redact.
- **⚠️ Verified retention gotcha — the one hook actively makes privacy *worse*:** Cursor's docs state
  *"Cursor's Zero Data Retention policy does not apply when you use your own API keys… Your data
  handling follows the privacy policy of your chosen provider."* So the **only** base-URL lever Cursor
  exposes (BYOK) **disables** the one retention protection Cursor offered. Using the hook trades a
  no-retention path for a retained one — the opposite of Scrimward's goal.

*Scope honesty:* we verified the **ZDR void under BYOK**. We do **not** assert that Privacy Mode and
BYOK are mutually exclusive (unverified) — see §7 / §9.

---

## 5. Provider body adapter — **N/A (zero reachable request fields)**

A body adapter needs a **local request to rewrite**. Cursor emits the provider call from its cloud, so
**no request field is reachable** by the local proxy. For completeness and to make the absence
concrete:

| Adapter concern | Status for Cursor | Reason |
|---|---|---|
| REQUEST fields to redact | **none reachable** | the assembled request is built and sent server-side; it never traverses `127.0.0.1` |
| RESPONSE/SSE fields to un-mask | **none reachable** | the stream is Cursor-cloud → Cursor-client over Cursor's own channel, not a provider SSE you proxy |
| token-split-across-deltas reassembly | **N/A** | no proxied stream exists to reassemble |
| fields to **NEVER** touch | **all of them** | the only safe action is to not be in the path at all |

Contrast (what a supported adapter *would* specify): OpenAI Chat Completions → redact
`messages[].content`, un-mask SSE `choices[].delta.content`; Anthropic Messages → redact `system` +
`messages[].content[].text`, un-mask SSE `content_block_delta.delta.text` with partial-token
reassembly. **None of these apply to Cursor** because there is no local request/stream to attach them
to.

---

## 6. Fail-closed gating — **refuse, do not route**

For ⛔ tools the only correct fail-closed posture is: **do not route Cursor through Scrimward, and tell
the user why.** "Fail-closed" here means *fail to install*, not *forward unredacted*.

- **Refusal (the gate):** `scrimward wrap cursor` (and any auto-detection of Cursor) MUST hard-refuse
  with a plain-language reason and the §7 alternatives — never print a localhost base-URL, never
  emit a tunnel recipe, never report "configured". Exit non-zero.

  ```
  $ scrimward wrap cursor
  ⛔ Cursor cannot be protected by a local redaction proxy.
     Cursor's cloud assembles your prompt before any provider call, so your
     prompt + files are ingested in cleartext before Scrimward could see them.
     → Use a supported tool for real redaction: claude-code | aider | cline
     → For Cursor itself, your only lever is Cursor's own Privacy Mode (see docs).
     Refusing rather than giving you false assurance.   [exit 2]
  ```

- **Anti-theater assertion (negative probe):** if a user manually pasted the proxy URL into Cursor's
  override anyway, Scrimward should **detect Cursor-origin traffic and warn**, not pretend it's covered.
  Two signals: (a) the override requires public HTTPS, so any request arriving at the proxy with a
  Cursor-cloud source IP / `User-Agent` is, by definition, **post-ingestion** — flag it as "already
  leaked upstream, not protected"; (b) the `127.0.0.1` route will simply never receive Cursor traffic,
  so a "live route" probe (the normal supported-tool readiness check: `curl 127.0.0.1:PORT/healthz`
  then a canary round-trip) **cannot be satisfied for Cursor** — which is the gate's whole point.
- **Why this is the honest fail-closed:** for supported tools, fail-closed = block forwarding if the
  body can't be parsed/redacted. For Cursor there is no body to parse on your machine, so the only way
  to "not forward unredacted" is to **not be the path** — i.e. refuse the integration outright.

---

## 7. Honest reality & alternatives

**Why a local proxy cannot protect Cursor (one paragraph):** Cursor is a *cloud-mediated* IDE. Context
gathering and final prompt assembly happen on Cursor's servers; the model-provider call is dispatched
from there too. The single client-exposed override (BYOK base URL) is applied **inside Cursor's
backend**, demands a **public HTTPS** endpoint, and covers **chat models only**. A redaction proxy
lives on `127.0.0.1` and can only intercept requests your machine emits — and your machine never emits
the assembled request. There is no seam to insert redaction before the data is retained by Cursor.

**What (if anything) partially helps — and its hard ceiling:**

- **Cursor Privacy Mode** *(the real lever for Cursor users):* when enabled, Cursor states your
  code/prompts are **not retained or used for training** by Cursor. This is the honest privacy control
  *inside* Cursor. **Ceiling:** it is a *Cursor-policy* guarantee, not local redaction — your cleartext
  still transits Cursor's cloud; you are trusting Cursor's stated handling, and it does nothing for the
  retained copy at the model provider once BYOK is in play.
- **A public HTTPS tunnel on the BYOK chat path** *(do NOT rely on this):* sanitizes only the
  **Cursor-cloud → provider** leg, only for chat models, and **only after** Cursor already ingested
  your raw prompt + files. It is **not** protection for the data you actually care about and Scrimward
  will not ship it. Also note: enabling BYOK **voids Cursor's ZDR** (§4), so this path can be *net
  worse* than just using Cursor's built-in models under Privacy Mode.

**If you need real pre-provider redaction, switch tools (all ✅ supported by Scrimward):**

| Use Cursor for… | Scrimward-supported equivalent | Why it works |
|---|---|---|
| Terminal/agentic coding | **Claude Code** | `ANTHROPIC_BASE_URL` + project `.claude/settings.local.json` → request built locally, intercepted on `127.0.0.1` |
| CLI pair-programming, BYO key, multi-model | **Aider** | `OPENAI_API_BASE` + `ANTHROPIC_BASE_URL` via LiteLLM — 100% local, fully interceptable |
| In-IDE (VS Code) agent | **Cline** | set the *OpenAI Compatible* / *Anthropic* provider **Base URL** field to the proxy (the default "Cline" account provider is NOT interceptable — pick a base-URL provider) |

> **No false hope.** Cursor stays ⛔ until/unless Cursor ships a *client-side*, localhost-reachable
> egress hook that carries the full payload before cloud assembly. Re-evaluate if that changes.

---

## 8. Test plan — canary leak test (INVERTED: prove the leak you can't stop)

For supported tools the canary test asserts the secret is **absent** from egress and the placeholder
is **present**. For a ⛔ tool that assertion is incoherent — there is no redacted egress to inspect.
The honest test instead **demonstrates that Cursor ingests the canary in cleartext**, proving the
proxy is structurally bypassed.

**Setup**
1. Plant a high-entropy canary in an open file in a Cursor workspace, e.g.
   `SCRIMWARD_CANARY_7f3a9c2e1b8d4f60_AKIA_TESTONLY` (not a real credential; unique, greppable).
2. Stand up the Scrimward proxy on `127.0.0.1:PORT` with request logging (the would-be interception
   point).
3. Capture **client→Cursor-cloud** egress at the network layer — `mitmproxy`/Charles with the system
   trust store, or a pcap (`tcpdump -i any -w cursor.pcap host <cursor-cloud-host>`). This is the leg
   that exists *before* any provider call.

**Drive**
4. In Cursor chat/Composer, ask a question that forces the file into context (e.g. "explain the config
   in this file").

**Assertions (the proof)**
5. **Canary is PRESENT in cleartext on the client→Cursor-cloud leg** → confirms Cursor ingested the
   raw secret before any redaction point could exist. *(This is the leak; it is expected and is the
   point of the test.)*
6. **The Scrimward `127.0.0.1:PORT` log is EMPTY** → confirms no Cursor traffic ever reached the proxy
   (structural bypass, not a misconfig).
7. **No placeholder token (`«…_1»`) appears anywhere** → there was no opportunity to mask.

**Pass criterion (inverted):** the test **passes** when it *demonstrates the un-stoppable leak* — canary
in cleartext upstream **AND** zero bytes at the proxy. That is the evidence backing the ⛔ badge.

**Control (positive sanity):** run the identical canary test against **Claude Code** wired through the
same proxy; there the canary must be **ABSENT** on egress and the **placeholder PRESENT**, with the
reply un-masked locally — proving the harness works and isolating Cursor's failure to Cursor's
architecture, not the test rig.

---

## 9. Citations

**Official Cursor docs**
- Cursor — API Keys (verbatim: *"all requests are routed through Cursor's servers for final prompt
  building"*; *"Your API key is sent to our backend with every request…"*; *"Custom API keys only work
  with chat models. Tab completion continues using Cursor's built-in models."*; *"Cursor's Zero Data
  Retention policy does not apply when you use your own API keys."*) — <https://cursor.com/help/models-and-usage/api-keys> (verified 2026-06)
- Cursor — Privacy / Privacy Mode (no-retention / no-training claim for Cursor) —
  <https://cursor.com/privacy> *(Privacy-Mode-vs-BYOK exclusivity NOT verified; see §4/§7)*

**Override base-URL constraints (community-verified)**
- Cursor Community Forum — "Override OpenAI Base URL" requires a **publicly accessible HTTPS** URL;
  localhost not directly usable — <https://forum.cursor.com/t/override-openai-base-url/152006>
- Cursor Community Forum — "The custom override of the OpenAI base URL is unusable" (localhost / agentic
  surfaces excluded) — <https://forum.cursor.com/t/the-custom-override-of-the-openai-base-url-is-unusable/152675>
- `kcolemangt/llm-router` — sets llm-router as Cursor's Base URL; documents that Composer / inline edit
  / autocomplete / apply are **locked to Cursor's backend**, only chat honors the override —
  <https://github.com/kcolemangt/llm-router>

**Headroom reference repo** (`/tmp/headroom-ref`)
- `headroom/cli/wrap.py` — `wrap cursor` is "Pattern-B" (prints config instructions / injects
  `.cursorrules`), **not** a base-URL interception launcher like `wrap claude`/`wrap codex`.
- `headroom/providers/cursor/runtime.py` — `render_setup_lines()` only *prints*
  `Base URL: http://127.0.0.1:<port>/…` for manual paste; comment notes "Cursor cannot send custom
  headers" so project id is encoded as a `/p/<name>` URL prefix (corroborates: no header-forward seam).
- `headroom/memory/writers/cursor_writer.py` — Cursor support is a `.cursor/rules/*.mdc` **memory
  writer**, not a redaction/interception path.
- `tests/test_cli/` — wrap launcher tests exist for claude/codex/copilot/aider/continue/goose/
  openhands/vibe; **no `test_wrap_cursor.py`** (no interception launcher to test).

**Scrimward internal**
- `docs/SUPPORTED-TOOLS.md` — Cursor row: ⛔ not protectable (this doc is the build-ready expansion).
- `README.md` — supported-tools matrix; Cursor ⛔.
- `docs/VERIFICATION.md` — proxy-vs-hook threat model that this verdict rests on.
