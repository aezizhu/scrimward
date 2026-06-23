# Scrimward Integration — Windsurf (Codeium / Devin Desktop)

![status](https://img.shields.io/badge/status-%E2%9B%94%20not%20protectable-red)

> **⛔ NOT PROTECTABLE.** A local redaction proxy cannot protect Windsurf. There is no theater here — read §2.

---

## 1. Title + status

**Tool:** Windsurf — the AI-native IDE formerly known as Codeium, **rebranded to "Devin Desktop" on 2026-06-02** by Cognition (Cognition acquired Windsurf's IP, product, and trademark on 2025-07-14). The in-editor agent is **Cascade**; the post-rebrand local agent is branded **"Devin Local"** and cloud agents run as **"Devin Cloud."** Completions + Cascade are the surfaces a user would want protected.

**Status:** ⛔ **Not protectable by Scrimward.** The retention point is the vendor's own backend, which a `127.0.0.1` proxy structurally cannot sit in front of.

---

## 2. TL;DR verdict (honest)

Windsurf's client (both inline completions and the Cascade agent) speaks **Cognition/Codeium's own proprietary protocol to their backend** (`server.codeium.com` / `*.windsurf.com` / `devin.ai`). Context gathering, prompt assembly, and the actual model-provider call all happen **server-side**, so the complete outbound payload never passes through your machine in a provider-shaped request a local proxy could redact. **Even BYOK does not help:** your "own" Anthropic key is pasted into Windsurf's settings, stored on your **Codeium/Cognition cloud account**, and used **server-side** — your key, but *their* backend makes the call. Scrimward **cannot** protect this; the only privacy levers are vendor-side (enterprise/self-hosted Codeium, account privacy settings). Use a **supported** tool instead (see §7).

---

## 3. Launcher — env vars / config to route through `127.0.0.1:PORT`

**N/A — there is no client-side base-URL route to point at the proxy.** This section exists for template consistency; for Windsurf it is empty *by fact, not by omission*.

What we verified (and why each candidate fails):

| Candidate "hook" a reader might try | What it actually is | Why it can't route to Scrimward |
|---|---|---|
| A model **base-URL / endpoint override** (the lever Scrimward uses for Claude Code, Aider, Cline) | **Does not exist** as a first-party setting. The model call is issued from Codeium's backend, not the client. | Nothing to set; the client never makes the provider request. |
| **BYOK** "API Key Settings → Anthropic → paste key" | Account-stored credential, **synced to your Codeium/Cognition cloud account** | The key is *used server-side*. Pasting it does not move the request onto your machine. See §4. |
| **`Http: Proxy` / "Detect proxy"** (Settings → search "proxy") | A **corporate forward/transit proxy** for reaching Codeium through a firewall | It *tunnels TLS through* to Codeium — it cannot **redirect** traffic to an endpoint you control, and it cannot **decrypt** the Codeium-protocol body. |
| **Cascade → "Add custom server" / `serverUrl`** | An **MCP (SSE) server** registration | This adds tools to the agent; it is **not** a model-endpoint override and never carries the prompt body. |

There is no idempotent "write env var / restore on exit" recipe to give, because there is no variable that relocates the model request to `127.0.0.1`. (Contrast: Scrimward's supported tools set `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, etc.; Windsurf exposes no equivalent. The Headroom prior-art repo ships `wrap` launchers for claude/codex/aider/copilot/continue/goose/openhands/vibe and **instructions-only** for Cursor — and **none at all** for Windsurf, which is structural corroboration.)

**Per-OS note:** identical on macOS / Linux / Windows — the absence of an override is a property of the product, not the platform.

---

## 4. Auth handling

**N/A for interception** — but worth stating precisely, because the auth model is exactly *why* this is unprotectable.

- **Subscription / Pro / managed login:** the client authenticates to Codeium/Cognition; the **vendor backend** holds the provider relationship and makes the model call. No provider token ever transits your machine for Scrimward to forward verbatim.
- **BYOK (Anthropic only):** you paste an Anthropic API key into Windsurf's **API Key Settings**; it is stored under **account-based syncing** (model settings, history, **and the key** sync to your Codeium/Cognition account). The key is then used **server-side** to call Anthropic. BYOK is offered on Free/Pro **individual** plans only — **not** Teams/Enterprise. There is no auth header that Scrimward could forward verbatim, because the authenticated provider call originates in the cloud, not the client.

"What breaks / how to avoid it": nothing to avoid — there is no auth path Scrimward can attach to.

---

## 5. Provider body adapter — fields to redact / un-mask

**N/A — no body is available to adapt.** Scrimward's adapters (Anthropic Messages, OpenAI Chat/Responses, Gemini) presuppose the client emits a provider-shaped JSON request that passes through the proxy. Windsurf emits **Codeium's proprietary protocol** to Codeium's backend; the provider-shaped request is constructed *after* that, on the server. There are:

- **No outbound REQUEST fields** we can enumerate to redact (the payload is the vendor protocol, not Anthropic/OpenAI/Gemini JSON, and it does not reach `127.0.0.1`).
- **No RESPONSE/SSE event or delta names** to un-mask (the stream is the vendor protocol; token-split reassembly is moot).
- **Nothing to "never touch,"** because nothing is in our path.

Inventing field names here would be fabrication. We do not.

---

## 6. Fail-closed gating

The fail-closed posture for Windsurf is **the verdict itself**: Scrimward **refuses to claim** any protection, because the route can never be made live.

A diagnostic probe a user can run to *confirm there is no route* (i.e., to confirm fail-closed honesty rather than to enable forwarding):

1. Start the Scrimward proxy on `127.0.0.1:PORT`.
2. Drive a Cascade prompt or a completion in Windsurf.
3. Inspect the proxy's request log. **Expected result: zero requests arrive.** Windsurf's traffic goes straight to `server.codeium.com` / `*.windsurf.com`, never to `127.0.0.1`.

Because nothing arrives, there is no body to "default-deny inspect" and no unredacted payload Scrimward could accidentally forward — Scrimward is fail-closed here by being **entirely out of the path**. The correct operator-facing state is a hard ⛔ in the tool matrix, never a green "protected."

---

## 7. Honest reality & alternatives

**Why a local proxy cannot protect Windsurf.** The retention point is **Cognition/Codeium's backend**. Your prompt, the files Cascade reads, and your pasted context are sent to that backend, where the prompt is assembled and the provider call is made. A proxy on `127.0.0.1` can only protect a request that *originates on your machine in a redactable shape*; Windsurf's does not. This is the same class as Cursor — **vendor-backend tools** — and it is unchanged by the Devin Desktop rebrand. ("Devin **Local**" is a branding for the local *agent UI*; it is **not** local inference — the model call still routes to Cognition's backend.)

**What (if anything) partially helps — and its limits.**

- **Vendor-side levers only:** Windsurf/Codeium's **enterprise / self-hosted** offering and account **privacy/zero-retention settings** are the *only* places to reduce retention — and they are the **vendor's** controls, not Scrimward's. We name them honestly; we do not implement or vouch for them.
- **Third-party reverse-proxy hacks** (e.g. community "Windsurf custom server" / OpenAI-compatible relay guides) exist that **intercept Windsurf's own proprietary protocol** to swap the upstream. These are **not** a Scrimward path: they require a proxy that speaks Windsurf's vendor protocol (not a provider-shaped body to redact), are fragile across client updates, and are **unsupported** by Scrimward and the vendor. They do **not** change the ⛔ verdict.

**Use a SUPPORTED tool instead** (from Scrimward's matrix):

- **Cline (VS Code) — closest like-for-like.** An IDE agent whose **provider Base URL** can be pointed at the Scrimward proxy (use the "Anthropic" / "OpenAI Compatible" provider, **not** the bundled "Cline" account provider). This gives you an in-editor agent that *is* interceptable.
- **Claude Code (CLI) — fully supported.** `ANTHROPIC_BASE_URL` + project settings; subscription (OAuth) works.
- **Aider (CLI) — fully supported.** `OPENAI_API_BASE` / `ANTHROPIC_BASE_URL` via LiteLLM; BYO key, 100% interceptable.

---

## 8. Test plan — canary test (inverted: proves NON-protectability)

For Windsurf you **cannot** write a passing redaction test, so the honest canary test **proves the leak is unprotectable** — that is the deliverable.

**Setup.** Plant a high-entropy canary secret (e.g. `SCRIMWARD_CANARY_a3f9e1c2b7d84f60`) in an open file / a Cascade prompt.

**Capture egress at the network layer** (not at the proxy, since nothing reaches it): macOS **Little Snitch** or **mitmproxy** (or `tcpdump` for destination-only), or Linux `mitmproxy`/`ss`.

**Assertions (all must hold for ⛔):**
1. **Destination is the vendor TLS endpoint** — `server.codeium.com` / `*.windsurf.com` / `devin.ai` — with **no `127.0.0.1` hop** anywhere in the path.
2. **No config exists that redirects the model call** to a local endpoint (re-run after trying every §3 candidate; the destination is unchanged).
3. **The body is opaque** — you cannot even decrypt the vendor-protocol payload to confirm the canary's presence locally. *That opacity is itself the proof:* if you cannot read it, you cannot redact it, and a local proxy is structurally excluded.
4. (Contrast control) Run the *same* canary through a **supported** tool (Cline / Claude Code) pointed at the Scrimward proxy and assert the proxy received a request, the canary is **ABSENT** from egress, the placeholder (`«SECRET_1»`) is **PRESENT** on the wire, and the reply is **un-masked locally**. This passing case is the standard Scrimward canary; juxtaposing it makes Windsurf's failure unambiguous.

**Expected outcome:** assertions 1–3 confirm Windsurf is ⛔; assertion 4 confirms the *supported* substitute is ✅. Do **not** report a passing redaction result for Windsurf — there isn't one.

---

## 9. Citations

**Official / first-party (load-bearing claims):**
- Windsurf (Devin) changelog — BYOK, rebrand, account-synced settings: <https://windsurf.com/changelog>
- Windsurf proxy configuration (Http:Proxy / Detect proxy = corporate forward proxy): <https://docs.windsurf.com/troubleshooting/windsurf-proxy-configuration>
- Windsurf docs (Cascade, custom MCP/SSE servers, `serverUrl`): <https://docs.windsurf.com/>

**Rebrand / acquisition (2026, verified):**
- "Windsurf Is Now Devin Desktop" (June 2026 rebrand, Agent Command Center, Devin Local): <https://www.digitalapplied.com/blog/windsurf-becomes-devin-desktop-ide-migration-2026>
- Rebrand + ACP / default surface analysis (2026-06-02): <https://aicoderscope.com/blog/windsurf-devin-desktop-rebrand-acp-2026/>

**BYOK stored cloud-side / used server-side (verified):**
- "How to Use Anthropic's Opus & Sonnet-4 in Windsurf with Your Own API Key" (paste key into settings; account-based syncing; Free/Pro individual only): <https://dev.to/hanselcarter/how-to-use-anthropics-opus-sonnet-4-in-windsurf-with-your-own-api-key-22kp>

**Third-party reverse-proxy hack (named per §7, does not change verdict):**
- Windsurf custom-configuration relay guide: <https://codedocs.xxworld.org/en/clients/windsurf>

**Headroom prior-art (structural corroboration — no Windsurf launcher exists):**
- `/tmp/headroom-ref/headroom/cli/wrap.py` — `wrap` supports claude / copilot / codex / aider / vibe / **cursor (instructions-only)** / openclaw; **no `windsurf`/`codeium` target**.
- `/tmp/headroom-ref/headroom/providers/` — provider wrappers exist for copilot, openclaw, etc.; **none for Windsurf/Codeium**.

**Scrimward internal (matrix + class precedent):**
- `/Users/aezi/Desktop/scrimward/docs/SUPPORTED-TOOLS.md` §"⛔ Not protectable" (Cursor + Windsurf, same vendor-backend class).
- `/Users/aezi/Desktop/scrimward/README.md` (architecture; ⛔ tier definition).

---

> *Verified against current (2026) official docs + the Headroom reference repo. Where a fact could not be confirmed first-party, it is marked rather than invented. The verdict rests on **no first-party client-side base-URL override existing** as of the 2026-06 Devin Desktop release — re-check on any future release that claims a local-inference path.*
