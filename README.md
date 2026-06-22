<div align="center">

# 🛡️ Redactly

### Mask your secrets **before** they ever leave your machine for the cloud.

*A local, fail‑closed redaction proxy for AI coding tools — [Claude Code](https://claude.com/claude-code), Codex, Aider, Cline, and more. It intercepts every request on its way out, strips the PII and secrets you care about (text **and** images), and only then lets it reach the cloud. Real values never leave your laptop.*

[![status](https://img.shields.io/badge/status-early%20development-orange)](#-status)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-cross--platform-black)](#-requirements)
[![for](https://img.shields.io/badge/built%20for-AI%20coding%20tools-6E56CF)](#supported-tools)

</div>

---

> ### ⚠️ Status
> **Design and feasibility are verified; implementation is in progress.** Do **not** yet rely on
> `redactly` to protect real secrets. This README describes the intended behavior and the
> architecture it is being built to. See [`docs/SUPPORTED-TOOLS.md`](docs/SUPPORTED-TOOLS.md) for
> what's possible per tool, and [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for the Claude Code
> deep-dive — verified against the official docs, not assumed.

---

## The problem

When you use an AI coding agent, **everything flows to the cloud**: the prompts you type, the files
it reads, the output of every command it runs, and the screenshots you paste. That's how it works —
and most of the time it's fine. But sometimes that stream carries things you'd rather a third party
never see: API keys, customer emails, internal hostnames, a name on a screenshot, a token in a log.

You shouldn't have to choose between *"use the agent"* and *"keep this private."*

## The idea

`redactly` puts a tiny **redaction proxy on your own machine**, between your AI coding tool and the
cloud. Nothing reaches the provider until it has passed through the masker:

```
  You ─ prompt / paste / file / image ─▶ your AI coding tool (Claude Code · Codex · Aider · …)
                                                 │   <tool>'s base-URL → 127.0.0.1
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │         redactly proxy          │  ← only ever on your machine
                                 │   • detect secrets & PII        │
                                 │   • mask text   →  «EMAIL_1»    │
                                 │   • blur image regions (faces,  │
                                 │     text) via Apple Vision      │
                                 │   • FAIL-CLOSED on any doubt    │
                                 └───────────────┬─────────────────┘
                                                 │  redacted request
                                                 ▼
                                         provider API  (cloud)
                                                 │  streamed reply
                                 ┌───────────────▼─────────────────┐
                                 │   local vault un-masks tokens    │  ← real values restored
                                 │   «EMAIL_1»  →  you@example.com   │     for your eyes only
                                 └───────────────┬─────────────────┘
                                                 ▼
                                          Your terminal
```

The clever part is **reversibility**: a secret is swapped for a stable token (`«EMAIL_1»`) before the
wire, and a **local-only vault** swaps it back into the streamed reply — so the model's answer stays
useful and readable, while the real value never left your laptop.

## Why a proxy — and not "just a plugin"?

This is the honest core of the project. We verified it against the current Claude Code docs
([`docs/VERIFICATION.md`](docs/VERIFICATION.md)):

- A hook **cannot rewrite your prompt** — it can only *block* or *append*. So it can't silently mask.
- **No hook ever sees an outbound image.** Pasted/attached images bypass every extension point.
- An **MCP server is structurally blind** to your conversation — it only sees tools it serves.

> **The only layer that sees the *complete* outbound payload — prompt, file contents, and images —
> is the HTTPS request itself.** That is why redaction has to live in a proxy. Anything that claims to
> do it as a pure hook/MCP plugin will *look* installed while silently leaking images and prompts —
> the exact failure mode this project refuses to ship.

`redactly` is therefore packaged as an **installable bundle** (a per-tool launcher + a control surface)
that stands the proxy up and **fails closed** if the route isn't active.

## Features

- 🔒 **Local-first.** The proxy runs only on `127.0.0.1`. Your real data never leaves the machine.
- 🔁 **Reversible.** Stable tokens out, real values restored in the reply via a local vault (mode-switchable to one-way).
- 🧠 **Smart detectors.** Emails, API keys (AWS/GitHub/Slack/Anthropic), JWTs, credit cards (Luhn-checked), IPs, phone numbers — plus your own rules.
- 🖼️ **Image redaction.** Blurs text regions and faces using **Apple Vision** (on-device, no extra installs).
- 🗣️ **Say what to hide.** Add rules in plain language via slash commands — `/redact add …`.
- 🚧 **Fail-closed by design.** If the proxy isn't in the path, the tool refuses rather than leaking.

## Status

| Capability | State |
|---|---|
| Feasibility & threat-model verification | ✅ Done — [`docs/VERIFICATION.md`](docs/VERIFICATION.md) |
| Architecture & spec | ✅ Done |
| Redaction engine (text, reversible vault) | ✅ Done — 8/8 tests |
| Local proxy (streaming, fail-closed) | ✅ Done — 8/8 tests |
| Anthropic + OpenAI-Chat adapters | ✅ Done |
| **Claude Code plugin** (slash commands + fail-closed guard hook) | ✅ Done |
| Image redaction (Apple Vision) | 🔨 Planned |
| OpenAI-Responses / Gemini adapters, more launchers | 🔨 Planned |

### Supported tools

Redactly is **provider-, not vendor-, shaped**: it protects any tool you can point at the local proxy.
The honest matrix below is the credibility core — full per-tool setup detail in
[`docs/SUPPORTED-TOOLS.md`](docs/SUPPORTED-TOOLS.md).

| Tool | Status | How |
|---|---|---|
| **Claude Code** (Anthropic) | ✅ Fully supported | `ANTHROPIC_BASE_URL` + project `.claude/settings.local.json`; subscription (OAuth) works |
| **Aider** (CLI) | ✅ Fully supported | `OPENAI_API_BASE` + `ANTHROPIC_BASE_URL` via LiteLLM — local, BYO key, 100% interceptable |
| **Cline** (VS Code) | ✅ Fully supported | Set the "OpenAI Compatible" / "Anthropic" provider Base URL to the proxy (the default "Cline" account provider is *not* interceptable) |
| **Codex CLI** (OpenAI) | ⚠️ Partial | `OPENAI_BASE_URL` or `~/.codex/config.toml` (global, not project-local); API-key mode clean, ChatGPT-login mode needs a custom `model_provider`. Responses API |
| **Gemini CLI** (Google) | ⚠️ Partial | `GOOGLE_GEMINI_BASE_URL` (API-key) or `CODE_ASSIST_ENDPOINT` (default "Login with Google" OAuth ignores the base-URL var); two request-envelope shapes |
| **GitHub Copilot** | ⚠️ Partial | CLI `COPILOT_PROVIDER_BASE_URL` / VS Code Custom Endpoint. BYOK clean; the paid subscription path needs OS-keychain token discovery + token-exchange; IDE chat path weakest |
| **Cursor** | ⛔ Not protectable | Prompts are assembled on Cursor's cloud and the BYOK base-URL override is dialed server-side — a local proxy can never see the content first |
| **Windsurf** (Codeium / Devin Desktop) | ⛔ Not protectable | Everything routes through Codeium's backend; there is no base-URL hook for the proxy to sit on |

For the ⛔ tier, Redactly **cannot** protect you and we say so plainly: the tool sends your content to
its **own vendor backend before any provider call**, so the retention point is the tool itself —
nothing a local proxy can intercept. We never pretend otherwise.

### How it works across tools

One shared core, reused everywhere: a single **local fail-closed proxy** plus a reversible **session
vault**. Per supported tool, Redactly adds (a) a thin **launcher** that points that tool's base-URL
env/config at `127.0.0.1` and forwards its auth headers verbatim, and (b) a per-**provider** body
**adapter** that knows where the text lives in each request/response shape — Anthropic Messages,
OpenAI Chat Completions, OpenAI Responses (never touching reasoning `encrypted_content`), and Google
Gemini (incl. Cloud Code Assist) — so it redacts the outbound request and un-masks the streamed reply.

## Install & use — as a Claude Code plugin

Redactly installs as a Claude Code plugin that **manages the proxy and fails closed** — it blocks tool
use until your traffic is actually routed through the local redactor, so you can't leak by accident.

```bash
# 1. one-time: get the code + its Python deps (Python 3.12+)
git clone https://github.com/aezizhu/redactly && cd redactly
python3 -m pip install --user fastapi httpx uvicorn click

# 2. inside Claude Code: add the marketplace + install the plugin
/plugin marketplace add ~/redactly          # path to the clone
/plugin install redactly@redactly-marketplace

# 3. turn it on, then RESTART Claude Code
/redactly:setup
```

After restart you're protected. Useful commands:

| Command | What it does |
|---|---|
| `/redactly:setup` | Start the proxy + route this project; then restart your tool |
| `/redactly:status` | Is the proxy up and is this project routed? |
| `/redactly:add <name> <value>` | Add your own thing to always mask (a name, codename, host) |
| `/redactly:list` | List your custom rules |

**How it stays honest:** a `SessionStart` hook starts the proxy and reports status; a `PreToolUse` hook
**denies tool use whenever the session isn't routed** through the proxy (fail-closed) — with a clear
message telling you to run `/redactly:setup` and restart. Built-in detectors (API keys, emails, cards,
JWTs, …) are always on; `/redactly:add` layers your own rules on top.

> Prefer no plugin? The same engine runs standalone: `python -m redactly.cli wrap claude` starts the
> proxy, routes Claude Code, and restores on exit.

## Threat model

**Protects against:** accidental transmission of secrets/PII to the model provider during normal use
of a supported AI coding tool (prompts, tool output, pasted images).

**Does *not* protect against:** a compromised local machine, the model needing the secret to do its
job (if you mask it, the model can't use it), or non-inference telemetry channels — which the setup
disables separately (`DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, …).

This is a guardrail against leaks, not a guarantee against a determined adversary on your box.

## Requirements

- **The proxy and text redaction are cross-platform** — they run wherever your tool does. Cline (VS Code), Codex, Aider, Gemini CLI, Copilot, and Claude Code are all cross-platform.
- At least one **supported tool** (see the table above) you can point at the local proxy.
- **macOS (Apple Silicon) is required only for image redaction**, which uses the native Apple Vision framework on-device. Everything else works on any OS.

## Documentation

- [`docs/SUPPORTED-TOOLS.md`](docs/SUPPORTED-TOOLS.md) — per-tool setup, status, and caveats for all eight tools (cited).
- [`docs/integrations/`](docs/integrations/) — build-ready per-tool integration specs (Codex, Gemini, Copilot, Cursor, Windsurf).
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) — what's actually possible in each supported tool (cited).
- [`docs/LEARNINGS-headroom.md`](docs/LEARNINGS-headroom.md) — patterns & anti-patterns learned from the closest prior art.
- `docs/ARCHITECTURE.md` — components, data flow, and design decisions *(coming with the first code drop)*.

## Contributing

Early days — issues and design discussion are very welcome. If you're poking at the proxy, the one
rule that matters: **never make it fail open.** A redactor that leaks silently is worse than none.

## License

[MIT](LICENSE) © Aezi Zhu
