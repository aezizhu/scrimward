<div align="center">

# 🛡️ claude-redact

### Mask your secrets **before** they ever leave your machine for the cloud.

*A local, fail‑closed redaction proxy for [Claude Code](https://claude.com/claude-code) — it intercepts every request on its way out, strips the PII and secrets you care about (text **and** images), and only then lets it reach the cloud. Real values never leave your laptop.*

[![status](https://img.shields.io/badge/status-early%20development-orange)](#-status)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-macOS-black)](#-requirements)
[![for](https://img.shields.io/badge/built%20for-Claude%20Code-6E56CF)](https://claude.com/claude-code)

</div>

---

> ### ⚠️ Status
> **Design and feasibility are verified; implementation is in progress.** Do **not** yet rely on
> `claude-redact` to protect real secrets. This README describes the intended behavior and the
> architecture it is being built to. See [`docs/VERIFICATION.md`](docs/VERIFICATION.md) for exactly
> what is and isn't possible in current Claude Code — verified against the official docs, not assumed.

---

## The problem

When you use an AI coding agent, **everything flows to the cloud**: the prompts you type, the files
it reads, the output of every command it runs, and the screenshots you paste. That's how it works —
and most of the time it's fine. But sometimes that stream carries things you'd rather a third party
never see: API keys, customer emails, internal hostnames, a name on a screenshot, a token in a log.

You shouldn't have to choose between *"use the agent"* and *"keep this private."*

## The idea

`claude-redact` puts a tiny **redaction proxy on your own machine**, between Claude Code and the
cloud. Nothing reaches the provider until it has passed through the masker:

```
  You ── prompt / paste / file / image ──▶  Claude Code
                                                 │   ANTHROPIC_BASE_URL → 127.0.0.1
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │      claude-redact proxy        │  ← only ever on your machine
                                 │   • detect secrets & PII        │
                                 │   • mask text   →  «EMAIL_1»    │
                                 │   • blur image regions (faces,  │
                                 │     text) via Apple Vision      │
                                 │   • FAIL-CLOSED on any doubt    │
                                 └───────────────┬─────────────────┘
                                                 │  redacted request
                                                 ▼
                                       api.anthropic.com  (cloud)
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

`claude-redact` is therefore packaged as an **installable bundle** (a launcher + Claude Code plugin
for the control surface) that stands the proxy up and **fails closed** if the route isn't active.

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
| Redaction engine (text, reversible vault) | 🔨 In progress |
| Local proxy (streaming, fail-closed) | 🔨 In progress |
| Image redaction (Apple Vision) | 🔨 In progress |
| Claude Code plugin (commands + guard hooks) | 🔨 In progress |

### Coverage by Claude Code auth mode (honest limits)

| Auth mode | Can the proxy protect you? |
|---|---|
| **API key** | ✅ Yes — full text + image redaction |
| **Pro/Max subscription (OAuth)** | ✅ Proven viable — prior art ([Headroom](docs/LEARNINGS-headroom.md)) routes Claude Code OAuth through a local proxy with no API-key billing; pending our own end-to-end test |
| **Vertex** | ✅ Viable via `ANTHROPIC_VERTEX_BASE_URL` (forwards your existing ADC token) |
| **Bedrock** | ⚠️ Redacting the body invalidates AWS SigV4 — needs a re-signing gateway; otherwise **detected & refused**, never faked |

## Threat model

**Protects against:** accidental transmission of secrets/PII to the model provider during normal
Claude Code use (prompts, tool output, pasted images).

**Does *not* protect against:** a compromised local machine, the model needing the secret to do its
job (if you mask it, the model can't use it), or non-inference telemetry channels — which the setup
disables separately (`DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, …).

This is a guardrail against leaks, not a guarantee against a determined adversary on your box.

## Requirements

- macOS (Apple Silicon) — image redaction uses the native Vision framework.
- Claude Code.

## Documentation

- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) — what's actually possible in Claude Code (cited).
- [`docs/LEARNINGS-headroom.md`](docs/LEARNINGS-headroom.md) — patterns & anti-patterns learned from the closest prior art.
- `docs/ARCHITECTURE.md` — components, data flow, and design decisions *(coming with the first code drop)*.

## Contributing

Early days — issues and design discussion are very welcome. If you're poking at the proxy, the one
rule that matters: **never make it fail open.** A redactor that leaks silently is worse than none.

## License

[MIT](LICENSE) © Aezi Zhu
