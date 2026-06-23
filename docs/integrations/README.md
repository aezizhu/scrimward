# Tool integrations

Build-ready, per-tool integration specs for Scrimward. Each covers: the **launcher** (exact
env/config to route the tool through the local proxy), **auth handling** per mode, the
**provider body adapter** (what to redact, what to un-mask, what to *never* touch),
**fail-closed gating**, and a **canary leak test**.

| Tool | Status | Spec |
|---|---|---|
| **Claude Code** (Anthropic) | ✅ supported | core path — `ANTHROPIC_BASE_URL` + `.claude/settings.local.json` ([SUPPORTED-TOOLS](../SUPPORTED-TOOLS.md), [VERIFICATION](../VERIFICATION.md)) |
| **Aider** (CLI) | ✅ supported | `OPENAI_API_BASE` / `ANTHROPIC_BASE_URL` via LiteLLM ([SUPPORTED-TOOLS](../SUPPORTED-TOOLS.md)) |
| **Cline** (VS Code) | ✅ supported | "OpenAI-Compatible"/"Anthropic" provider Base URL ([SUPPORTED-TOOLS](../SUPPORTED-TOOLS.md)) |
| **Codex CLI** (OpenAI) | ⚠️ partial → path to ✅ | [codex-cli.md](codex-cli.md) |
| **Gemini CLI** (Google) | ⚠️ partial → path to ✅ | [gemini-cli.md](gemini-cli.md) |
| **GitHub Copilot** | ⚠️ partial → path to ✅ | [github-copilot.md](github-copilot.md) |
| **Cursor** | ⛔ not protectable | [cursor.md](cursor.md) |
| **Windsurf** (Codeium/Devin) | ⛔ not protectable | [windsurf.md](windsurf.md) |

**The ✅ tools** have a clean local base-URL hook and are documented in
[SUPPORTED-TOOLS.md](../SUPPORTED-TOOLS.md); dedicated specs can be added as the launcher code lands.
**The ⚠️ tools** each have a full spec with the exact caveats to clear to reach ✅.
**The ⛔ tools** route your content through their *own* vendor backend before any provider call —
so a local proxy can never see it first. Their specs explain why plainly and point to a supported
tool instead. We don't fake coverage.

> Status: design specs, grounded in current (2026) per-tool research + the Headroom prior art.
> Items flagged "needs empirical testing" in each spec must be confirmed against a live run before
> a tool's status is upgraded.
