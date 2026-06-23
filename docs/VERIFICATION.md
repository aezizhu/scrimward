# Scrimward — capability verification (Claude Code v2.1.185, 2026-06-22)

> **Scope:** this document covers **Claude Code specifically** — its hook/proxy capabilities and the
> auth-mode coverage limits for the Anthropic Messages path. Per-tool interceptability for the other
> supported tools (Codex, Gemini CLI, Copilot) and the not-protectable tier (Cursor, Windsurf) lives
> in [`docs/SUPPORTED-TOOLS.md`](./SUPPORTED-TOOLS.md).

7 doc-grounded agents (citing code.claude.com/docs + changelog). Bottom line: a proxy is
**unavoidable**, and "for all users" has **hard coverage limits** the PR must handle fail-closed.

## Confirmed facts

| # | Question | Verdict | Note |
|---|---|---|---|
| 1 | Hook can **rewrite the typed prompt** before send? | **NO** (high) | `UserPromptSubmit` can only **block** or **append** context — never rewrite. So hooks can't silently redact what the user types. |
| 2 | Hook can rewrite **tool input/output**? | **YES** (high) | `PreToolUse.updatedInput` + `PostToolUse.updatedToolOutput` **do exist** in v2.1.185. ⇒ the ultraplan was RIGHT to use them — real defense-in-depth for Read/Bash/Grep results. |
| 3 | Hook sees **outbound images**? | **NO** (high) | Pasted/@-ref/screenshot images never reach any hook. Proxy-only. |
| 4 | Plugin can **auto-set `ANTHROPIC_BASE_URL`**? | **NO** (high) | settings.json supports only `agent`/`subagentStatusLine`; base URL is read at startup. Plugin can ship the proxy binary + a SessionStart hook, but **can't self-activate** the route. |
| 5 | **MCP** can intercept conversation/images? | **NO** (high) | Structural — MCP only sees args of tools it serves. An MCP "redactor" is a **silent no-op**. |
| 6 | Auth/transport (**the gate**) | **PARTIAL** (med) | see below |
| 7 | Any **non-proxy** path to redact everything? | **NO** (high) | Proxy unavoidable. Prior art: `github.com/ShindouMihou/cc-redact` (Read-hook only, misses @-refs+paste). Native feature request `anthropics/claude-code#29434` **closed: not planned**. |

## The gate (#6) — per auth mode, for "发给所有人"
- **API-key users:** ✅ proxy via `ANTHROPIC_BASE_URL` works; **plaintext `http://127.0.0.1` is supported**. Full text+image redaction achievable.
- **Pro/Max subscription (OAuth):** ⚠️ **UNVERIFIED** whether Claude Code honors `ANTHROPIC_BASE_URL` under subscription login, or silently falls back to `api.anthropic.com`. This is the **most common user** — if it bypasses, the plugin **looks installed but leaks everything**. **The PR MUST empirically test this and fail-closed if the route isn't active.**
- **Bedrock/Vertex users:** ❌ `ANTHROPIC_BASE_URL` **does not apply** — separate `bedrock-runtime` endpoint, SigV4-signed. A proxy can't rewrite the body without holding AWS creds + re-signing, or TLS-MITM. Treat as **unsupported → detect & refuse**, don't pretend.

## New leak channel the ultraplan likely missed
`ANTHROPIC_BASE_URL` covers **only inference traffic**. These bypass the proxy to their own
destinations and **leak metadata** unless disabled:
`DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1` (Sentry), `DISABLE_AUTOUPDATER=1`,
`DISABLE_FEEDBACK_COMMAND=1`, `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1`, `skipWebFetchPreflight:true`.
The launcher/setup must set these (or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`).

## What the PR should guarantee (checklist)
1. **Fail-closed routing:** SessionStart hook verifies `ANTHROPIC_BASE_URL` actually points at the live proxy; if not (or subscription bypasses it, or Bedrock active) → **refuse / loud block**, never silent pass-through. This is the #1 safety item.
2. **Empirically test subscription+base-URL** before claiming subscription support. If unconfirmed, document "API-key mode verified; subscription unverified."
3. **Bedrock/Vertex:** detect (`CLAUDE_CODE_USE_BEDROCK`/`_VERTEX`) and refuse with a clear message.
4. **Disable non-inference channels** (env vars above) or the tool leaks telemetry/errors.
5. **Keep tool-I/O hooks** (`updatedToolOutput`/`updatedInput`) as defense-in-depth — they're real in v2.1.185.
6. **Install isn't drop-in:** needs base-URL wiring + restart (launcher `claude-safe` is cleanest). Don't market as pure `/plugin install`.
7. **Preserve `anthropic-version`/`anthropic-beta` headers** + valid Messages-API body after redaction, or features break.
8. Image redaction (Vision) + reversible vault as designed — those are fine.

**One-line verdict:** the architecture is sound for API-key users; for "everyone" the make-or-break is
(a) does subscription honor the base URL, and (b) Bedrock can't be proxied — both must fail-closed, or
the tool silently leaks for the very users who installed it for privacy.
