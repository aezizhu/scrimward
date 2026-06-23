# Redaction policy — privacy *without* degrading Claude

## Why this exists
Inputs sent to the model provider can be **retained (e.g. ~30 days)** for trust-and-safety review.
For private code and PII that retention window is unacceptable. Scrimward ensures the copy that
leaves your machine — and therefore any retained copy — **does not contain your secrets**.

> Note: where available, an Anthropic **Zero-Data-Retention** agreement removes retention entirely —
> but that's enterprise/API-only. Client-side redaction is the **accessible, provider- and
> model-agnostic** layer that also works for subscription users and as defense-in-depth. The two
> compose; this tool is the one *you* control.

## The hard constraint: don't make Claude dumber
Naive redaction destroys the context Claude needs and tanks answer quality. Over-redaction — not
under-redaction — is the usual failure. Our entire design is built to avoid it.

## The core principle: redact **values**, preserve **structure**, **restore** on response
Replace only the literal secret with a **typed, stable, reversible token**; keep everything else
byte-faithful; un-mask the reply locally so the deliverable is complete.

A good token carries the three things Claude actually reasons with:

| Property | Token | Why it preserves capability |
|---|---|---|
| **Type** | `«EMAIL_1»`, `«AWS_KEY_1»`, `«PERSON_1»` | Claude still knows *what* it is — can validate format, write code that handles "an email", reason about "a key". |
| **Identity** | same secret → **same** token everywhere, whole session | Claude tracks relationships: "the email in line 3 is the one the test asserts on." |
| **Count** | `_1`, `_2`, `_3` | Claude knows there are *two different* people / *three distinct* keys, not one blob. |

Because the real value returns on the response, **the final output the user sees has zero loss.**
Claude reasoned over a faithful *skeleton*; you get the *filled-in* answer.

## Provider-agnostic by design
This policy describes the **engine**, not any one provider's wire format. The same
detect → tokenize → vault → un-mask logic runs unchanged behind a thin set of **per-provider body
adapters** — Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, and Google Gemini — each of
which knows only *where the text lives* in that provider's request and streamed response. So everything
below applies **identically across every supported tool** (Claude Code, Aider, Cline, Codex CLI,
Gemini CLI, …): the model and the envelope change, the redaction discipline does not.

## What we redact vs. preserve

**Redact (high-confidence; the literal value is rarely the task):**
credentials (API keys, tokens, private keys, passwords, connection strings), emails, phone numbers,
national IDs, credit cards (Luhn-checked), and — by **user rule** — names, internal hostnames/URLs,
company-specific identifiers.

**Never redact (doing so wrecks performance):**
code structure (keywords, function/variable/class names, types, control flow), public API & library
names, the task/instructions themselves, well-known values (`localhost`, `example.com`, common ports),
and anything on the user's **allowlist**.

**The hard middle (handle with care, not blanket rules):**
- **Person names** — the #1 false-positive source. Capitalized-word NER over-fires and shreds context.
  v1: names are **rule-based / opt-in** (you name the people/terms), not blanket detection.
- **Numbers** — most aren't secrets. **Validate** (Luhn, length, checksum) before masking; never mask
  versions, line numbers, sizes, ports.
- **Ambiguous IDs** (UUIDs, paths) — could be a public resource or a session token; default to your rules.

## Precision vs. recall — and how we get both
Privacy wants **recall** (miss nothing); performance wants **precision** (mask nothing extra). We
reconcile structurally, not by guessing:
1. **User-driven rules are precise by construction** — you declare what's sensitive, so we don't
   over-mask things you actually need. ("These things are sensitive" → exactly those.)
2. **Built-in detectors are high-confidence + validated** (Luhn, key prefixes, checksums) to keep
   false positives low.
3. **Allowlist** un-redacts known-safe values that match a pattern but aren't private.
4. **Confidence tiers** (future): high-confidence → mask silently; low-confidence → optionally flag,
   not blanket-mask.
5. **Fail-closed is about transport, not aggression** — if we *can't* process a body we block it; we
   do **not** "mask everything to be safe" (that would be the performance disaster).

## Token format: keep it syntactically safe
- **Prose / chat:** `«EMAIL_1»` (guillemets are rare in real content → reliable to find for un-masking).
- **Inside code / JSON:** prefer a **type-faithful** placeholder that won't break syntax (e.g. a
  valid-looking `user1@redacted.invalid`, a same-length dummy key) so Claude can still edit the file.
  Trade-off: type-faithful tokens are syntactically safe but harder to un-mask unambiguously; the
  engine picks per-context and the **vault** maps either form back. (Design open item, tracked.)

## Latency & prompt-cache (the *other* meaning of "performance")
- **Deterministic + content-hash cached:** the same input always yields the same token, and we scan
  only **new** content blocks each turn (Claude re-sends the whole conversation otherwise). Regex
  detection is microseconds.
- **Prompt caching survives:** because redaction is deterministic, the redacted bytes are **stable
  across turns**, so Anthropic's prompt cache still hits — no cache-busting, no cost/latency
  regression. (Non-determinism would silently break this — so any future LLM/NER pass runs at
  temperature 0 and is cached.)
- **Heavy passes deferred:** local-LLM fuzzy matching and image OCR add latency, so they're optional /
  cached / v2 — v1 is fast regex + your rules.

## Escape hatch: when Claude *needs* the real value
Some tasks require the secret (debug *this* connection string, test *this* key). Provide a per-value
or per-session **bypass/allowlist** so you can deliberately let Claude see it. You stay in control;
the tool never silently hides something you asked it to work on.

## Honest boundaries (non-goals)
- Redaction recall is **not 100%** — a novel secret format can slip; that's why rules + allowlist +
  the leak-detection test rig matter, and why this is defense-in-depth, not a guarantee.
- We protect **content**, not metadata (timing, sizes, which files exist).
- If you mask something Claude truly needs and don't allowlist it, quality drops *for that task* —
  by design you, not us, decide that trade.

## One-line summary
**Mask the value, keep the shape, give it back on the way home** — so the provider's retained copy is
sanitized while Claude still sees a faithful skeleton and you still get a complete answer.
