---
name: add
description: Add a custom thing to always redact (a name, company, internal hostname, project codename…).
argument-hint: <name> <value>
---

# Add a custom redaction rule

The user wants Redactly to mask a specific value everywhere it appears. Take a short rule NAME and
the VALUE to hide, then run:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactly-py" rules add "<name>" "<value>"
```

- Add `--regex` if the user gave a pattern rather than a literal string.
- Tell them the new rule applies after the proxy reloads (restart it, or restart the tool).
- **Security note:** for a *real* secret, suggest they run that command in their own terminal rather
  than typing the secret into chat — the chat prompt itself would be sent before redaction is set up.
