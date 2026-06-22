---
name: setup
description: Turn on Redactly — start the local redaction proxy and route this project's AI traffic through it.
---

# Turn on Redactly

Run the Redactly setup command with a Bash tool call:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactly-py" setup
```

Then tell the user, in plain language: **restart your AI tool now** (exit and re-run `claude`)
for the routing to take effect. Explain that until routing is active, tool use is blocked
(fail-closed) on purpose — so nothing is ever sent to the cloud un-redacted.
