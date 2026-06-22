---
name: status
description: Show whether Redactly is protecting this session (proxy healthy + this project routed).
---

# Redactly status

Run:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactly-py" status
```

Report the result plainly: is the proxy healthy, is this project routed through it, and how many
custom redaction rules are loaded. If it is **not** routed, tell the user to run `/redactly:setup`
and restart their tool.
