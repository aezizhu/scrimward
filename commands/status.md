---
name: status
description: Show whether Scrimward is protecting this session (proxy healthy + this project routed).
---

# Scrimward status

Run:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/scrimward-py" status
```

Report the result plainly: is the proxy healthy, is this project routed through it, and how many
custom redaction rules are loaded. If it is **not** routed, tell the user to run `/scrimward:setup`
and restart their tool.
