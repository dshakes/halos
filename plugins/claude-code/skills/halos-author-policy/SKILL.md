---
name: halos-author-policy
description: Write or modify Halos profiles, rings and experiments in a policy repo. Use for any edit to policy YAML; always validates.
---

# Author Halos policy

1. Read the existing files first (resources `halos://policy/<path>`) and the schema (`halos://schema/profile|experiment|gateway`). Match the repo's style; profiles use `extends:` rather than copy-paste.
2. Make the smallest edit. Rings point at releases; do not hand-edit a ring's release pointer, that is what a promotion PR is for.
3. Call `validate`. Repeat until `ok` is true. Never report an edit as done without a passing `validate`.
4. Call `render_preview` for each affected ring and OS and read the output. Check: no `bypassPermissions` / `danger-full-access`, model allowlists as intended, MCP allowlist intact. Adapters warn rather than drop unsupported settings; surface every warning to the human.
5. If a ring's release changes, call `plan` and show the diff.
6. Show the final diff. Do not commit, publish, or merge unless the human asks.
