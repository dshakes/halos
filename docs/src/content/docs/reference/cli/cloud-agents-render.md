---
title: "halo cloud-agents render"
description: "Render the SHA-pinned, least-privilege workflow files of the repo-configured cloud agents"
---

Render the SHA-pinned, least-privilege workflow files of the repo-configured cloud agents

Renders .github/workflows/halos-claude.yml, halos-gemini.yml and copilot-setup-steps.yml from halos.yaml
cloudAgents, checked against the never-bypass invariant. Without --out it prints them. Commit them to the
repositories cloudAgents.&lt;vendor>.repos names, by pull request. Console-configured vendors are in `halo admin plan`.

## Usage

```console
halo cloud-agents render [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--out` |  | string |  | write the files under this directory (a repository checkout); default: print them |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo cloud-agents`](/halos/reference/cli/cloud-agents/)
