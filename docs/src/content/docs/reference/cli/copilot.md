---
title: "halo copilot"
description: "AI-assisted policy operations: the model drafts, Halos verifies, a human approves (ADR-0035)"
---

AI-assisted policy operations: the model drafts, Halos verifies, a human approves (ADR-0035)

The model proposes; Halos' validator, plan, impact preview, bypass-token check and internal/stats verify; a human
approves. Nothing is written without --apply, and --apply only commits to a new local branch: pushing, the PR and
merging are human steps. Each model call logs its token counts to stderr; --offline needs no model.

## Usage

```console
halo copilot
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo copilot draft`](/halos/reference/cli/copilot-draft/) | Turn an intent into a verified policy diff (validate, plan, impact); --apply commits it to a local branch |
| [`halo copilot experiment`](/halos/reference/cli/copilot-experiment/) | Design an experiment: arms and metrics proposed, sample size and duration computed by internal/stats |
| [`halo copilot explain`](/halos/reference/cli/copilot-explain/) | Explain a release, a policy diff or an experiment in plain language, citing only Halos outputs |
| [`halo copilot next`](/halos/reference/cli/copilot-next/) | Suggest next steps from experiment verdicts, eval scorecards, ROI and budgets, each with evidence and the command |

## Parent

[`halo`](/halos/reference/cli/)
