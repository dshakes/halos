---
name: pr-review
description: Review a pull request against Acme's engineering checklist before a human reviewer sees it. Use when asked to review a PR, a diff or a branch.
---

# Acme PR review

Review the change in front of you, not the whole repository.

1. Read the diff and the files it touches. Note what the change is for in one sentence.
2. Check it against the checklist below. Cite `path:line` for every finding.
3. Report findings ordered by severity (blocking, should fix, nit). Say plainly when there are none.

## Checklist

- Tests cover the new behaviour and its error paths, and they pass locally.
- Errors are handled and carry enough context to debug from a log line.
- No secrets, tokens or customer data in code, fixtures or logs.
- Public APIs and config keys are documented; breaking changes are called out.
- New dependencies are justified and pinned to an exact version.

Do not approve or merge. A human reviewer owns that decision.
