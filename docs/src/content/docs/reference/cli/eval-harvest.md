---
title: "halo eval harvest"
description: "Turn shadow steps where the candidate regressed into redacted step-level eval cases (ADR-0020)"
---

Turn shadow steps where the candidate regressed into redacted step-level eval cases (ADR-0020)

Reads the halo-shadow pair store, selects steps (the candidate diverged, made an invalid call, stopped early, lost on judge score, or a stratified sample by depth) and writes one redacted case per step: the real prefix, the offered tools and production's action. Redaction (credentials, JWTs, private keys, high-entropy strings, emails, --redact-pattern; only allowlisted request fields kept) always runs and fails closed. Files are 0600. Replay them with `halo eval steps run`.

## Usage

```console
halo eval harvest [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--allow-plaintext-pairs` |  | bool | false | with --pair-key-file, also read unsealed rows (a store written before sealing was turned on); off: such rows are refused |
| `--dry-run` |  | bool | false | select and redact, print the summary, write nothing |
| `--experiment` |  | string |  | only this experiment |
| `--history` |  | string |  | `halo eval online` history JSONL: judge scores for --select judge-loss |
| `--judge-loss` |  | float64 | 0.2 | judge-loss: control minus candidate score above which a step is selected |
| `--keep-field` |  | stringSlice | [] | extra top-level request field to keep (default allowlist: model, system, messages, tools, input, contents...) |
| `--out` |  | string |  | suite directory to write the cases into (created 0700) |
| `--pair-key-file` |  | stringSlice | [] | base64 32-byte pair key (repeatable: current and retired) |
| `--pairs` |  | string |  | halo-shadow pair store (JSONL) (required) |
| `--per-depth` |  | int | 5 | sample: steps per depth bucket (0, 1-4, 5-19, 20+) |
| `--redact-pattern` |  | stringArray | [] | extra RE2 regex to redact (repeatable) |
| `--seed` |  | uint64 | 1 | sampling seed |
| `--select` |  | stringSlice | [diverged,invalid-call,premature-stop] | why a step becomes a case: diverged, invalid-call, premature-stop, judge-loss, sample |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo eval`](/halos/reference/cli/eval/)
