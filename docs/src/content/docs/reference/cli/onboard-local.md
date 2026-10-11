---
title: "halo onboard local"
description: "My machine: create (or keep) halos.yaml, validate it and plan the managed-config install"
---

My machine: create (or keep) halos.yaml, validate it and plan the managed-config install

Defaults come from this machine: --tools pins every CLI on PATH at its installed version, --provider
is the one whose key is exported, and the gateway is a local halo-proxy on http://127.0.0.1:8088.
An existing halos.yaml is never overwritten. --apply writes halos.yaml only; managed config is
written by `halo onboard install --apply`.

## Usage

```console
halo onboard local [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--apply` |  | bool | false | write halos.yaml (default: dry run) |
| `--gateway` |  | string |  | gateway base URL the CLIs call (default: local halo-proxy http://127.0.0.1:8088) |
| `--gateway-engine` |  | string |  | what serves --gateway: halo-proxy (default) \| kong \| external (your company's own API gateway: CLIs get provider model ids) |
| `--model` |  | stringArray | [] | model alias=provider model id, repeatable |
| `--org` |  | string | local | organization name |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--project` |  | string |  | Google Cloud project (provider vertex) |
| `--provider` |  | string |  | anthropic \| bedrock \| vertex \| openai \| gemini \| multi (default: from the exported key) |
| `--ring` |  | string |  | ring this machine follows (default: the GA ring) |
| `--rollout` |  | string | standard | fast \| standard \| careful |
| `--root` |  | string |  | plan the install under this directory instead of the real paths |
| `--safety` |  | string | standard | strict \| standard \| relaxed |
| `--tools` |  | stringSlice | [] | harnesses as name@version (default: every CLI on PATH at its installed version) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo onboard`](/halos/reference/cli/onboard/)
