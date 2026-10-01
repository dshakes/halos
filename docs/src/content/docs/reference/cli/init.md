---
title: "halo init"
description: "Create a policy repo: one simple halos.yaml (--full for the multi-file scaffold)"
---

Create a policy repo: one simple halos.yaml (--full for the multi-file scaffold)

Writes a simple-mode halos.yaml: tools, provider, models, gateway, safety and rollout presets.
Load expands it into the Gateway, Profile and Rings; `halo explain` shows them, `halo eject` writes them out.

## Usage

```console
halo init [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--full` |  | bool | false | write the multi-file scaffold (gateway, profile, rings) instead of simple mode |
| `--gateway` |  | string |  | gateway base URL clients use (default https://ai.&lt;org>.example) |
| `--interactive` | `-i` | bool | false | prompt for each setting |
| `--issuer` |  | string |  | OIDC issuer URL (any IdP) |
| `--model` |  | stringArray | [] | model alias=provider model id, repeatable (default: the provider's current model; tools whose wire the provider cannot serve get an alias named after the tool, e.g. --model codex=gpt-5-codex) |
| `--org` |  | string | my-org | organization name |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--project` |  | string |  | Google Cloud project (provider vertex) |
| `--provider` |  | string | anthropic | anthropic \| bedrock \| vertex \| openai \| gemini \| multi |
| `--rollout` |  | string | standard | rollout preset: fast \| standard \| careful |
| `--safety` |  | string | standard | safety preset: strict \| standard \| relaxed |
| `--tools` |  | stringSlice | [claude-code@2.1.280] | harnesses as name@version (claude-code, codex, gemini-cli, copilot-cli) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Examples

```console
halo init --org acme --tools claude-code@2.1.280,codex@0.99.0 --provider bedrock \
    --model default=claude-sonnet-4-5 --model strong=claude-opus-4-1 --gateway https://ai.acme.com
```

## Parent

[`halo`](/halos/reference/cli/)
