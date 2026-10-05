---
title: "halo onboard company"
description: "My company: generate the policy repo, Helm values, IdP client and enrollment config from interview answers"
---

My company: generate the policy repo, Helm values, IdP client and enrollment config from interview answers

Writes (with --apply) into an empty --policy-dir: halos.yaml, .halos/helm-values.yaml,
.halos/oidc-client.yaml, .halos/enroll/* per delivery channel, a validate+plan CI workflow, a smoke eval
and a README of the human steps. Nothing is secret, published, enrolled or pushed.

## Usage

```console
halo onboard company [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--admin-group` |  | stringSlice | [] | IdP group of platform admins (ring0 and portal admins), repeatable |
| `--apply` |  | bool | false | write the files (default: dry run) |
| `--auth-helper` |  | string |  | command each laptop runs to print a short-lived gateway token (optional) |
| `--client-id` |  | string | halos | OIDC client id |
| `--delivery` |  | stringSlice | [halod] | devcontainer \| mdm \| halod, comma-separated |
| `--gateway` |  | string |  | https URL the CLIs call (required) |
| `--gateway-kind` |  | string | halo-proxy | halo-proxy \| kong \| external |
| `--halo-version` |  | string | dev | halo version CI installs |
| `--issuer` |  | string |  | OIDC issuer URL of your IdP (required) |
| `--model` |  | stringArray | [] | model alias=provider model id, repeatable |
| `--org` |  | string |  | organization name (required) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--policy-repo` |  | string |  | git URL of this policy repo, for Helm git-sync (required) |
| `--portal-url` |  | string |  | https URL halo-server will serve the console on (required) |
| `--project` |  | string |  | Google Cloud project (provider vertex) |
| `--provider` |  | string | anthropic | anthropic \| bedrock \| vertex \| openai \| gemini \| multi |
| `--registry` |  | string |  | OCI repository releases are published to (required) |
| `--rollout` |  | string | standard | fast \| standard \| careful |
| `--safety` |  | string | standard | strict \| standard \| relaxed |
| `--tools` |  | stringSlice | [claude-code@2.1.280] | harnesses as name@version |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Examples

```console
halo onboard company --policy-dir acme-halos --org acme --tools claude-code@2.1.280,codex@0.99.0 \
    --provider bedrock --gateway https://ai.acme.com --gateway-kind halo-proxy --issuer https://login.acme.com \
    --admin-group ai-platform --delivery halod,devcontainer --registry ghcr.io/acme/halos-releases \
    --policy-repo https://github.com/acme/halos-policy.git --portal-url https://halos.acme.com
```

## Parent

[`halo onboard`](/halos/reference/cli/onboard/)
