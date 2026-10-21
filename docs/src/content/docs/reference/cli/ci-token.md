---
title: "halo ci token"
description: "Exchange this job's OIDC token for a short-lived gateway credential and export it for the harnesses"
---

Exchange this job's OIDC token for a short-lived gateway credential and export it for the harnesses

Reads the CI provider's OIDC token (GitHub Actions: requested from
ACTIONS_ID_TOKEN_REQUEST_URL, needs "permissions: id-token: write"; anything
else: the variable named by --token-env, e.g. a GitLab id_tokens entry),
exchanges it at halo-server POST /api/v1/token/exchange and exports the
gateway URL and credential for Claude Code, Codex and Gemini CLI.

--format github (default inside GitHub Actions) masks the credential with
::add-mask:: and appends the variables to $GITHUB_ENV; --format env prints
"export" lines for eval; --format json prints the exchange response.

## Usage

```console
halo ci token [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--audience` |  | string | halos | audience to request for the GitHub Actions OIDC token (policy workloads.audience) |
| `--format` |  | string |  | env \| github \| json (default: github inside GitHub Actions, else env) |
| `--server` |  | string |  | halo-server base URL (env HALO_SERVER); https unless loopback |
| `--timeout` |  | duration | 30s | overall timeout for fetching and exchanging the token |
| `--token-env` |  | string | HALO_ID_TOKEN | variable holding the OIDC token on non-GitHub CI (GitLab id_tokens, Buildkite, CircleCI, cloud metadata) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo ci`](/halos/reference/cli/ci/)
