---
title: "halo service-token"
description: "Create, list and revoke halo-server service-account API tokens (admin)"
---

Create, list and revoke halo-server service-account API tokens (admin)

Service-account tokens are bearer credentials for automation (CI, `halo mcp serve`, scripts), bound to one halo-server role and always expiring. Use them as HALO_TOKEN instead of copying a browser's halo_session cookie into HALO_SESSION. Creating one needs an interactive admin session (HALO_SESSION): a token cannot mint tokens.

## Usage

```console
halo service-token
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
| [`halo service-token create`](/halos/reference/cli/service-token-create/) | Create a service-account token; it is printed once and never again |
| [`halo service-token list`](/halos/reference/cli/service-token-list/) | List service-account tokens (never their secrets) |
| [`halo service-token revoke`](/halos/reference/cli/service-token-revoke/) | Revoke a service-account token at once, on every replica |

## Parent

[`halo`](/halos/reference/cli/)
