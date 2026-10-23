---
title: "halo agents verify"
description: "Fetch an A2A AgentCard, verify its signature and pinned digest, and print the digest to pin"
---

Fetch an A2A AgentCard, verify its signature and pinned digest, and print the digest to pin

Fetches the AgentCard over https (no redirect off-host, at most 256KB, --timeout), refusing loopback, private and link-local destinations unless --allow-private. With --pubkey or --jwks-url the card's JWS signature must verify (A2A spec section 8.4); with --digest the card must match it. With --policy-dir, an agents.remote entry whose cardURL is the URL supplies digest, publicKey, jwksURL and skills (flags override). Exit 1 when anything fails.

## Usage

```console
halo agents verify <card-url> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--allow-private` |  | bool | false | allow loopback, private and link-local destinations (an internal agent) |
| `--digest` |  | string |  | expected card digest (sha256:&lt;hex>) |
| `--jwks-url` |  | string |  | https JWKS whose key must have signed the card |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--pubkey` |  | string |  | PEM public key the card must be signed with |
| `--timeout` |  | duration | 10s | fetch timeout |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo agents`](/halos/reference/cli/agents/)
