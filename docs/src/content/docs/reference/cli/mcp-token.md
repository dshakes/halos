---
title: "halo mcp token"
description: "Mint a short-lived token for one MCP server whose authorization server is Halos"
---

Mint a short-lived token for one MCP server whose authorization server is Halos

Exchanges your Halos credential at halo-server POST /api/v1/token/exchange
(RFC 8693 with resource=&lt;server URL>, RFC 8707) for a token only that server
accepts (aud = its URL, 5 minutes at most). The server must be in the
halos.yaml mcp registry with auth mode halos and enabled for your ring or unit.

The credential is HALO_SESSION (your halo_session cookie value) when set,
else HALO_GATEWAY_TOKEN holding a workload or delegated agent credential
(halo ci token, agent delegation). It is sent only to halo-server, never to
the MCP server.

--format headers (the default) prints {"Authorization": "Bearer ..."}, the
output Claude Code's headersHelper expects; token prints the bare token; json
the exchange response.

## Usage

```console
halo mcp token [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--format` |  | string | headers | headers \| token \| json |
| `--resource` |  | string |  | the MCP server's URL as the registry lists it (required) |
| `--server` |  | string |  | halo-server base URL (env HALO_SERVER); https unless loopback |
| `--timeout` |  | duration | 15s | exchange timeout |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo mcp`](/halos/reference/cli/mcp/)
