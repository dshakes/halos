---
title: "halo mcp registry import"
description: "Print a pinned halos.yaml mcp entry for a server from the official MCP Registry"
---

Print a pinned halos.yaml mcp entry for a server from the official MCP Registry

Reads a server.json (the official MCP Registry format) and prints a
halos.yaml mcp.servers entry pinned to its exact version: the npm, pypi or oci
stdio package (oci needs --sha256), or with --remote the streamable-HTTP URL.

The argument is a local file, an https URL serving server.json, or a registry
name (io.github.owner/server), fetched read-only from --registry's
/v0/servers/&lt;name>/versions/latest. Nothing is written: review the entry, set
rings/units, tools and auth, and add it to halos.yaml in a pull request.

## Usage

```console
halo mcp registry import <name|https-url|file> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--id` |  | string |  | registry id (default: derived from the server name) |
| `--registry` |  | string | https://registry.modelcontextprotocol.io | MCP Registry base URL for a name argument |
| `--remote` |  | bool | false | pin the remote streamable-HTTP endpoint instead of a package |
| `--sha256` |  | string |  | image digest sha256:&lt;hex> (required for an oci package) |
| `--timeout` |  | duration | 30s | fetch timeout |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo mcp registry`](/halos/reference/cli/mcp-registry/)
