---
title: "halo keys generate"
description: "Generate an ed25519 signing key pair (PEM)"
---

Generate an ed25519 signing key pair (PEM)

Writes &lt;name>.key (private, 0600) and &lt;name>.pub. Without --out the pair goes to the per-user config
directory (&lt;user config dir>/halos/keys, 0700), never the current directory: that is often a policy repo,
where `git add -A` would commit the private key. A private key is refused inside a git work tree
unless --force.

## Usage

```console
halo keys generate [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--force` |  | bool | false | write the key even inside a git work tree (git-ignore it yourself) |
| `--name` |  | string | halo | file base name |
| `--out` |  | string |  | output directory (default: &lt;user config dir>/halos/keys) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo keys`](/halos/reference/cli/keys/)
