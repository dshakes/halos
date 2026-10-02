---
title: "halo quickstart"
description: "Try it: bring up the whole stack on Docker (make demo), open the console and print a guided tour"
---

Try it: bring up the whole stack on Docker (make demo), open the console and print a guided tour

Runs scripts/demo.sh from a Halos checkout: --src, else the current directory if it is one, else a
shallow clone it makes in ~/.cache/halos/src. DEV ONLY: mock IdP, mock models, throwaway keys.
`halo quickstart down` stops it and deletes its volumes.

## Usage

```console
halo quickstart [down] [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--dry-run` |  | bool | false | print the commands instead of running them |
| `--no-open` |  | bool | false | do not open the console in a browser |
| `--src` |  | string |  | Halos checkout to run from |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
