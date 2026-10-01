---
title: "halo release refresh"
description: "Re-sign a ring's pointer and its experiment channel pointers (same releases, new seq and expiry)"
---

Re-sign a ring's pointer and its experiment channel pointers (same releases, new seq and expiry)

Pointers expire after 7 days and halod then refuses the ring. Run refresh on a schedule
well inside that window (e.g. daily); see .github/workflows/refresh-pointers.yml.example.
The pointers of every client-axis experiment channel the ring's current release routes to
are refreshed too.

Refresh re-signs what the registry serves, so it refuses anything that could be a replayed
old pointer: an expired pointer (recover with: halo rollback --to &lt;version>), and, via the
--state-file, a pointer older than the last one this signer wrote. The state file lives at
$XDG_STATE_HOME/halos/pointers.json by default; in CI, cache it between runs, or pass
--expect-digest with the release digest the ring must be serving.

## Usage

```console
halo release refresh [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--adopt-existing` |  | bool | false | trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache); without it such a pointer is refused unless --expect-digest names it |
| `--cosign-key` |  | string |  | cosign key reference (file or KMS URI); co-signs alongside --key |
| `--cosign-keyless` |  | bool | false | cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log |
| `--expect-digest` |  | string |  | refuse unless the ring currently serves this release digest (sha256:...); the stateless replay guard for CI |
| `--key` |  | string |  | ed25519 private key PEM (create one with: halo keys generate) |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--ring` |  | string |  | ring to refresh (required) |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo release`](/halos/reference/cli/release/)
