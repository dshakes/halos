---
title: "halo controller run"
description: "Evaluate running experiments and act on verdicts (never merges)"
---

Evaluate running experiments and act on verdicts (never merges)

Evaluates every running experiment from ClickHouse evidence, then drives active rollouts (state in
&lt;data-dir>/rollouts/; rollback/pause automatic, advance only opens a PR). rollback: trips the kill switch in
&lt;data-dir>/killswitch.jsonl (served to gateways when &lt;data-dir> is halo-server's --data-dir), opens a
PR pausing the experiment, notifies. Without --killswitch-served, messages say the kill is only recorded. promote/expired: opens a PR concluding it, notifies. Each action
happens once per experiment run (&lt;data-dir>/controller-state.jsonl). PRs are opened from the git
checkout containing --policy-dir with gh. Run a single controller per data dir. Kills are also appended
to &lt;data-dir>/audit.jsonl (hash chain shared with halo-server): do not run this against a data dir
a live halo-server is appending to (single writer); use the server's in-process controller there.

## Usage

```console
halo controller run [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--base` |  | string |  | PR base branch |
| `--clickhouse` |  | string |  | ClickHouse HTTP URL, e.g. http://localhost:8123 (required) |
| `--data-dir` |  | string |  | directory for controller-state.jsonl and killswitch.jsonl (required) |
| `--database` |  | string |  | ClickHouse database |
| `--interval` |  | duration | 5m0s | tick interval without --once |
| `--killswitch-served` |  | bool | false | acknowledge that halo-server (with --killswitch-key-file) serves this --data-dir to gateways; without it, rollback messages say the kill is only recorded, not enforced |
| `--no-pr` |  | bool | false | do not open PRs (verdicts, kills and notifications only) |
| `--notify-slack-url-file` |  | string |  | file holding a Slack incoming-webhook URL |
| `--notify-webhook-secret-file` |  | string |  | file holding the webhook HMAC-SHA256 secret (X-Halo-Signature) |
| `--notify-webhook-url-file` |  | string |  | file holding a generic webhook URL |
| `--once` |  | bool | false | run a single tick and exit (CI/cron); non-zero exit if any experiment failed |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--user` |  | string |  | ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD) |
| `--verdicts-file` |  | string |  | upsert each verdict into this JSON array file read by halo-server |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo controller`](/halos/reference/cli/controller/)
