---
title: Data-loss prevention
description: Stop secrets leaving in model calls and flag prompt injections in tool results, per ring and org unit, with audit evidence in your SIEM.
---

Every model call a coding CLI makes carries what the agent read: `.env` files, cloud keys, tokens pasted into the chat. Tool results bring web pages and files into the model with your user's authority. With `gateway.dlp`, `halo-proxy` and `halo-kong` scan each request for secrets and each tool result for prompt-injection signals, act per ring and org unit, and record every finding without ever storing the secret. Design and limits: [ADR-0033](/halos/adr/0033-gateway-dlp-and-injection-defense/).

## Turn it on

Start in `monitor` everywhere. It changes nothing, counts and audits:

```yaml
# gateway.yaml
dlp:
  secrets:
    action: monitor
  injection:
    action: monitor
```

Then tighten by ring or unit once the counts look right:

```yaml
dlp:
  secrets:
    action: redact            # everyone: secrets become [REDACTED:<detector>:<hash8>]
    patterns:
      - id: acme-deploy-token # your own token formats (RE2)
        regex: 'acme_dpl_[a-z0-9]{32}'
  injection:
    action: monitor
  rules:                      # first match wins
    - units: [payments]       # payments and its child units refuse secrets outright
      secrets: block
    - rings: [ring1-canary]   # try injection blocking on the canary ring first
      injection: block
```

`halo validate` checks the block (actions, detector ids, RE2 patterns, rule rings and units). Publish as usual: `halo gateway compile` and roll the snapshot.

| Action | Secrets | Prompt injection |
|---|---|---|
| `monitor` (default) | forwarded unchanged; counted, logged, audited | same |
| `redact` | each secret replaced with `[REDACTED:<detector>:<hash8>]`; the rest of the JSON is byte-for-byte unchanged | n/a: model content is never modified |
| `block` | HTTP 400 in the CLI's own error format | HTTP 400 when a tool result scores at or above `threshold` (default 4) |
| `off` | not scanned | not scored |

The 400 names the detector, marker and JSON path (for example `github-token, [REDACTED:github-token:5f0c9e2a] at messages[12].content[0].content`), so the developer knows what to remove. A conversation re-sends its history every turn: under `block` it stays refused until the secret is out of the conversation (rewind or clear), and the secret should be rotated.

## Detectors

`aws-access-key-id`, `github-token`, `gitlab-token`, `slack-token`, `slack-webhook`, `stripe-key` (live keys), `anthropic-api-key`, `openai-api-key`, `jwt`, `private-key` (PEM), `gcp-service-account`, and `generic-secret` (a secret-like key name assigned a long, mixed-case, high-entropy value). Turn one off with `secrets.disable: [jwt]`. The [ADR](/halos/adr/0033-gateway-dlp-and-injection-defense/#secret-detectors) lists exactly what each matches and why it is high precision.

Injection signals (each counts once per tool result): instruction overrides (3), a secret inside a URL (3), invisible Unicode (tag characters 3, zero-width or bidi 2), role reassignment (2), fake conversation turns (2), imperatives in HTML comments (2), Markdown-image exfiltration URLs (2), and permission-bypass flags such as `--dangerously-skip-permissions` (2). The default threshold of 4 needs two independent signals. Only tool output and documents are scored, never what the user typed.

## Try it locally

`halo dlp test` runs the same scan on a file without sending anything. A JSON model-call body is scanned as a request; anything else is scanned as a tool result:

```bash
halo dlp test ~/.aws/credentials
halo dlp test --policy-dir . --unit checkout captured-request.json
halo dlp test --secrets redact --show-redacted captured-request.json
halo --output json dlp test suspicious-readme.md
```

It prints each finding (kind, detector, hash, JSON path, injection score and signals) and what the gateway would do. Exit code 0 means nothing was found, 2 means something was, so it works in a pre-commit hook or CI step.

## Evidence

**Audit and SIEM.** Point the gateways at `halo-server` and every finding becomes an audit entry (`dlp.secret` or `dlp.injection`, actor `gateway:halo-proxy`, target the verified user, details detector, hash, location, action, ring, unit, harness), which the [SIEM export](/halos/guides/siem-export/) forwards with everything else:

```bash
openssl rand -hex 32 > dlp.token          # same file on halo-server and the gateways
halo-server ... --gateway-dlp-token-file dlp.token
halo-proxy  ... --dlp-url https://halo-server/api/v1/gateway/dlp --dlp-token-file dlp.token
```

halo-kong: `dlp_url` and `dlp_token` (`{vault://env/HALO_DLP_TOKEN}`) in the plugin config. Without a URL, findings are still counted and logged. One finding is audited once an hour per user even though the history repeats it on every turn.

**Metrics** (halo-proxy `/metrics`):

| Metric | Labels |
|---|---|
| `halo_proxy_dlp_findings_total` | `kind`, `detector`, `action`, `direction` (`request`, `response`) |
| `halo_proxy_dlp_scans_total` | `direction`, `outcome` (`clean`, `finding`, `redacted`, `blocked`, `truncated`) |
| `halo_proxy_dlp_scan_seconds_total` | time spent scanning request bodies |
| `halo_proxy_dlp_audit_events_total` | `outcome` (`sent`, `dropped`, `deduped`) |
| `halo_proxy_dlp_audit_failures_total` | failed posts to halo-server (retried) |

halo-kong exports `halo_kong_dlp_findings_total{kind,detector,action}`. Alert on `rate(halo_proxy_dlp_findings_total{kind="secret"}[1h]) > 0` per detector, and on `halo_proxy_dlp_scans_total{outcome="truncated"}` growing (raise `maxScanBytes`).

**Request log.** A `dlp` attribute lists `kind detector action at <path> #<hash8>` per finding. **Session ledger:** each session record carries `dlpSecrets` and `dlpInjections` ([session ledger](/halos/guides/session-ledger/)).

The secret itself is never in any of these: only the detector id, the first 8 hex of its SHA-256 (to correlate one secret across events) and where it was.

## Responses

halo-proxy also watches streamed responses for secrets the model repeats back (`direction="response"`). This is monitor only: the stream reaches the CLI byte for byte, never delayed or cut. halo-kong does not scan responses. Turn it off with `scanResponses: false`.

## Limits

- Pattern-based: a secret with no recognisable format and no key name next to it is not found. Add org `patterns` for your own token formats.
- Injection scoring is a tripwire and an audit trail, not a guarantee; the CLIs' permission prompts and the [guardrails](/halos/adr/0007-guardrails-in-go-not-opa/) stay the control on what an agent may do.
- `maxScanBytes` (default 4 MiB) and a 250 ms budget bound each scan. Under `monitor` or `redact` the rest of a larger body passes unscanned and is counted as `truncated`. Under a `block` secret action the request is refused rather than forwarded unscanned: HTTP 413 past `maxScanBytes`, HTTP 400 (`dlp_scan_incomplete`) past the time budget, counted as `truncated` (`halo_proxy_dlp_scans_total{outcome="truncated"}` and `outcome="blocked"`; `halo_kong_dlp_truncated_total{outcome="blocked"}`). The user sees the message in the CLI; `/compact` or a new session gets under the cap. A 200 KB request costs about 5 ms at p99.
