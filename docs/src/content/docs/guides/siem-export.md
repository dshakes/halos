---
title: SIEM export
description: Forward halo-server's hash-chained audit log to Splunk, Datadog or any HTTPS endpoint, or syslog over TLS, at least once and in order; rotate it; verify the chain on both ends.
---

`halo-server` records every privileged action (kills, enrollments, revocations, approvals, logins) in a hash-chained audit log in `--data-dir`. This guide ships that log to your SIEM and keeps it bounded on disk. Design and trade-offs: [ADR-0016](/halos/adr/0016-audit-export-to-siem/).

What you get:

- **Every entry, at least once, in order**, to each sink. A sink that is down holds back only itself and catches up from its cursor; nothing is skipped.
- **The chain travels with the data.** Each event carries `seq`, `prev` and `hash`, so the SIEM can prove nothing was edited, dropped or reordered, and holds the copy that catches a truncated server log.
- **No effect on actions.** Export runs after the local, fsynced append. A SIEM outage never delays or fails a kill or a revocation.

## Configure

Write an `--audit-config` file (JSON, unknown fields rejected) and start `halo-server` with `--data-dir` and `--audit-config`:

```json
{
  "rotation": {"maxBytes": 67108864, "maxAgeSeconds": 86400},
  "export": {
    "sinks": [
      {"name": "splunk", "type": "splunk-hec", "format": "ocsf",
       "url": "https://splunk.example.com:8088/services/collector/event",
       "token": {"env": "HALO_SPLUNK_HEC_TOKEN"}, "index": "halo"}
    ]
  }
}
```

| Field | Default | Meaning |
|---|---|---|
| `rotation.maxBytes` | off | Rotate before the active segment would pass this size (at least 4096) |
| `rotation.maxAgeSeconds` | off | Rotate once the active segment's first entry is this old (checked on append) |
| `export.batchSize` | 100 | Entries per delivery (max 1000) |
| `export.pollIntervalSeconds` | 5 | Idle re-check; an append wakes every sink at once |
| `export.maxBackoffSeconds` | 300 | Cap of the retry backoff (1 s doubling, jittered) |
| `sinks[].name` | | `[a-z0-9-]`, unique. Names the cursor file and the `sink` metrics label |
| `sinks[].type` | | `splunk-hec`, `webhook` or `syslog` |
| `sinks[].format` | `native` | `native` (the stored entry, byte for byte) or `ocsf` (OCSF API Activity, mapping in ADR-0016) |
| `sinks[].url` | | `splunk-hec`, `webhook`: https only |
| `sinks[].token` | | `splunk-hec`: secret ref, sent as `Authorization: Splunk <token>` |
| `sinks[].index`, `sourceType` | none, `halo:audit` | `splunk-hec` event metadata |
| `sinks[].headers` | | `webhook`: header name to secret ref (for example `DD-API-KEY`). `Content-Type` and `X-Halo-*` are reserved |
| `sinks[].hmacSecret` | | `webhook`: secret ref; signs each request |
| `sinks[].address` | | `syslog`: `host:port` (6514 is the TLS syslog port) |
| `sinks[].facility` | 13 (log audit) | `syslog` facility; severity is informational |
| `sinks[].caFile`, `certFile`, `keyFile` | system roots | TLS trust and an optional client certificate (mTLS) |
| `sinks[].timeoutSeconds` | 10 | Per delivery |

**Secrets** are references, never values: `{"env": "VAR"}` or `{"file": "/path"}` (trimmed). They are read once at start; a missing or empty one fails startup with the reference's name, never its value. Nothing logs a secret, a header value or a sink URL. Rotate a credential by updating it and restarting `halo-server`.

### Helm

`server.audit` is rendered to `/etc/halos/audit.json` and needs `server.persistence.enabled`. The ConfigMap holds references only; set the variables from a Secret, open egress to the SIEM, and enable metrics:

```yaml
server:
  metrics: {enabled: true}
  audit:
    rotation: {maxBytes: 67108864, maxAgeSeconds: 86400}
    export:
      sinks:
        - {name: splunk, type: splunk-hec, format: ocsf, index: halo,
           url: "https://splunk.example.com:8088/services/collector/event",
           token: {env: HALO_SPLUNK_HEC_TOKEN}}
  extraEnv:
    - name: HALO_SPLUNK_HEC_TOKEN
      valueFrom: {secretKeyRef: {name: halos-siem, key: hec-token}}   # human runs: kubectl create secret generic halos-siem ...
networkPolicy:
  egress:
    server:
      - {to: [{ipBlock: {cidr: 10.20.0.0/24}}], ports: [{protocol: TCP, port: 8088}]}
```

For file references (CA bundles, client keys) mount a Secret with `server.extraVolumes` and `server.extraVolumeMounts` and point `caFile`, `certFile`, `keyFile` or `{file: ...}` at it.

## Splunk

Create an HEC token whose allowed indexes include the one you name. The sink posts one HEC event per entry to `/services/collector/event`:

```json
{"time": 1767323045, "host": "halos-server-7d9", "source": "halo-server", "sourcetype": "halo:audit", "index": "halo", "event": {...}}
```

`event` is the stored entry (`native`) or the OCSF object (`ocsf`). With the Splunk OCSF add-on, `format: ocsf` lands as API Activity (class 6003). Search for gaps with `index=halo sourcetype=halo:audit | stats dc(seq) as n max(seq) as head` (for OCSF, `metadata.sequence`): `n == head` means nothing is missing.

## Datadog and other HTTP endpoints

The `webhook` sink posts a JSON array of events per batch with `Content-Type: application/json`, which Datadog's log intake accepts as-is:

```json
{"name": "datadog", "type": "webhook",
 "url": "https://http-intake.logs.datadoghq.com/api/v2/logs?ddsource=halos&service=halo-server",
 "headers": {"DD-API-KEY": {"env": "DD_API_KEY"}}}
```

Use your site's intake host (`datadoghq.eu`, `us3.datadoghq.com`, ...). Add a date remapper on `time` (native) if your pipeline does not pick it up.

For your own receiver, set `hmacSecret`. Each request then carries `X-Halo-Timestamp` (unix seconds) and `X-Halo-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>`, the same scheme as the controller's notification webhook. Recompute it over the raw body, compare in constant time, and reject timestamps more than 5 minutes off:

```python
import hmac, hashlib, time
def verify(secret: bytes, ts: str, sig: str, body: bytes) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    want = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
```

Answer 2xx only once the batch is stored. Any other status, a timeout or a redirect is a failure and the batch is retried.

## Syslog over TLS

The `syslog` sink speaks RFC 5424 over TLS with RFC 5425 octet-counted framing; the message is the event JSON:

```text
<110>1 2026-01-02T03:04:05Z halos-server-7d9 halo-server - audit - {"seq":1,"time":"2026-01-02T03:04:05Z",...}
```

```json
{"name": "syslog", "type": "syslog", "address": "siem.example.com:6514", "caFile": "/etc/siem-ca/ca.pem"}
```

syslog-ng receiver:

```text
source s_halo {
  syslog(port(6514) transport("tls")
         tls(key-file("/etc/syslog-ng/key.pem") cert-file("/etc/syslog-ng/cert.pem") peer-verify(optional-untrusted)));
};
```

rsyslog: `module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")` and `input(type="imtcp" port="6514")`. Require client certificates (`peer-verify(required-trusted)`, `AuthMode="x509/certvalid"`) and set `certFile`/`keyFile` on the sink for mTLS.

Syslog has no acknowledgement: a batch counts as delivered once the TLS write returns, so entries in flight when the connection drops can be lost. Use Splunk HEC or the webhook where that matters.

## Verify the chain in the SIEM

Every event carries the chain: `seq` (1, 2, 3, ... with no gaps), `prev` (the previous entry's `hash`) and `hash`. In OCSF they are `metadata.sequence`, `unmapped.prev` and `metadata.uid`, and `raw_data` is the stored line.

1. **Linkage** (no edits between entries, no gaps, no reordering): sorted by `seq`, each `prev` equals the previous `hash`.
2. **Content**: `hash` is the SHA-256 of the stored line with its trailing hash blanked. Take the native event (or `raw_data`) as received, replace the final `"hash":"<64 hex>"` with `"hash":""` and hash it:

   ```python
   import hashlib, re
   def entry_ok(raw: str) -> bool:
       m = re.search(r'"hash":"([0-9a-f]{64})"}$', raw)
       blank = raw[: m.start()] + '"hash":""}'
       return hashlib.sha256(blank.encode()).hexdigest() == m.group(1)
   ```

   This needs the bytes as sent. A SIEM that re-serializes JSON (reorders keys, re-escapes `<`, `>`, `&`) changes them; use `raw_data` (OCSF) or keep the raw event.
3. **Truncation**: the newest `hash` in the SIEM must appear in the server's log. `halo audit verify --data-dir <dir>` prints the server's head.

Delivery is at least once: a crash between a delivery and saving the cursor resends up to one batch. De-duplicate on `seq`.

## Agent sessions

Agent session ledger records ([ADR-0031](/halos/adr/0031-agent-session-ledger/)) are audit entries with `action` `session.record`, `target` the ledger id, and the record JSON in `details.record` (OCSF: `api.operation` and `unmapped.details.record`). They ship with the rest of the chain; no sink setting is needed. Filter on the action to route them to their own index. A session imported again is a new entry; the newest `seq` for a ledger id is the current version.

## Operate

Metrics on `--metrics-listen` ([reference](/halos/reference/metrics/#audit-export-metrics)): `halo_server_audit_forward_sent_total`, `halo_server_audit_forward_failed_total`, `halo_server_audit_forward_lag_entries`, `halo_server_audit_forward_last_success_timestamp_seconds` per `sink`, and `halo_server_audit_rotate_errors_total`. The [operations guide](/halos/guides/operations/#alerts) has the alert rules, and [audit log rotation](/halos/guides/operations/#audit-log-rotation) covers segments, archiving and backups.

**A sink stopped and the log says `audit chain broken`.** The forwarder only ships entries that continue what it already shipped, so an entry edited or removed on disk stops that sink at the break. Treat it as an incident: run `halo audit verify --data-dir <dir>`, compare the server's log with the SIEM copy, and find out who changed the volume. Export resumes on its own once the log is restored to verify (from a backup or the SIEM copy). It never skips a break: to move on without a repair, stop the server, move every `audit*.jsonl` out of the data dir (keep them as evidence), delete `<data-dir>/audit-forward/`, and start it. The server begins a new chain at seq 1 and the sinks ship it from the start; record the cut in the SIEM, since `seq` values repeat.

**`cursor ... is ahead of the log head`.** The data dir was restored from a backup older than what the sink received. See [restore](/halos/guides/operations/#restore).

**Adding a sink later** back-fills it: a new sink starts at the oldest entry still on disk.
