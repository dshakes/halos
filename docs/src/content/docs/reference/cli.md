---
title: CLI reference
description: halo, halod, halo-proxy, halo-server, halo-shadow. Derived from the binaries' --help output.
---

Everything on this page is taken from `--help` of the built binaries. `halo` has one global flag: `--output text|json`. Commands that read a policy repo take `--policy-dir D` (default `.`); the old `--dir` and positional `[dir]` still work but are deprecated.

## `halo`

| Command | Purpose |
|---|---|
| `halo init [--org name]` | Scaffold a minimal policy repo |
| `halo validate` | Load and validate a policy repo (schema, references, guardrails). Exit 2 on errors |
| `halo whoami --user U [--groups g1,g2]` | Ring and experiment variants a user is assigned |
| `halo harnesses` | Harness capability matrix |
| `halo render --ring R [--os darwin\|linux\|windows] [--out dir] [--release-version V]` | Render a ring's harness files under `--out`, mirroring absolute paths; adapter warnings go to stderr. Defaults: `--os darwin`, `--out rendered` |
| `halo plan --ring R --against <release.tar or host/org/name[:tag]> [--registry ...] [--pubkey pem] [--cosign-key ref] [--plain-http]` | Diff the release a ring would get against a previous release |
| `halo release build --ring R [-o release.tar] [--release-version V] [--no-artifacts]` | Build a release tarball |
| `halo release publish --ring R --release-version V --registry REPO --key halo.key [--cosign-key ref] [--cosign-keyless] [--plain-http] [--no-artifacts]` | Build, sign and push; tags `v<version>` and `ring-<ring>` and writes the signed ring pointer. A running client-axis experiment on the ring adds one signed channel per variant ([below](#experiment-channels-in-release-commands)) |
| `halo release promote --from-ring A --to-ring B --registry REPO --key halo.key [--expect-digest sha256:...]` | Point ring B at the release **A's signed pointer** names (signature, ring, org, expiry and state continuity checked; the `ring-A` tag is never used). Moves only the ring pointer, never A's experiment channels |
| `halo release refresh --ring R --registry REPO --key halo.key [--expect-digest sha256:...]` | Re-sign a ring's pointer and its experiment channel pointers: same releases, new `seq` and expiry. Pointers expire after 7 days; run this daily. **Refuses an expired pointer** (recover with `halo rollback --to <version>`) |
| `halo rollback --ring R --to <version\|sha256:manifest-digest> --registry REPO --key halo.key [--expect-digest sha256:...]` | Point a ring and its experiment channels back at an earlier signed release (new pointers, higher `seq`). `--to <version>` is refused unless the release's signed manifest carries that version; `--to sha256:` is the **OCI manifest** digest |
| `halo export jamf\|intune\|devcontainer` | Export a signed release for a delivery channel (below) |
| `halo exp list\|show\|start\|pause\|conclude` | Experiments; `start`, `pause`, `conclude` edit the YAML `status` in place. `--policy-dir` selects the policy repo |
| `halo exp analyze <name> --clickhouse URL [--database D] [--user U] [--verdicts-file f]` | Verdict: `promote`, `rollback`, `continue`, `expired`. Password from `HALO_CLICKHOUSE_PASSWORD` |
| `halo controller run --clickhouse URL --data-dir D [flags]` | Automated experiment loop: evaluate, kill on rollback, open PRs, notify. [Flags below](#halo-controller-run) |
| `halo exp promote <name> --ring R --release digest --clickhouse URL [--base B] [--dry-run]` | Open a PR pointing the ring at the release. Needs a `promote` verdict; never merges |
| `halo eval run <suite.yaml> [--local] [--parallel 2] [--cpus 2] [--memory 4g] [--network none] [--pass-env VARS] [--seed 1]` | Offline replay evals in Docker; prints a scorecard. `--local` runs on the host with no isolation (testing only) |
| `halo gateway compile [-o policy.json]` | Compile the policy snapshot `halo-proxy`, `halo-kong` and `halo-shadow` load |
| `halo gateway deck [--identity-header H] [--groups-header H] [--policy-path P] [--halo-shadow-url U] [--halo-shadow-token T] [--killswitch-url U] [-o kong.yml]` | Generate the decK declarative config for Kong plus `halo-kong`. `--killswitch-url` (must be https) sets `killswitch_url` and emits the token and public key as `{vault://env/halo-killswitch-token}` / `{vault://env/halo-killswitch-pubkey}` references; it does not emit `killswitch_allow_insecure_in_cluster`. See [Bedrock via Kong](/halos/guides/bedrock-via-kong/#5-kill-switch-optional) |
| `halo telemetry collector-config --clickhouse tcp://host:9000 [--database halo] [--grpc-endpoint ...] [--http-endpoint ...] [--gateway-endpoint ...] [--prometheus-endpoint ...] [--cli-token-file F] [-o file]` | OpenTelemetry Collector config that normalizes to `halo.*`. [Flags below](#halo-telemetry-collector-config) |
| `halo keys generate [--name halo] [--out .]` | Generate an ed25519 key pair (`<name>.key`, `<name>.pub`). Use `--name killswitch` for the [kill-switch key](/halos/concepts/security-model/#kill-switch); never reuse the release key |
| `halo mcp serve [--policy-dir D] [--allow-writes] [--clickhouse URL] [--database D] [--user U] [--schema-dir D]` | MCP server over stdio. See [agentic operations](/halos/guides/agentic-operations/) |
| `halo version` | Print the version |

Commands that need a signing key take `--key <ed25519 private key PEM>`; `publish`, `promote`, `refresh` and `rollback` also accept `--cosign-key` (file or KMS URI, as a co-signature) and `--cosign-keyless`. `--plain-http` allows a local HTTP registry.

### Signing continuity flags

`publish`, `promote`, `refresh` and `rollback` take `--state-file` and `--adopt-existing`; `promote`, `refresh` and `rollback` also take `--expect-digest`. Concepts: [signer continuity](/halos/concepts/security-model/#signer-continuity), [ADR-0008 addendum](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/#addendum-2026-09-30-signer-side-continuity).

| Flag | Meaning |
|---|---|
| `--state-file PATH` | Signer state file: the last pointer written per registry repo and ring (`seq`, `digest`, `issuedAt`). A registry serving a lower `seq`, the same `seq` with another digest, or no pointer where one was written is refused. Default `$XDG_STATE_HOME/halos/pointers.json` (`~/.local/state/halos/pointers.json`). A missing file is empty state, but a pointer the registry already serves that the file has no record of is **refused** unless confirmed with `--expect-digest` or `--adopt-existing`; an unparseable file blocks signing. One signer per file. **In CI, cache this file between runs** |
| `--adopt-existing` | Trust a served pointer the state file has no record of (first run with a new state file, or after a CI cache eviction) and continue the checks from it. Prefer `--expect-digest` when you know the digest the ring must serve |
| `--expect-digest sha256:...` | Refuse unless the release involved has this **release** digest (`refresh`: what the ring serves now; `promote`: what `--from-ring` serves; `rollback`: what `--to` resolves to). The stateless replay guard for CI |

New pointers get `seq = max(served + 1, recorded + 1, unix now)`. Before each signature the command prints one line per pointer (the ring and each experiment channel) to **stderr**, so `--output json` stays parseable:

```text
Signing ring ring1-canary → version 1.4.2 (digest sha256:..., seq 1790784827)
```

The release digest (this line, `publish` text output, JSON `digest`) differs from the OCI manifest digest (JSON `manifest`), which is what `rollback --to sha256:` takes.

### Experiment channels in release commands

Text output, one line per pointer or channel:

```text
published ghcr.io/acme/halos tags v1.0.0, ring-ring1-ga (sha256:...)
  channel experiment cli-upgrade variant control: tags v1.0.0-x-cli-upgrade.control, ring-ring1-ga.x-cli-upgrade.control (sha256:...)
  channel experiment cli-upgrade variant treatment: tags v1.0.0-x-cli-upgrade.treatment, ring-ring1-ga.x-cli-upgrade.treatment (sha256:...)
```

`refresh`, `rollback` and `promote` print `ok refreshed|rolled back|promoted ring-<name>: version V, seq N, digest ..., expires ...` for the ring first, then for each channel.

With `--output json`, `publish` returns `registry`, `digest` (release), `manifest` (OCI manifest), `tags` and `"channels": ["ring1-ga.x-cli-upgrade.control", ...]` (the `tags` string lists every tag written). `refresh`, `rollback` and `promote` return the ring's `ring`, `version`, `seq`, `digest`, `expiresAt` plus `"channels": [{"channel", "version", "seq", "digest", "expiresAt"}]` (empty when the ring runs no client-axis experiment). Concepts: [rings and releases](/halos/concepts/rings-and-releases/#experiment-channels).

### `halo telemetry collector-config`

Generates a collector with two OTLP receivers so experiment evidence can be trusted ([evidence trust](/halos/concepts/evidence-plane/#evidence-trust)).

| Flag | Default | Purpose |
|---|---|---|
| `--clickhouse ENDPOINT` | (required) | ClickHouse endpoint, for example `tcp://clickhouse:9000`. The config reads `${env:CLICKHOUSE_USER}` and `${env:CLICKHOUSE_PASSWORD}` |
| `--database` | `halo` | ClickHouse database |
| `--grpc-endpoint` / `--http-endpoint` | `0.0.0.0:4317` / `0.0.0.0:4318` | CLI receiver (developer machines). Drops `halo.gateway.*`, stamps `halo.source=cli`, request size capped at 4 MiB |
| `--gateway-endpoint` | `0.0.0.0:4319` | `halo-proxy` OTLP/HTTP receiver. Requires the bearer token in the **collector's** env `HALO_OTLP_GATEWAY_TOKEN` (the collector refuses to start without it); stamps `halo.source=gateway` |
| `--cli-token-file F` | off | Require a per-device bearer token on the CLI receiver. One token per line in this file, **as seen by the collector** (mount it); re-read when it changes |
| `--prometheus-endpoint` | `0.0.0.0:8889` | Scrape address. `halo.gateway.*` is not exposed here |
| `-o`, `--out` | `-` (stdout) | Output file |

`halo-proxy` side: `--telemetry-otlp-endpoint http://collector:4319 --telemetry-token-file F` with the same token ([below](#halo-proxy)).

### `halo controller run`

Evaluates every running experiment from ClickHouse evidence on a timer (or once) and acts. `rollback` trips the kill switch in `<data-dir>/killswitch.jsonl`, opens a PR pausing the experiment and notifies. `promote` and `expired` open a PR concluding it and notify. Each action happens once per experiment run, recorded in `<data-dir>/controller-state.jsonl`. PRs are opened with `gh` from the git checkout containing `--policy-dir`. **Run a single controller per data dir.** Concepts: [experiments](/halos/concepts/experiments/#the-controller-loop).

| Flag | Default | Purpose |
|---|---|---|
| `--clickhouse URL` | (required) | ClickHouse HTTP URL, for example `http://localhost:8123` |
| `--data-dir DIR` | (required) | Directory for `controller-state.jsonl` and `killswitch.jsonl`. Kills reach gateways only when this is `halo-server`'s `--data-dir` |
| `--database`, `--user` | | ClickHouse database and user; password from `HALO_CLICKHOUSE_PASSWORD` |
| `--policy-dir` | `.` | Policy repo directory |
| `--killswitch-served` | off | Acknowledge that `halo-server` (started with `--killswitch-key-file`) serves this `--data-dir` to gateways. Without it, rollback messages say the kill was only **recorded**, not enforced |
| `--interval` | `5m` | Tick interval without `--once`; minimum `1m` |
| `--once` | off | One tick, then exit (CI, cron); non-zero exit if any experiment failed |
| `--no-pr` | off | Do not open PRs (verdicts, kills and notifications only) |
| `--base` | | PR base branch |
| `--verdicts-file F` | | Upsert each verdict into this JSON array file read by `halo-server`. The old name `--verdicts` is deprecated |
| `--notify-slack-url-file F` | | File holding a Slack incoming-webhook URL |
| `--notify-webhook-url-file F` | | File holding a generic webhook URL (receives the JSON event) |
| `--notify-webhook-secret-file F` | | File holding the HMAC-SHA256 secret; adds `X-Halo-Timestamp: <unix s>` and `X-Halo-Signature: sha256=<hex HMAC(secret, timestamp + "." + body)>`; receivers must verify and reject timestamps more than 5 minutes off ([snippets](#verifying-the-webhook-signature)) |

`--interval` replaces the deprecated `--controller-interval`. Behavior that matters:

- **Kills are audited.** Each kill is appended to `<data-dir>/audit.jsonl` (the hash chain `halo-server` uses, fsynced). If the audit append fails, the kill stays applied and the command reports the error. Because `audit.jsonl` has a single writer, **do not run this against a data dir a live `halo-server` is appending to**; use the server's in-process controller there.
- **Only gateway-sourced evidence kills.** A rollback decided on CLI telemetry opens the pause PR and notifies with `killOutcome: not_gateway_evidence`.
- **Killed experiments are held.** A running experiment that is already killed is not evaluated; notifications say to unkill before resuming.
- **Notifications retry per channel** on later ticks; a channel that succeeded is not re-posted.

#### Verifying the webhook signature

The generic webhook is `POST` JSON with `X-Halo-Timestamp` and `X-Halo-Signature`. Verify the HMAC over the **raw body** and reject a stale timestamp (5 minutes), or a captured request can be replayed. Go:

```go
const tolerance = 5 * time.Minute

func verify(secret []byte, r *http.Request, body []byte, now time.Time) error {
	ts, err := strconv.ParseInt(r.Header.Get("X-Halo-Timestamp"), 10, 64)
	if err != nil {
		return errors.New("bad X-Halo-Timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("timestamp outside tolerance (replay?)")
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	want := "sha256=" + hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-Halo-Signature"))) {
		return errors.New("signature mismatch")
	}
	return nil
}
```

Python:

```python
import hashlib, hmac, time

TOLERANCE = 300  # seconds

def verify(secret: bytes, headers: dict, body: bytes) -> bool:
    try:
        ts = int(headers["X-Halo-Timestamp"])
    except (KeyError, ValueError):
        return False
    if abs(time.time() - ts) > TOLERANCE:
        return False
    want = "sha256=" + hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers.get("X-Halo-Signature", ""))
```

Read the body bytes before parsing JSON; re-serialized JSON will not match. The event has `experiment`, `axis`, `verdict` (`promote`, `rollback`, `expired`, or `killed` for a held experiment), `reason`, `killed`, `killOutcome` (`enforced`, `recorded_only`, `not_configured`, `not_gateway_evidence`, `failed`), `killError`, `prURL`, `prError`, `report` and `at`.

### `halo export`

Shared flags: `--registry` (required), `--pubkey` (required; verifies the release and is embedded inline), `--out` (default `halo-export`), `--plain-http`, `--download-url` (https `halod` URL; `{os}` and `{arch}` are substituted), `--halod-sha256 <os>/<arch>=<hex>` (repeatable or comma-separated), `--ring`, `--org`.

**`--org` is required with `--ring`.** The export pulls the ring's signed pointer, verifies it with `--pubkey` and requires the pointer to carry that org, so a pointer for another org (or an unsigned/expired one) is refused before anything is written.

| Subcommand | Output | Notes |
|---|---|---|
| `jamf` | `.mobileconfig` plus a `halod` postinstall | Needs `--ring`, `--download-url` and `--halod-sha256` for `darwin/amd64` and `darwin/arm64`. Kandji takes the same file |
| `intune` | PowerShell script writing `HKLM\SOFTWARE\Policies\ClaudeCode` and a SYSTEM startup task | Needs `--ring`, `--download-url` and `--halod-sha256` for `windows/amd64` and `windows/arm64`. **UNVERIFIED:** PowerShell not executed |
| `devcontainer` | Dev Container Feature source with org defaults baked in | Needs Linux amd64 and arm64 sha256s. `--org` when no release is pulled; with `--ring` it is required as above |

Only the Claude Code harness has an MDM channel.

### Exit codes

`halo validate` exits 0 when valid and 2 on validation errors. Other commands exit non-zero with `error: ...` on stderr.

## `halod`

`halod run|once|status [--config f] [--state f] [--root dir] [--install=true]`; `halod help` lists commands and `halod <command> -h` its flags.

| Command | Purpose |
|---|---|
| `halod run` | Loop: pull, verify, apply, report, sleep `interval` (default 15m) |
| `halod once` | One cycle, then exit |
| `halod status` | Print the last status (`ring`, `digest`, per-harness `want`/`installed`, `drift`, `lastError`, `errorCode`, and `experiment`/`variant` when a client-axis variant is applied; `killed` when that experiment is on the kill list) from the state file |

Flags: `--config` and `--state` default to the per-OS paths in [delivery](/halos/concepts/delivery/); `--install=false` skips CLI installs; `--root` prefixes every path (testing). `halod` refuses to start if the config, public key, device-token file or state file, or any ancestor, is not root-owned and non-group/other-writable.

### `halod.yaml`

| Key | Required | Meaning |
|---|---|---|
| `registry` | yes | OCI repository, for example `ghcr.io/acme/halos` |
| `org` | yes | Must equal the org in the signed pointer and release |
| `pubkey` / `pubkeys` | one of | Path to the ed25519 public key PEM, and/or a list of additional PEM paths. A release signed by any listed key verifies, so old and new keys overlap during rotation. `halod` never applies an unsigned release |
| `revokedKeys` | no | Fingerprints (`sha256:<hex>` of the raw ed25519 public key, printed by `halod` at startup) that are never trusted, even if listed in `pubkey`/`pubkeys` |
| `ring` or `ringEndpoint` | one of | Fixed ring name, or an https endpoint answering `GET ?user=&host=` with `{"ring":"name"}`; it may add `"subject"` (halo-server does) |
| `subject` | no | User id that client-axis experiments are assigned by, used when the ring endpoint does not return one (MDM: template the user id in). Falls back to the last saved subject. With none, `halod` stays on the ring release and reports `no_subject_for_experiment`. 1 to 256 characters, no control characters or surrounding space |
| `killSwitch` | no | `pubkey` (kill-switch public key PEM; setting it enables polling), `url` (default `<ringEndpoint origin>/api/v1/fleet/killswitch`, https), `interval` (default `60s`, minimum `1s`). Needs a device token. A killed client-axis experiment reverts the device to the ring release within one interval; `status` shows `killed: true`. [Experiments](/halos/concepts/experiments/#limits-the-client-axis) |
| `interval` | no | Go duration, default `15m`, minimum `1s` |
| `os` | no | Defaults to the host OS |
| `reportURL` | no | https URL that receives the status after every cycle |
| `deviceToken` / `deviceTokenFile` | no | Bearer token for ring and report calls. Prefer the file (mode 0600, root-owned) |
| `plainHTTP` | no | Registry over HTTP (development only) |
| `allowShellInstall` | no | **Insecure.** Permits the legacy `installCommand` when no verified artifact exists. Default `false` |
| `maxBundleBytes` | no | Cap on the release download, default 256 MiB |

`ringEndpoint` and `reportURL` must be https (plain http only to loopback).

## `halo-proxy`

Flags (env `HALO_PROXY_<FLAG>`, YAML `--config`): `--listen :8088` (proxied model traffic only), `--admin-listen 127.0.0.1:9090` (unauthenticated `/healthz` and `/metrics`; empty disables; YAML `adminListen`), `--policy`, `--next-hop`, `--default-upstream`, `--forward-auth`, `--identity-mode jwt|trusted_header|none`, `--issuer`, `--audience`, `--identity-header`, `--groups-header`, `--trusted-proxy-cidrs`, `--allow-anonymous`, `--halo-shadow-url`, `--halo-shadow-token`, `--max-body-bytes 33554432`, `--read-timeout 5m`, `--upstream-header-timeout 10m`, `--shutdown-timeout 30s`. Details: [stack-agnostic](/halos/concepts/stack-agnostic/).

| Flag | YAML | Purpose |
|---|---|---|
| `--killswitch-url` | `killSwitch.url` | halo-server `/api/v1/gateway/killswitch`; empty disables |
| `--killswitch-token-file` | `killSwitch.tokenFile` | File holding the gateway token |
| `--killswitch-pubkey-file` | `killSwitch.pubkeyFile` | ed25519 PEM public key verifying the kill list |
| `--killswitch-interval` | `killSwitch.interval` | Poll interval, default `10s` |
| `--telemetry-otlp-endpoint` | `telemetry.otlpEndpoint` | OTLP/HTTP collector base URL for `halo.gateway.*` per-request metrics; use the collector's gateway receiver (`:4319`). Empty disables |
| `--telemetry-token-file` | `telemetry.tokenFile` | File holding the bearer token for that receiver (the collector's `HALO_OTLP_GATEWAY_TOKEN`), read once at startup. Without it the collector answers 401 and the controller sees no gateway evidence, so it cannot auto-kill |
| `--telemetry-unit-salt-file` | `telemetry.unitSalt` (inline) | File holding the `halo.unit` hash salt. Use the same salt on every replica so one user stays one unit; empty means a random per-process salt. The flag takes a file because flags leak through `ps` |
| `--telemetry-protocol`, `--telemetry-interval` | `telemetry.protocol`, `telemetry.interval` | `http/protobuf` (default) or `http/json`; export interval, default `10s`, minimum `1s` |
| | `killSwitch.allowInsecureInCluster` | YAML only, default `false`. Plain `http://` to a non-loopback kill-switch URL is refused (the gateway token would travel in the clear) unless this is `true`; for a trusted in-cluster Service URL |
| | `signHosts` | YAML only, list of exact hostnames. Extra hosts a `kind: bedrock` upstream may be SigV4-signed for, besides `*.amazonaws.com`, `*.amazonaws.com.cn` and `*.api.aws` (for example a private VPC endpoint DNS name) |

The kill-switch URL, token file and public key must be set together. `kind: bedrock` upstreams are SigV4-signed by `halo-proxy` with its own AWS credentials, configured in policy plus `signHosts`. It signs only for AWS endpoint hosts or `signHosts`; any other host with a region gets a 502, and every client `x-amz*` / `x-amzn*` header is stripped first ([direct Bedrock](/halos/concepts/stack-agnostic/#direct-bedrock-sigv4-in-halo-proxy)).

## `halo-server`

Flags (Go style, single or double dash):

| Flag | Default | Purpose |
|---|---|---|
| `-policy-dir` | (required) | Policy repo served by the API. SIGHUP reloads |
| `-token-file` | (required) | Fleet bearer token for `POST /api/v1/fleet/report` |
| `-listen` | `127.0.0.1:8080` | API and console address |
| `-data-dir` | in-memory | Directory for the JSONL logs: fleet, requests, devices, session revocations, `audit.jsonl`, `killswitch.jsonl`, `controller-state.jsonl`. Empty means in-memory only |
| `-portal-config` | | Portal and self-service JSON config |
| `-verdicts-file` (deprecated alias `-verdicts`) | | Verdicts JSON file shown in the console; written by `halo exp analyze --verdicts-file` or the controller |
| `-trusted-proxy-cidrs` | | Reverse proxies whose `X-Forwarded-For` is trusted for rate limiting |
| `-device-ttl` | `2160h` (90 days) | Device token lifetime after enrollment; expired devices must re-enroll |
| `-dev-insecure-user`, `-dev-insecure-groups`, `-dev-insecure-admin` | | Demo only: disable login and act as this user |
| `-killswitch-key-file` | | ed25519 PKCS#8 PEM private key signing the kill list (`halo keys generate --name killswitch`). Use a dedicated key. Requires `-data-dir`. Without it the kill and unkill endpoints return 501, no kill list is served, `GET /api/v1/capabilities` reports `killSwitch: false`, and the in-process controller reports rollbacks as **not enforced** ("merge urgently": only the pause PR stops traffic). Startup fails if `-killswitch-key-file` is set without `-data-dir` or without `-gateway-token-file` |
| `-gateway-token-file` | | Bearer token (16+ characters) gateways present to `GET /api/v1/gateway/killswitch`. Set with `-killswitch-key-file` or not at all |
| `-controller` | off | Run the automated experiment loop. Requires `-clickhouse-url` and `-data-dir` |
| `-interval` (deprecated alias `-controller-interval`) | `5m` | Controller tick interval; minimum `1m` |
| `-clickhouse-url`, `-clickhouse-database`, `-clickhouse-user`, `-clickhouse-password-file` | | Evidence source |
| `-policy-repo-dir` | | **Dedicated** clone the controller opens PRs from (hard-reset to `origin/<base>` before each PR). Must not be or overlap `-policy-dir`. May be the portal's `policyRepoDir` (then console and controller share that clone and its lock; subdir/base must match the portal's). Without it, no PRs are opened |
| `-policy-repo-subdir`, `-policy-repo-base` | (root), `main` | Policy root inside that clone; PR base branch |
| `-notify-slack-url-file`, `-notify-webhook-url-file`, `-notify-webhook-secret-file` | | Controller notifications; the secret signs generic webhook bodies (`X-Halo-Timestamp` plus `X-Halo-Signature`, [verification](#verifying-the-webhook-signature)) |
| `-metrics-listen` | off | Address serving the controller's `/metrics`. **Unauthenticated**: keep it internal |

`POST /api/v1/experiments/{name}/kill` needs a `reason` (HTTP 422 without one). Kill, unkill, enrollment, session and device revocation and experiment-status PRs fail with HTTP 500 if the audit append fails ([security model](/halos/concepts/security-model/#audit-log)).

Details: [self-service portal](/halos/concepts/self-service-portal/), [API reference](/halos/reference/api/), [experiments](/halos/concepts/experiments/#the-controller-loop).

## `halo-shadow`

Flags: `-policy`, `-listen 127.0.0.1:8090`, `-out pairs.jsonl`, `-pair-key-file`, `-upstream-headers`, `-budget-usd 50`, `-price-in 3`, `-price-out 15`, `-queue 64`, `-workers 4`, `-retention 720h`, `-metrics-listen` (env `HALO_SHADOW_METRICS_LISTEN`; extra address serving only `GET /metrics` without the token, for Prometheus; empty disables). Environment: `HALO_SHADOW_TOKEN` (required); `HALO_SHADOW_AUTH_HEADER` is refused (use `-upstream-headers`).

`halo-shadow decrypt-pairs [-pair-key-file FILE]... PAIRS.jsonl` is an ops command that decrypts a pair file written with `-pair-key-file` and writes plaintext JSONL to stdout; repeat the flag to supply current and retired keys. **Output is plaintext prompts and responses**: handle it accordingly Details: [shadow traffic](/halos/concepts/shadow-traffic/).
