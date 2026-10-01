---
title: A/B a CLI upgrade
description: Run a client-axis A/B of a new Claude Code (or Codex, Gemini CLI) version on a slice of a ring, end to end, with signed channels and rollback.
---

**Axis:** client. **Type:** `ab`. Half of a ring keeps the current CLI pin (control) and half gets the new one (treatment). Each device learns its variant from the signed ring release, pulls that variant's signed channel, and reports it. Background: [client-axis delivery](/halos/concepts/experiments/#client-axis-delivery).

The example repo ships the pieces: `examples/acme-corp/experiments/claude-cli-2.1.3xx-ab.yaml` (enrolls `ring1-canary` and `ring2-early`) with profiles `engineering` (control, Claude Code 2.1.280) and `engineering-next` (treatment, 2.1.312).

<img class="diagram dark:sl-hidden" src="/halos/diagrams/cli-upgrade-flow-light.svg" alt="Pin a new CLI version in a profile, validate, run evals, and on pass publish ring1-canary with a ring release and two channels. halod picks the variant and pulls its channel. A promote verdict opens a PR setting the ring profile to treatment and concluding; a breach pauses and republishes or runs halo rollback." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/cli-upgrade-flow-dark.svg" alt="Pin a new CLI version in a profile, validate, run evals, and on pass publish ring1-canary with a ring release and two channels. halod picks the variant and pulls its channel. A promote verdict opens a PR setting the ring profile to treatment and concluding; a breach pauses and republishes or runs halo rollback." width="760" />

The commands below were run against a local registry, `halo`, and a test build of `halod`. They were not run against a live fleet or the telemetry pipeline (**UNVERIFIED** at fleet scale).

## 0. Setup for a local try-out

```bash
docker run -d --rm --name halo-reg -p 127.0.0.1:5055:5000 registry:2
halo keys generate --out keys          # keys/halo.key, keys/halo.pub
P=examples/acme-corp
REG=localhost:5055/acme/halos
```

Against a real registry drop `--plain-http` and use your `ghcr.io/...` repository.

## 1. Pin the new version and validate

```yaml
# profiles/engineering-next.yaml
apiVersion: halos.dev/v1alpha1
kind: Profile
name: engineering-next
extends: engineering
harnesses:
  claude-code: {version: 2.1.312}
```

```bash
halo validate $P
```

**Check:** `OK: policy valid`. A client-axis variant profile is held to the ring profile by **errors**, not warnings: exact version pins, telemetry on, `permissions.disableBypass`, nothing widened, no MCP changes, no weaker sandbox or `managedOnly`/`enforce`, no more permissive `permissions.mode`, only hooks the ring already has, the ring's telemetry endpoint and `logPrompts`, a models list that stays inside the ring's, and identical `instructions` and `env`. Only one running client-axis experiment may enroll a ring. Full list: [variant guardrails](/halos/concepts/experiments/#variant-guardrails).

For Claude Code the release sets `requiredMinimumVersion` and `requiredMaximumVersion` to the pin, so the CLI refuses other versions. For Codex and Gemini CLI, `halod` installs the pin from a verified artifact and reports drift; their CLI metrics are not attributed to the experiment ([attribution](/halos/concepts/experiments/#attribution)).

## 2. Eval gate

```bash
halo eval run evals/suites/cli-upgrade.yaml --output json > scorecard.json
```

Runs use Docker images `ghcr.io/dshakes/eval-<harness>:<version>` (a placeholder until images are published), no network by default, and `--pass-env` to forward only the credentials the agent step needs. **Check:** no regression beyond your thresholds. See [writing evals](/halos/guides/writing-evals/).

## 3. Start the experiment and publish

The example experiment is `status: running`; to start a paused one use `halo exp start claude-cli-2.1.3xx-ab --policy-dir $P`. Publish the ring:

```bash
halo release publish --policy-dir $P --ring ring1-canary --release-version 2.1.300 \
  --registry $REG --key keys/halo.key --plain-http --no-artifacts
```

`--no-artifacts` builds offline; in production leave it off so `halod` gets verified install artifacts. Output (one signed release per variant, then the ring):

```text
published localhost:5055/acme/halos tags v2.1.300, ring-ring1-canary (sha256:1ac9...)
  channel experiment claude-cli-2.1.3xx-ab variant control: tags v2.1.300-x-claude-cli-2.1.3xx-ab.control, ring-ring1-canary.x-claude-cli-2.1.3xx-ab.control (sha256:b085...)
  channel experiment claude-cli-2.1.3xx-ab variant cli-next: tags v2.1.300-x-claude-cli-2.1.3xx-ab.cli-next, ring-ring1-canary.x-claude-cli-2.1.3xx-ab.cli-next (sha256:7470...)
```

**Check:** a `channel` line per variant. With `--output json`, `channels` lists `ring1-canary.x-claude-cli-2.1.3xx-ab.control` and `...cli-next`. Channels and the ring's signed `experiments` section: [rings and releases](/halos/concepts/rings-and-releases/#experiment-channels).

## 4. See who gets what

```bash
halo whoami --policy-dir $P --user dev45@acme.com    # ring1-canary, claude-cli-2.1.3xx-ab = cli-next
halo whoami --policy-dir $P --user dev26@acme.com    # ring1-canary, claude-cli-2.1.3xx-ab = control
```

**Check:** the variant line. This is the function the gateway and `halod` both use, so it predicts what each device applies. Those two user ids are in `ring1-canary`, one per variant, for the example policy.

## 5. A device picks its variant

An enrolled device gets its ring and subject (the user id) from halo-server's ring endpoint. For a device without an endpoint (MDM-managed, or this try-out) set both in `halod.yaml`:

```yaml
registry: localhost:5055/acme/halos
org: acme-corp
pubkey: /etc/halos/release.pub
ring: ring1-canary
subject: dev45@acme.com        # MDM: template the user id here
plainHTTP: true                # local registry only
```

```bash
sudo halod once --config /etc/halos/halod.yaml
sudo halod status --config /etc/halos/halod.yaml
```

Expected for `dev45` (`dev26` shows `control`, pin 2.1.280):

```json
{ "ring": "ring1-canary", "experiment": "claude-cli-2.1.3xx-ab", "variant": "cli-next", ... }
```

**Check:** `status` has `experiment` and `variant`, and on Linux `/etc/claude-code/managed-settings.json` has `requiredMinimumVersion` and `requiredMaximumVersion` equal to `2.1.312` and `OTEL_RESOURCE_ATTRIBUTES` containing `halo.experiment=claude-cli-2.1.3xx-ab,halo.variant=cli-next`. The same attributes label Claude Code's OTEL metrics, which is how `halo exp analyze` splits arms.

If the device has no subject, `halod` applies the ring release and reports `no_subject_for_experiment` (exit non-zero). If the variant channel fails verification, it keeps the last-good release and does not fall back to control.

## 6. Keep pointers fresh

```bash
halo release refresh --ring ring1-canary --registry $REG --key keys/halo.key --plain-http
```

```text
ok refreshed ring-ring1-canary: version 2.1.300, seq ..., digest sha256:1ac9..., expires 2026-10-07T22:54:14Z
ok refreshed ring-ring1-canary.x-claude-cli-2.1.3xx-ab.control: version 2.1.300-x-claude-cli-2.1.3xx-ab.control, seq ...
ok refreshed ring-ring1-canary.x-claude-cli-2.1.3xx-ab.cli-next: version 2.1.300-x-claude-cli-2.1.3xx-ab.cli-next, seq ...
```

Before each signature, stderr prints `Signing ring <ring or channel> → version V (digest D, seq S)`, one line per pointer. `refresh` also refuses a pointer that has expired and, through the signer state file (`--state-file`, default `$XDG_STATE_HOME/halos/pointers.json`), a registry that serves an older pointer than this signer wrote; see [pointer refresh](/halos/guides/production-deployment/#pointer-refresh).

**Check:** one line for the ring and one per channel. Run it daily, like any ring: a channel pointer expires after 7 days too. Client-axis changes apply on the next `halod` pull (15 minutes by default), so allow for lag when choosing `maxDays`.

## 7. Decide

```bash
halo exp analyze claude-cli-2.1.3xx-ab --policy-dir $P --clickhouse http://clickhouse:8123
halo exp promote claude-cli-2.1.3xx-ab --policy-dir $P --clickhouse http://clickhouse:8123 \
  --ring ring2-early --release sha256:... --dry-run     # drop --dry-run to open the PR
```

To ship the treatment, a human merges a change that points the ring's profile at `engineering-next` (and sets the experiment `concluded`), then publishes the ring. `halo release promote --from-ring A --to-ring B` points B at the release A's **signed pointer** names and moves **only the ring pointer**: A's experiment channels stay with A, and B's devices get the release as control.

## 8. Stop or roll back

| Goal | Command | Effect on devices |
|---|---|---|
| Stop the experiment | `halo exp pause claude-cli-2.1.3xx-ab --policy-dir $P`, merge, then `halo release publish ... --release-version 2.1.301` | The new ring release lists no experiment and no channels; devices converge to it on their next pull |
| Undo a release | `halo rollback --ring ring1-canary --to 2.1.300 --registry $REG --key keys/halo.key --plain-http` | Ring and every channel re-point to the snapshot published with 2.1.300, each with a higher `seq`. `--to <version>` is refused unless the release's signed manifest carries that version; `--to sha256:<manifest digest>` is content-addressed |
| Stop it now | [Kill switch](/halos/concepts/experiments/#kill-switch) | See below |

**Check (pause):** after `halod once`, `status` has no `experiment` and `halo.release=2.1.301` appears in `OTEL_RESOURCE_ATTRIBUTES`. **Check (rollback):** the output has `ok rolled back` for the ring and each channel.

### Kill switch on devices

Gateways read the signed kill list and stop attributing a killed client-axis experiment immediately. A device reverts to the ring release (control) only if its `halod.yaml` enables the kill list; it polls the list every minute by default and does not wait for a republish:

```yaml
killSwitch:
  pubkey: /etc/halos/killswitch.pub   # the kill-switch key, not the release key
  # url: defaults to <ringEndpoint origin>/api/v1/fleet/killswitch
  # interval: 60s
```

It needs `deviceToken` or `deviceTokenFile` (the endpoint is device-authenticated). Enrollment does not add this block; add it to the `halod.yaml` you distribute. `status` then shows `"killed": true` for the experiment. Unkilling returns the device to its variant at the next poll. Without `killSwitch` configured, a kill reaches gateways only, and devices revert on pause and republish.

The ClickHouse steps need the telemetry pipeline running (`halo telemetry collector-config`).
