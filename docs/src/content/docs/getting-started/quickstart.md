---
title: Quickstart
description: Build Halos, run the traffic-plane demo, then publish, promote and roll back a signed release against a local registry.
---

Every command on this page was run against this repository. Upstreams are mocks; no model provider, cloud account or real Kong Enterprise is involved.

## Prerequisites

- Go 1.25+
- Docker with Compose v2
- `curl`
- Free host ports 8080 (Kong), 8081 (mock IdP), 8090 (halo-shadow) and 5055 (local registry, part 2). If 8080 or 8081 are taken, set `HALO_PORT` / `HALO_IDP_PORT` and use those numbers below.

## Part 0: your policy in one file

```bash
git clone https://github.com/dshakes/halos && cd halos
make build
export PATH="$PWD/bin:$PATH"

halo init --policy-dir /tmp/my-policy --org acme
halo validate --policy-dir /tmp/my-policy
halo explain --policy-dir /tmp/my-policy --kind ring
```

**Check:** `halo init` prints `create /tmp/my-policy/halos.yaml` (plus two `next:` hints) and writes no other file: that one file is the whole policy ([simple mode](/halos/concepts/simple-mode/)). `halo validate` prints `OK: policy valid (0 warnings)`. `halo explain` prints the four rings the `standard` rollout preset expands to (`ring0-team`, `ring1-canary` 5%, `ring2-early` 25%, `ring3-ga`), each marked `# source: halos.yaml (simple mode)`.

The rest of this page uses `examples/acme-corp`, a full-mode repo with every document written out, because it exercises more of the stack. `halo init --full` scaffolds that style.

## Part 1: the traffic plane

### 1. Build and inspect the policy

```bash
halo validate --policy-dir examples/acme-corp
halo whoami --policy-dir examples/acme-corp --user alice@acme.com --groups ai-platform
halo exp list --policy-dir examples/acme-corp
```

**Check:** `halo validate` prints `OK: policy valid (0 warnings)` and exits 0 (it exits 2 on errors, for example if a profile enables `bypassPermissions`). `halo whoami` prints `ring     ring0-harness-team`. `halo exp list` shows three experiments.

See what a ring would write to a Linux machine, with the adapters' warnings on stderr:

```bash
halo render --policy-dir examples/acme-corp --ring ring1-canary --os linux --out /tmp/rendered
find /tmp/rendered -type f
```

**Check:** files appear under `/tmp/rendered/etc/claude-code/`, `/etc/codex/` and `/etc/gemini-cli/`, mirroring the absolute paths `halod` would write. Warnings such as `codex: profile field "hooks.items" is not supported and was not rendered` are expected: adapters warn instead of silently dropping settings.

### 2. Start the stack

```bash
cd deploy/compose
docker compose up -d --build
docker compose ps
```

This starts five services: Kong with the `halo-kong` plugin, a mock OIDC provider, two mock upstreams (`orch-mock`, `anthropic-mock`) and `halo-shadow`. There is no OTEL collector, ClickHouse or Grafana in this compose file. **Check:** all five services are `Up`.

Prefer no Kong? `docker compose -f docker-compose.halo-proxy.yml up -d --build` runs the same demo with `halo-proxy` in Kong's place (the Kong variant is the one shown below).

### 3. Send requests

The mock IdP issues a signed JWT for any user and group list. Identity is verified by the gateway from that token; nothing the client claims in a header is believed.

```bash
TOK=$(curl -s 'localhost:8081/token?user=alice@acme.com&groups=ai-platform')
curl -s localhost:8080/v1/messages \
  -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -H 'x-claude-code-session-id: s1' \
  -H 'x-halo-ring: ring3-ga' \
  -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
```

Output (formatted):

```json
{"content":[{"text":"served-by=orch model=us.anthropic.claude-sonnet-4-5-v1:0 path=/v1/messages headers=map[anthropic-version:2023-06-01 x-halo-release:sha256:ring0 x-halo-ring:ring0-harness-team]","type":"text"}],"id":"msg_mock","model":"us.anthropic.claude-sonnet-4-5-v1:0","role":"assistant","type":"message","usage":{"input_tokens":12,"output_tokens":34}}
```

**Check:** the mock echoes what the *upstream* received. The spoofed `x-halo-ring: ring3-ga` is gone; the ring is `ring0-harness-team`, derived from Alice's verified group. The alias `sonnet` was rewritten to the upstream model id. The `x-halo-*` stamps are added to the upstream request; they are not echoed to the client as response headers.

More requests to try:

| Try | Expect |
|---|---|
| Token for `bob@acme.com`, groups `eng` | GA ring; he lands in the `sonnet-direct-canary` experiment (`x-halo-variant:control` or the canary variant) |
| `-d '{"model":"gpt-4o",...}'` (not a policy alias) | 400 `invalid_request_error`: `model "gpt-4o" is not permitted by the Halos gateway policy; allowed models: haiku, sonnet`. Never forwarded |
| `curl -N` with `"stream":true` | Server-sent events arrive incrementally |
| `POST /model/sonnet/invoke` | Path rewritten to the Bedrock model id |
| No, forged or expired token | Both gateways: 401 `authentication_error` (`halo-kong` falls back to default routing only with `allow_unverified`) |

The compose policy (`deploy/compose/policy.json`) is hot-reloaded by mtime, so editing it moves users between rings without a restart. After editing routes or upstreams, regenerate Kong's config with `go run ./deploy/compose/gen` and `docker compose restart kong`.

### 4. Look at shadow pairs

`sonnet-next-shadow` samples 100% of first-turn requests in this demo, so pairs appear immediately.

```bash
curl -s -H 'X-Halo-Shadow-Token: dev-only-token' localhost:8090/metrics | grep '^halo_shadow'
docker compose exec -T halo-shadow tail -n 1 /data/pairs.jsonl
```

**Check:** `halo_shadow_*` counters (for example `halo_shadow_errors_total`) are present and `pairs.jsonl` has control/candidate pairs. halo-shadow stops at a $5 estimated spend in this demo.

### 5. Clean up

```bash
docker compose down -v
```

## Part 2: sign, promote and roll back a release

This uses a local OCI registry, so nothing leaves your machine. Run from the repository root.

```bash
docker run -d --rm --name halo-reg -p 127.0.0.1:5055:5000 registry:2
REG=localhost:5055/acme/halos

halo keys generate --name demo --out .          # demo.key (private), demo.pub (public)
export XDG_STATE_HOME="$PWD/.demo-state"         # keep the demo's signer state out of ~/.local/state
```

Every signing command records the last pointer it wrote in a signer state file (`$XDG_STATE_HOME/halos/pointers.json`) and refuses a registry that serves an older one. Pointing it at a throwaway directory lets you reset the demo registry later without tripping that check.

Publish a release for `ring0-harness-team`. `--no-artifacts` skips resolving vendor CLI download artifacts so the demo runs offline; `halod` would then refuse to install CLIs from this release (see [installation](/halos/getting-started/installation/)).

```bash
halo release publish --policy-dir examples/acme-corp --ring ring0-harness-team --release-version 1.0.0 \
  --registry $REG --key demo.key --plain-http --no-artifacts
```

**Check:** stderr shows `Signing ring ring0-harness-team → version 1.0.0 (digest sha256:..., seq ...)` before the pointer is signed, then stdout `published localhost:5055/acme/halos tags v1.0.0, ring-ring0-harness-team (sha256:...)`.

Point `ring1-canary` at the same release, then publish a newer release for `ring1-canary`:

```bash
halo release promote --from-ring ring0-harness-team --to-ring ring1-canary \
  --registry $REG --key demo.key --plain-http
halo release publish --policy-dir examples/acme-corp --ring ring1-canary --release-version 1.1.0 \
  --registry $REG --key demo.key --plain-http --no-artifacts
```

**Check:** `ok promoted ring-ring1-canary: version 1.0.0, seq ..., digest sha256:..., expires ...`. The source is `ring0-harness-team`'s signed pointer, not its `ring-` tag. Each ring is served by a *signed pointer* carrying `seq` and a 7-day expiry; see [rings and releases](/halos/concepts/rings-and-releases/).

Diff what a ring would get against a published release:

```bash
halo plan --policy-dir examples/acme-corp --ring ring1-canary \
  --against "${REG}:ring-ring0-harness-team" --registry $REG --pubkey demo.pub --plain-http
```

**Check:** the plan lists per-harness changes, for example `harness claude-code: version 2.1.312 -> 2.1.280`.

Roll `ring1-canary` back to `1.0.0` and re-sign a pointer:

```bash
halo rollback --ring ring1-canary --to 1.0.0 --registry $REG --key demo.key --plain-http
halo release refresh --ring ring1-canary --registry $REG --key demo.key --plain-http
```

**Check:** both print `ok ...` with a higher `seq` than before. Rollback is a *new* signed pointer with a higher `seq` naming the older digest, so it works for `halod` clients that refuse to go backwards. `--to 1.0.0` only succeeds because the release at tag `v1.0.0` carries version `1.0.0` in its signed manifest.

```bash
docker rm -f halo-reg
rm -rf .demo-state
```

If you reset the registry without removing the state, the next `publish` is refused with `ring ... has no pointer but ... records seq N ... registry reset or tag deleted? refusing`. That is the replay check working; for a throwaway registry, delete the state file.

`halod` itself was not run here: it must run as root against root-owned files. See [laptops and MDM](/halos/guides/laptops-mdm/) and [production deployment](/halos/guides/production-deployment/).
