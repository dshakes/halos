---
title: Your first 10 minutes
description: Build halo, create a policy repo, render a ring's config, sign and publish a release to a local registry, and see releases in the console.
---

You will go from a fresh checkout to a signed release in a local registry, and see how the console reports releases. Every command below was run as shown; long output is trimmed with `…`.

**Prerequisites:** Go (see `go.mod`), Docker, `curl`, and a checkout of the repo. Installers and Homebrew arrive with the first tagged release, so this builds from source.

## 1. Build the CLI

```console
$ make build
…
$ export PATH="$PWD/bin:$PATH"
```

`bin/` now holds `halo`, `halod`, `halo-server`, `halo-proxy`, `halo-shadow` and `halo-kong`.

## 2. Create a policy repo

```console
$ mkdir /tmp/acme-policy && cd /tmp/acme-policy
$ halo init --org acme
create halos.yaml
next: halo explain --policy-dir .   (the full policy this expands to)
next: halo validate --policy-dir .
$ halo validate
OK: policy valid (0 warnings)
```

`halos.yaml` is the whole policy: Claude Code `2.1.280`, provider `anthropic`, model `claude-sonnet-4-5`, `safety: standard`, `rollout: standard`. `halo explain` prints the gateway, profile and four rings it expands to.

## 3. See who lands where

```console
$ halo whoami --user alice@acme.com --groups acme-ai-platform
user     alice@acme.com
ring     ring0-team
profile  default
variants (none: no running experiment enrolls this user)
$ halo whoami --user zed@acme.com
user     zed@acme.com
ring     ring2-early
profile  default
variants (none: no running experiment enrolls this user)
```

Ring membership is deterministic: a group match wins (`ring0-team`), everyone else is hashed into a percent ring.

## 4. Render a ring's config

```console
$ halo render --ring ring0-team --out rendered --release-version 0.1.0
write rendered/Library/Application Support/ClaudeCode/managed-settings.json
$ grep -E 'bypass|requiredM|BASE_URL' "rendered/Library/Application Support/ClaudeCode/managed-settings.json"
  "disableBypassPermissionsMode": "disable",
    "ANTHROPIC_BASE_URL": "https://ai.acme.example",
  "requiredMaximumVersion": "2.1.280",
  "requiredMinimumVersion": "2.1.280",
```

That file is what `halod` writes on a laptop: bypass mode disabled, the CLI pinned to one version, traffic pointed at your gateway.

## 5. Generate a dev signing key

```console
$ halo keys generate --out keys --name dev
private keys/dev.key (keep secret)
public  keys/dev.pub
```

Keep `dev.key` out of git. In production the key lives in CI or a KMS.

## 6. Publish to a local registry

Port 5000 is often taken on macOS (AirPlay), so this maps the registry to 5055.

```console
$ docker run -d --name halos-registry -p 5055:5000 registry:2
$ halo release publish --ring ring0-team --release-version 0.1.0 \
    --registry localhost:5055/acme/halos --key keys/dev.key --plain-http --no-artifacts
warning: --no-artifacts: halod will not install CLIs from this release unless allowShellInstall is set
Signing ring ring0-team → version 0.1.0 (digest sha256:3743b2fd…, seq 1790824931)
published localhost:5055/acme/halos tags v0.1.0, ring-ring0-team (sha256:3743b2fd…)
$ curl -s localhost:5055/v2/acme/halos/tags/list
{"name":"acme/halos","tags":["ring-ring0-team.pointer","ring-ring0-team","v0.1.0"]}
```

`--plain-http` is for local registries only. `--no-artifacts` builds offline; leave it off in production so `halod` gets hash-pinned install artifacts.

## 7. See releases in the console

The console reads releases from the registry it is configured for, so it will not show the one you just pushed. The playground has its own seeded registry; start it from the repo root and read what the console reports:

```console
$ make demo
…
$ AUTHZ=$(curl -s -c jar -o /dev/null -w '%{redirect_url}' localhost:18080/auth/login)
$ curl -s -b jar -c jar -o /dev/null "$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ&user=alice@acme.com")"
$ curl -s -b jar localhost:18080/api/v1/releases | python3 -c 'import sys,json
for r in json.load(sys.stdin)["rings"]: print(r["ring"], r["digest"][:19], "seq="+str(r["seq"]), "expired="+str(r["expired"]).lower(), "channels="+str(len(r["channels"])))'
ring0-harness-team sha256:37be19a32e9a seq=1790825867 expired=false channels=0
ring1-canary sha256:e0cb6eb950e9 seq=1790825867 expired=false channels=2
ring2-early sha256:58c5b59d5b14 seq=1790825868 expired=false channels=2
ring3-ga sha256:aef1514bf42f seq=1790824986 expired=false channels=0
$ make demo-down
```

Or open `http://localhost:18080`, click **Sign in** and pick `alice@acme.com` to see the same data in the browser. The playground is dev only: the IdP signs in anyone. Clean up your own registry with `docker rm -f halos-registry`.

## What just happened

- `halo init` wrote one `halos.yaml`; `validate`, `whoami` and `render` all work offline from that policy.
- The rendered `managed-settings.json` is the deterministic output of the Claude Code adapter for one ring: same policy in, same bytes out.
- `release publish` built the ring's release, signed it with your ed25519 key, pushed it to the registry and moved the `ring-ring0-team` pointer to it. Tags `v0.1.0` and the ring pointer are the only mutable-looking parts; the release itself is content-addressed.
- The console lists each ring's signed pointer: digest, sequence, expiry and any experiment channels.

## Next

- [Roll out a Claude Code upgrade safely](/halos/tutorials/claude-code-upgrade/)
- [Add a feature toggle](/halos/tutorials/add-a-toggle/)
- [Playground](/halos/getting-started/playground/) and [rings and releases](/halos/concepts/rings-and-releases/)
