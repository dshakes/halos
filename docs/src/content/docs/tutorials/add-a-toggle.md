---
title: Add a feature toggle
description: Write a toggle that turns an MCP server on for a slice of a ring, validate it, see who gets it and why, and check what the release records.
---

A [toggle](/halos/concepts/toggles/) turns one capability on for a cohort and can be killed fleet-wide without a release. You will add a Linear MCP server for 25% of `ring1-canary`, watch validation catch a missing expiry and a forbidden value, and look at the fragment the release records. Commands were run against a copy of `examples/acme-corp`.

**Prerequisites:** a built `halo` ([Your first 10 minutes](/halos/tutorials/first-10-minutes/)). Work in a copy: `cp -r examples/acme-corp policy && cd policy`.

## 1. Write the toggle

Create `toggles/linear-mcp.yaml`:

```yaml
apiVersion: halos.dev/v1alpha1
kind: Toggle
name: linear-mcp
description: Linear MCP server for a quarter of the canary ring
owner: ai-platform
default: false
axis: client
rules:
  - name: ring1-quarter
    rings: [ring1-canary]
    percent: 25
client:
  harnesses:
    claude-code:
      mcpServers:
        - name: linear
          url: https://mcp.linear.app/mcp
          headers:
            Authorization: Bearer ${LINEAR_MCP_TOKEN}
    gemini-cli:
      mcpServers:
        - name: linear
          url: https://mcp.linear.app/mcp
```

`${LINEAR_MCP_TOKEN}` is an env reference resolved on the device; a literal secret fails the build.

## 2. Validate

```console
$ halo validate
warning toggles[linear-mcp].expires  no expiry date; toggles are temporary, set expires (YYYY-MM-DD)
OK: policy valid (1 warnings)
```

Add `expires: "2026-12-31"` under `owner`, then:

```console
$ halo validate
OK: policy valid (0 warnings)
$ halo toggle list
format-hook                  client  default=false rules=1 owner=ai-platform expires=2026-11-30
github-mcp                   client  default=false rules=1 owner=ai-platform expires=2026-12-31
linear-mcp                   client  default=false rules=1 owner=ai-platform expires=2026-12-31
sonnet-next-route            traffic default=false rules=1 owner=ai-platform expires=2026-12-15
```

## 3. See who gets it, and why

`dev26` and `dev45` are both in `ring1-canary`; the 25% hash picks one:

```console
$ halo toggle eval --user dev26@acme.com | grep -A1 linear
off linear-mcp                   no rule matched; default off
      rule ring1-quarter: ring ok ("ring1-canary" in [ring1-canary]), percent no (bucket 4542 < 2500 of 10000)
$ halo toggle eval --user dev45@acme.com | grep -A1 linear
on  linear-mcp                   rule ring1-quarter matched (on)
      rule ring1-quarter: ring ok ("ring1-canary" in [ring1-canary]), percent ok (bucket 585 < 2500 of 10000)
$ halo toggle eval --user dev45@acme.com --killed linear-mcp | grep -A2 linear
off linear-mcp                   killed via the signed kill list
      rule ring1-quarter: ring ok ("ring1-canary" in [ring1-canary]), percent ok (bucket 585 < 2500 of 10000)
      kill list: killed
```

The bucket comes from `internal/assign` with a per-toggle salt, so it is independent of ring and experiment assignment. `--killed` previews a kill without touching a server.

## 4. See what the release records

```console
$ halo release build --ring ring1-canary --release-version 0.1.0 --no-artifacts -o rel.tar
built rel.tar (sha256:1067b5d5…)
$ tar -xOf rel.tar manifest.json | python3 -c 'import sys,json
m=json.load(sys.stdin); t=[t for t in m["toggles"] if t["name"]=="linear-mcp"][0]
print(t["rules"]); print({h:v["linux"][0]["path"] for h,v in t["fragments"].items()})'
[{'name': 'ring1-quarter', 'rings': ['ring1-canary'], 'percent': 25}]
{'claude-code': '/etc/claude-code/managed-mcp.json', 'gemini-cli': '/etc/gemini-cli/settings.json'}
```

The signed manifest holds the rules and one content-addressed fragment per harness and OS. The release's ordinary files are the toggle-off state; `halod` layers the fragment on top only for users the rules turn on. Warnings live in the same manifest, and `format-hook` shows what an ineffective fragment looks like: `toggle format-hook: codex/darwin: fragment changes nothing (already in the profile, or unsupported by the adapter)`.

## 5. Try a forbidden value

Toggle fragments go through the same guardrails as a profile. Add an `env` block to `claude-code` that sets `ANTHROPIC_BASE_URL`:

```console
$ halo validate
error   toggles[bad].client.harnesses.claude-code.env.ANTHROPIC_BASE_URL  env prefix ANTHROPIC_ is reserved for the renderer
1 errors, 0 warnings
$ echo $?
2
```

`halo release build` refuses the same policy (`error: policy has validation errors`). Remove the file to continue.

## What just happened

- `validate` enforced the toggle contract: an `owner`, an `expires` date (a warning when missing), and the profile guardrails on every fragment.
- `toggle eval` re-ran the targeting rules exactly as the gateway and `halod` do, with the hash bucket in the trace.
- The release recorded rules and fragments in its signed manifest, so neither can change in transit. Nothing is on or off for anyone until you publish a release and `halod` pulls it.
- Turning it off later takes a kill, not a release: [Kill a bad change in 10 seconds](/halos/tutorials/kill-a-bad-change/).

## Next

- [Feature toggles](/halos/concepts/toggles/) for rule semantics and the traffic axis
- `halo toggle stale` lists toggles past `expires`; delete them when the rollout is done
- [Canary a new model](/halos/tutorials/canary-a-model/) uses a traffic toggle
