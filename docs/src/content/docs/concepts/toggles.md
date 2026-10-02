---
title: Feature toggles
description: Turn a capability on for a targeted cohort, and kill it fleet-wide, without a new release.
---

A **Toggle** is a named switch with ordered targeting rules. It turns one capability on for a cohort (an MCP server, a hook, an env var, a model route) and can be killed everywhere within one poll interval (about 10 s at gateways, 60 s on devices by default) without cutting a release.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/toggles-light.svg" alt="A feature toggle with ordered targeting rules (ring, group, percentage) resolves to on or off per developer from verified identity, and a signed kill switch turns it off everywhere." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/toggles-dark.svg" alt="A feature toggle with ordered targeting rules (ring, group, percentage) resolves to on or off per developer from verified identity, and a signed kill switch turns it off everywhere." width="880" />

## How a toggle decides

- **Rules run in order; the first match decides.** A rule matches when every condition it sets holds: `rings`, `groups` and `users` each match if the subject is in any listed value, and `percent` keeps that share of the matching subjects. A rule with no conditions matches everyone.
- **`effect`** is `on` (the default) or `off`. When no rule matches, `default` applies.
- **Percent rollouts hash through `internal/assign`** with the salt `halos/toggles/<name>`. A toggle's cohort is therefore independent of the ring and of every experiment. A caller with no subject id never lands in a percent rollout.
- **Identity, not headers.** The subject is the authenticated user, their IdP groups and the ring they resolve to.

## Two axes

| Axis | Payload | Applied by |
|---|---|---|
| `client` | Per-harness fragment: `mcpServers`, `hooks`, `env`, `overrides` | `halod`, from fragments inside the signed release |
| `traffic` | `routes`: model alias to route | `halo-proxy` / `halo-kong`. An experiment's variant route still wins |

Client fragments go through the same adapter and guardrails as a profile. The build fails on a forbidden value (`bypassPermissions`, `danger-full-access`, literal secrets, reserved env prefixes), and an unsupported field becomes a manifest warning. The release's own files are the toggle-off state; the fragments are deltas recorded in the signed manifest, so neither rules nor fragments can change in transit.

## Example

```yaml
# examples/acme-corp/toggles/github-mcp.yaml
apiVersion: halos.dev/v1
kind: Toggle
name: github-mcp
description: GitHub MCP server (issues, PRs) for a slice of the canary ring
owner: ai-platform          # required
expires: "2026-12-31"       # past it, validate warns; `halo toggle stale` lists it
default: false
axis: client
rules:
  - name: ring1-ten-percent
    rings: [ring1-canary]
    percent: 10
client:
  harnesses:
    claude-code:
      mcpServers:
        - name: github
          url: https://api.githubcopilot.com/mcp/
          headers:
            Authorization: Bearer ${GITHUB_MCP_TOKEN}
```

## See what a user gets, and why

```console
$ halo toggle eval --user ana@acme.dev --groups acme-platform-eng --policy-dir examples/acme-corp
user ana@acme.dev  ring ring3-ga  groups [acme-platform-eng]
on  format-hook                  rule platform-eng matched (on)
      rule platform-eng: group ok ([acme-platform-eng] vs [acme-platform-eng])
off github-mcp                   no rule matched; default off
      rule ring1-ten-percent: ring no ("ring3-ga" in [ring1-canary]), percent no (bucket 2056 < 1000 of 10000)
off sonnet-next-route            no rule matched; default off
      rule harness-team: ring no ("ring3-ga" in [ring0-harness-team])
```

The ring is resolved the same way the gateway and the portal resolve it. `--ring` overrides it; `--killed a,b` previews a kill.

## The kill path

```console
$ export HALO_SESSION=...        # admin halo_session cookie; never a flag
$ halo toggle kill github-mcp --server https://halos.acme.example --reason "MCP 5xx storm"
```

1. `halo-server` appends `toggle:github-mcp` to its kill store, with an audit entry, and re-signs the kill list with the kill-list ed25519 key (not the release key).
2. **Traffic toggles**: each gateway polls the signed list and verifies signature, freshness and replay order. A killed toggle drops out of routing on the next poll.
3. **Client toggles**: `halod` polls `/api/v1/fleet/killswitch` with its device token (`killSwitch.interval`, default 60s). A killed toggle is off whatever its rules say, and its files revert to the release's toggle-off content.

No release, no ring move, no PR. `--unkill` clears it. The kill call requires https, or http to a loopback host, because it carries a session cookie.

## In the console

Admins get a **Toggles** page in the [operator console](/halos/concepts/self-service-portal/#operator-console): a searchable list with axis and status filters (on by default, killed, stale), and a detail drawer per toggle. The drawer shows the rules as sentences, what the toggle delivers (names only; header and env values are never sent to the browser), who killed it and why, the history from the audit log, and a **Who gets it?** tester that runs the same evaluator as `halo toggle eval`.

- **Kill / Restore** asks for a reason and takes effect at the next poll, exactly like `halo toggle kill`.
- **Propose change** opens a validated policy PR: default, a rule's percent (`0` matches nobody), rings, groups or users to add or remove, expiry. Nothing changes until a human merges it.

## Commands

| Command | Does |
|---|---|
| `halo toggle list` | Name, axis, owner, default, rule count, expiry; flags stale ones |
| `halo toggle eval --user U [--groups G] [--ring R] [--killed T]` | Per-toggle decision with the full rule trace |
| `halo toggle kill NAME --reason "..." [--unkill]` | Trip or clear the fleet-wide kill through `halo-server` |
| `halo toggle stale` | Toggles past `expires` |

Toggles are temporary by design: `owner` is required, and a toggle without `expires` draws a validation warning. Schema: `schemas/toggle.schema.json`. Related: [experiments](/halos/concepts/experiments/) (the kill list is shared), [security model](/halos/concepts/security-model/).
