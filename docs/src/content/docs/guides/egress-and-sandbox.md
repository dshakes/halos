---
title: Egress and sandbox
description: Write one sandbox and network egress policy, have every harness enforce it with its own native mechanism, see where a harness cannot, and verify it on each device.
---

A coding agent runs shell commands and fetches URLs with the developer's credentials. Halos lets you state two limits once, in the profile: what the agent's shell may write and read (the **sandbox**) and which hosts it may reach (**egress**). Each adapter renders them into the harness's own managed settings. What a harness cannot hold becomes a release warning, and `halod` and `halo doctor` check the device ([ADR-0032](/halos/adr/0032-egress-and-sandbox-policy/)).

## Write the policy

```yaml
# profiles/base.yaml
permissions:
  sandbox: workspace-write          # or sandbox.mode; off | workspace-write | read-only
sandbox:
  writableRoots: [/opt/build-cache] # absolute or ~/, beyond the workspace
  protectedPaths: ["~/.ssh", "~/.aws", ".env*"]
egress:
  allowedDomains: [ai.acme.example, otel.internal.acme.example]
  presets: [vcs, package-registries]
  deniedDomains: [pastebin.com, transfer.sh]
  # default: deny                   # implied: something is allowed
```

How a host is decided, everywhere (validation, `halo egress test`, every adapter):

1. A `deniedDomains` match denies. Deny always wins.
2. An `allowedDomains` or preset match allows.
3. Otherwise `default` decides. Unset means `deny` when anything is allowed, else `allow`.

`github.com` matches only that host. `*.github.com` matches every subdomain, never `github.com` itself. Domains are lower case, with no scheme, port, path or bare `*` (use `default: allow` for that).

### Presets

| Preset | Hosts | Sources |
|---|---|---|
| `package-registries` | `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `proxy.golang.org`, `sum.golang.org`, `index.crates.io`, `static.crates.io`, `repo.maven.apache.org`, `rubygems.org` | [Copilot allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference), [Go modules reference](https://go.dev/ref/mod), [Cargo registry index](https://doc.rust-lang.org/cargo/reference/registry-index.html), [PyPI integration guide](https://warehouse.pypa.io/api-reference/integration-guide.html) |
| `vcs` | `github.com`, `api.github.com`, `codeload.github.com`, `*.githubusercontent.com`, `gitlab.com`, `bitbucket.org` | [Copilot allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference), [Cursor run modes](https://cursor.com/docs/agent/security/run-modes.md) |
| `model-providers` | `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.githubcopilot.com`, `*.githubcopilot.com` | [Claude Code network config](https://code.claude.com/docs/en/network-config), [Codex managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration), [Gemini API](https://ai.google.dev/api), [Copilot managed settings](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings) |

Behind a Halos gateway you rarely need `model-providers`: the harnesses call the gateway host, which a restricted policy must allow anyway.

### What validation refuses

These amount to a bypass (invariant 1) and are errors:

- a writable root of `/`, `~`, a glob, a relative path, a home directory (`/Users/alice`, `/home/bob`, `/root`), a system directory or an ancestor of one (`/etc`, `/usr`, `/var`, `/Users`, `/home`, `/System`, `/Library`), anything under `/etc` or `/usr`, or one over or under a protected path (case-insensitive, and `/Users/alice/.ssh` counts as `~/.ssh`); any writable root with mode `read-only`;
- sandbox mode `off` together with egress rules, protected paths or writable roots;
- `default: allow` together with `allowedDomains` or `presets`;
- an egress policy that denies the gateway host;
- `sandbox.mode` and `permissions.sandbox` set to different values.

### Rings and units

A ring uses its profile's policy. For a ring that needs more (say ring0 may reach a staging registry), point it at a profile that `extends` the baseline and adds the host; `halo validate` warns that the child widens its parent. A unit overlay (ADR-0018) may add `deniedDomains` and `protectedPaths` and narrow the allowlist. Switching the default to `allow`, dropping a denied domain or protected path, or adding a writable root is a loosening and fails validation.

## What each harness enforces

Rendered from the policy above; `halo release build` lists the rest as warnings, and `halo harnesses` shows the `sandbox` and `egress` capabilities.

| Harness | Sandbox | Shell egress | Fetch tool | Protected paths | Notes |
|---|---|---|---|---|---|
| Claude Code | `sandbox.enabled`, no unsandboxed retry, `filesystem.allowWrite` | `sandbox.network.allowedDomains` + `allowManagedDomainsOnly`, `deniedDomains` | `WebFetch(domain:...)` deny rules; unlisted hosts still prompt | `filesystem.denyRead`/`denyWrite` (absolute, `~/`) and `Read`/`Edit` deny rules | `read-only` renders as workspace-write. No sandbox on native Windows. |
| Codex | `requirements.toml` `allowed_sandbox_modes`; `writable_roots` (default) | `requirements.toml` `[experimental_network]` `allowed_domains`/`denied_domains` (documented experimental) | not covered | `[permissions.filesystem] deny_read`, absolute and `~/` paths only (reads; codex >= 0.122.0) | With an allowlist, `network_access` is left to the user (off by default); once on, sandboxed commands reach only the allowed hosts. Checked against codex 0.99.0 and 0.166.0. |
| Copilot CLI | managed `sandbox` with `allowBypass: false`, `readwritePaths` | `userPolicy.network.allowedHosts`/`blockedHosts`, `allowOutbound: false` | not documented | `userPolicy.filesystem.deniedPaths` (absolute) | Needs CLI >= 1.0.93; an older pin renders nothing (it would lock users out). Windows relies on programs honoring the proxy. |
| Gemini CLI | `tools.sandbox: true` on macOS (Seatbelt) | none | none | none | A default: `--sandbox` and `GEMINI_SANDBOX` override it, and any `SANDBOX` variable skips it. The default Seatbelt profile (`permissive-open`) leaves network open. Linux and Windows need Docker or Podman; not rendered there. Gemini CLI ignores a system settings file that is not root-owned. |
| OpenCode | none | none | `permission.webfetch`: `deny` when nothing is allowed, else `ask` | `read`/`edit`/`external_directory` deny rules | No sandbox; bash is unconfined. `OPENCODE_PERMISSION`, or an agent's `permission.webfetch` in user config, overrides the managed rule. |
| Cursor CLI | not rendered | not rendered | not rendered | not rendered | `sandbox.json` and `cli-config.json` are per user or per repo only; set the team sandbox policy in Cursor's admin dashboard. |

Sources and the claims not yet observed with the real CLIs are in the ADR and in `internal/harness/FACTS.md`.

## Ask about a host

```console
$ halo egress test https://pastebin.com/raw/x --ring ring3-ga   # claude-code and codex caveat lines trimmed
DENY pastebin.com  (ring ring3-ga, profile engineering)
rule   egress.deniedDomains pastebin.com
  claude-code   enforced: sandbox.network allowedDomains/deniedDomains for Bash, WebFetch(domain:...) deny rules for the fetch tool
  codex         enforced: requirements.toml [experimental_network] for sandboxed commands
  gemini-cli    not enforced
                  - gemini-cli: profile field "egress.deniedDomains" is not supported and was not rendered
```

`--unit` applies a unit's overlays; `--os` picks the platform the per-harness rendering assumes; `--output json` returns the decision, rule, resolved rules and per-harness detail. It exits 1 on deny, so a CI step can assert a host stays blocked.

## Verify on the device

`halod` already restores every managed file it owns. What can still weaken the posture is the user's own configuration, which halod reports and never rewrites. When the managed file turns the sandbox or egress on, these become `drift` in the device report, each as `posture:<harness>: <problem>; fix: <fix>`:

| Harness | Per-user setting reported |
|---|---|
| Codex | `~/.codex/config.toml` `sandbox_mode = "danger-full-access"`, top level or in any `[profiles.<name>]` |
| Gemini CLI | `~/.gemini/settings.json` `tools.sandbox = false` |
| Cursor CLI | `~/.cursor/sandbox.json` `type = "insecure_none"` (always checked) |

Because it is drift, a ring with `posture: enforce` (ADR-0011) refuses such a device at the gateway until it is fixed. halod reads these files as root, so it reads only regular files up to 1 MiB, opens them without blocking, and never logs their content. A project's own `.codex/config.toml` and command-line flags (`-s`, `-c`, `--profile`) are beyond halod's reach: there only `requirements.toml` `allowed_sandbox_modes` (codex >= 0.77.0) holds.

`halo doctor` prints the effective posture of every installed harness, plus environment overrides it can see (`GEMINI_SANDBOX=false`, `SANDBOX`, `OPENCODE_PERMISSION`, `CODEX_HOME`):

```console
$ halo doctor
ok   posture/claude-code      sandbox: on (managed); egress: default deny, 19 allowed, 2 denied (managed)
ok   posture/codex            sandbox: modes [read-only workspace-write] (managed); egress: default deny, 19 allowed, 2 denied (managed)
warn posture/codex            ~/.codex/config.toml sets sandbox_mode = "danger-full-access"
                              fix: remove sandbox_mode from ~/.codex/config.toml; requirements.toml refuses it on codex >= 0.77.0, older versions run unsandboxed
```
