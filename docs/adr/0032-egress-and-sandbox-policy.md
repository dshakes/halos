---
title: "ADR-0032: Egress and sandbox policy"
description: One harness-neutral policy for the agent sandbox (mode, writable roots, protected paths) and network egress (default, allow and deny domain lists, presets), rendered into each harness's own mechanism, warned where a harness cannot hold it, and checked on the device by halod and halo doctor.
status: accepted
date: 2026-10-27
---

# ADR-0032: Egress and sandbox policy

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

A coding agent runs shell commands and fetches URLs on the developer's machine with the developer's credentials. Two controls bound what it can do there: a sandbox (what the shell may write and read) and an egress policy (which hosts it may reach). Halos had one sandbox mode (`permissions.sandbox`) and an allowlist (`egress.allowedDomains`) that only Claude Code rendered. Every vendor now ships its own native mechanism, each with different shapes, wildcard rules, scopes and gaps, and none of them is the same file. A security team that writes "no shell egress except our registries, never read `~/.ssh`" had to learn six formats and could not tell which machines held it.

Can one policy say it once, have every harness enforce it with its own mechanism, say plainly where a harness cannot, and verify it on the device?

## Vendor research (checked 2026-10-27)

Primary sources only (each vendor's documentation, or its source where noted). "Not documented" is treated as absent.

| Harness | Sandbox mechanism (managed) | Egress mechanism (managed) | Protected paths | Lock |
|---|---|---|---|---|
| Claude Code | `sandbox.enabled`, `allowUnsandboxedCommands: false`, `failIfUnavailable`, `filesystem.allowWrite`[^c1][^c2] | `sandbox.network.allowedDomains` + `allowManagedDomainsOnly` (refuses other hosts, no prompt), `deniedDomains` (refused in every mode); the WebFetch tool follows `WebFetch(domain:...)` permission rules, not the sandbox[^c1][^c3] | `sandbox.filesystem.denyRead`/`denyWrite` (absolute, `~/`); `Read(...)`/`Edit(...)` deny rules for the file tools[^c2][^c3] | managed settings win |
| Codex | `requirements.toml` `allowed_sandbox_modes`; `managed_config.toml` `sandbox_mode`, `[sandbox_workspace_write] writable_roots`, `network_access` (defaults)[^o1][^o2] | `requirements.toml` `[experimental_network]` `enabled`, `managed_allowed_domains_only`, `domains = {host = "allow" \| "deny"}` (deny wins; `*.x` subdomains only), documented as experimental[^o1][^o3] | `[permissions.filesystem] deny_read` (absolute, `~`, `/**/` globs)[^o1][^o3] | requirements are enforced |
| Gemini CLI | `tools.sandbox` in the system settings file; the `--sandbox` flag and `GEMINI_SANDBOX` take precedence; Seatbelt on macOS, Docker/Podman elsewhere[^g1][^g2] | none per domain (`tools.sandboxNetworkAccess` is a boolean with an undocumented scope)[^g2] | none | default only |
| Copilot CLI | `managed-settings.json` `sandbox.enabled`, `failIfUnavailable`, `allowBypass: false`, `userPolicy.filesystem.readwritePaths`; CLI >= 1.0.93, older clients are blocked while the key is set[^h1] | `sandbox.userPolicy.network.allowedHosts` (non-empty blocks the rest; `*.x` subdomains only), `blockedHosts` (wins; also blocks subdomains), `allowOutbound: false`; on Windows programs must honor the proxy[^h1] | `userPolicy.filesystem.deniedPaths` ("should be absolute")[^h1] | managed values are minimums |
| OpenCode | none (no sandbox key in the config schema)[^p1] | `permission.webfetch` = allow \| ask \| deny for every URL (no patterns in v1)[^p2] | `read`/`edit`/`external_directory` deny patterns[^p2] | managed file wins; `OPENCODE_PERMISSION` overrides it (FACTS.md) |
| Cursor CLI | `sandbox.json` `type` (`workspace_readwrite` \| `workspace_readonly` \| `insecure_none`), per user or per repo; team policy in the admin dashboard[^u1] | `sandbox.json` `networkPolicy {default, allow, deny}` (deny wins; `*.x` includes the apex)[^u1] | `cli-config.json` `Read(glob)` deny rules (per user)[^u2] | no system-wide file |

## Decision drivers

- Invariant 1: no combination of fields may amount to `danger-full-access` or a bypass, and nothing rendered carries a bypass token.
- Invariant 2: every field a harness cannot hold is a release warning naming the harness and the reason, never dropped.
- One meaning: the same host gets the same decision in `halo egress test`, in validation and in every adapter's rendering.
- Enforced over advisory: prefer each vendor's managed, non-overridable key; when only a default exists, render it and say so.
- The device is the truth: managed files are restored byte for byte already; what can still weaken the posture is the user's own config, and that has to be visible.

## Considered options

1. **Extend the profile with `sandbox` and `egress` blocks, render per adapter (chosen).** One model, existing release, unit and loosening machinery.
2. **A Halos egress proxy on every device.** Uniform enforcement, but a new privileged daemon in the data path of every shell command, and it duplicates what four vendors now enforce natively.
3. **Per-harness overrides only.** No shared meaning, no way to answer "is pastebin.com reachable from ring1", and the override allowlist rejects sandbox keys on purpose (ADR-0007).

## Decision outcome

### Policy

```yaml
sandbox:
  mode: workspace-write              # off | workspace-write | read-only (= permissions.sandbox)
  writableRoots: [/opt/build-cache]  # absolute or ~/, beyond the workspace
  protectedPaths: [~/.ssh, ~/.aws, ".env*"]
egress:
  default: deny                      # allow | deny; unset = deny when anything is allowed
  allowedDomains: [ai.acme.example]
  presets: [vcs, package-registries] # model-providers too
  deniedDomains: [pastebin.com]
```

- **Decision.** A deny rule wins over an allow rule; then the allowlist (`allowedDomains` plus presets); then the default. `*.example.com` matches subdomains only, never the apex. `policy.EgressRules.Decide` is the single implementation (validation, `halo egress test`, adapters).
- **Default.** Unset means deny when anything is allowed, which is what `allowedDomains` already meant, so existing policy keeps its meaning and its rendered output.
- **Presets** expand to documented host sets (sources in the guide). They join the allowlist; they never widen a deny.
- **Merge.** Down an `extends` chain and across units, `deniedDomains` and `protectedPaths` union (restrictions accumulate); `allowedDomains`, `presets` and `writableRoots` replace. `sandbox.mode` and `permissions.sandbox` are one setting; set both and they must agree.
- **Per-ring and per-unit.** A ring takes its profile's policy; a ring that needs a different policy points at a profile that extends the baseline. Units overlay `egress` and `sandbox`; switching the default from deny to allow, dropping a denied domain or protected path, or adding a writable root is a loosening (ADR-0018). No new ring field: a second place to state policy would be a second resolution path.

### Validation (bypass-shaped combinations are errors)

- `writableRoots` of `/`, `~` or a glob (the whole disk or home writable), a relative root, a root over or under a protected path, or any root with mode `read-only`.
- Mode `off` with egress rules or sandbox paths: the shell would run outside every rule the profile states.
- A bare `*`, a URL, a port or upper case in a domain list; an unknown preset; `default: allow` together with an allowlist.
- A restricted egress policy that denies the gateway host.
- `sandboxRequired` now accepts `default: deny` as well as an allowlist.

### Rendering

Per the research table. Claude Code turns the sandbox on whenever egress or sandbox paths are set, renders both lists with `allowManagedDomainsOnly`, protected paths into `denyRead`/`denyWrite` and `Read`/`Edit` deny rules, and denied domains into `WebFetch(domain:...)` deny rules. Codex keeps `network_access = false` under default deny (the release check refuses `true`) and enforces domains and `deny_read` in `requirements.toml`. Copilot renders the managed sandbox only for pins >= 1.0.93 (an older pin would lock users out). Gemini renders `tools.sandbox` on macOS only (Seatbelt ships with the OS). OpenCode gets `webfetch` and path deny rules. Cursor gets nothing and a warning that names its per-user files. Everything else is a manifest warning; `TestNoSilentDrop` holds every adapter to that for every new field, and `TestEgressSandboxGolden` pins one policy's output for all six adapters on three OSes.

### Endpoint verification

`harness.ReadPosture` reads, per harness, the managed file (what the release turned on) and the per-user settings that can weaken it: `~/.codex/config.toml` `sandbox_mode = "danger-full-access"`, `~/.gemini/settings.json` `tools.sandbox = false`, `~/.cursor/sandbox.json` `type = "insecure_none"`. `halod` adds each finding to the device report's `drift` as `posture:<harness>: <problem>; fix: <fix>`, so ring posture gates (ADR-0011) see it; it never rewrites a user's file. It reads those files only if they are regular, at most 1 MiB, opened non-blocking (a FIFO cannot hang the cycle), and never echoes their content. `halo doctor` shows the effective posture of every installed harness and adds environment overrides (`GEMINI_SANDBOX=false`, `OPENCODE_PERMISSION`, `CODEX_HOME`).

### `halo egress test`

`halo egress test <url> --ring R [--unit U] [--os O]` prints the decision, the rule that made it and, per harness the profile enables, the mechanism that enforces it and the warnings that qualify it. It exits 1 on deny.

## Consequences

- Good: one policy and one decision function; per-harness gaps are explicit in every release and in `halo egress test`; device drift covers the per-user escape hatches.
- Changed output for existing policies (new releases only; rings keep pointing at what they ship until re-pointed): an allowlist profile now also renders Codex `[experimental_network]` and `network_access = false` (it used to warn as unsupported there) and an extra explanatory Claude Code warning; `permissions.sandbox: workspace-write|read-only` now renders Gemini CLI `tools.sandbox: true` on macOS; a Copilot pin >= 1.0.93 gets the managed sandbox. Claude Code output is unchanged.
- Bad: enforcement depth differs by harness; Gemini CLI and OpenCode cannot limit shell egress at all, and Cursor has no system-wide file. Halos says so; it does not paper over it.
- Bad: Codex's `[experimental_network]` is documented as experimental and the first version that honors it is not documented; older versions ignore the table (their requirements struct ignores unknown keys, so they still start).
- Neutral: presets are data in `internal/policy/egress.go`; changing one changes every release that uses it, through the normal PR and ring flow.

## More information

- Guide: [Egress and sandbox](/halos/guides/egress-and-sandbox/). Facts and per-claim sources: `internal/harness/FACTS.md`.
- **UNVERIFIED** (documented, not observed with the real CLIs): Codex `[experimental_network]` minimum version; Copilot `deniedPaths` `~/` expansion and whether its URL fetches use the sandbox proxy; Gemini `tools.sandboxNetworkAccess` scope; Claude Code resolution of relative managed `sandbox.filesystem` paths; OpenCode 1.19.3 honoring `webfetch` from the managed file. None of these is in `make uat-clis` yet.

[^c1]: https://code.claude.com/docs/en/sandboxing (checked 2026-10-27)
[^c2]: https://code.claude.com/docs/en/settings-reference, "Sandbox settings" and "Sandbox path prefixes" (checked 2026-10-27)
[^c3]: https://code.claude.com/docs/en/permissions, WebFetch and Read/Edit rules (checked 2026-10-27)
[^o1]: https://learn.chatgpt.com/docs/enterprise/managed-configuration, "Configure network access requirements" and "Enforce deny-read requirements" (checked 2026-10-27)
[^o2]: https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/config.schema.json, `SandboxWorkspaceWrite` (checked 2026-10-27)
[^o3]: https://raw.githubusercontent.com/openai/codex/main/codex-rs/config/src/config_requirements.rs, `ConfigRequirementsToml` (`experimental_network` alias, `permissions.filesystem.deny_read`) (checked 2026-10-27)
[^g1]: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/sandbox.md (checked 2026-10-27)
[^g2]: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md, `tools.sandbox`, `tools.sandboxAllowedPaths`, `tools.sandboxNetworkAccess` (checked 2026-10-27)
[^h1]: https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings, `sandbox` (checked 2026-10-27)
[^p1]: https://opencode.ai/config.json (checked 2026-10-21; no sandbox key)
[^p2]: https://opencode.ai/docs/permissions/ (checked 2026-10-27)
[^u1]: https://cursor.com/docs/reference/sandbox.md (checked 2026-10-27)
[^u2]: https://cursor.com/docs/cli/reference/configuration.md and https://cursor.com/docs/cli/reference/permissions.md (checked 2026-10-27)
