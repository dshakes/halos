---
title: Delivery
description: Environment-as-policy. Dev containers, Coder, Codespaces, the halod agent, MDM and the self-service portal, and why the environment comes first.
---

Delivery gets a verified release onto the machine where the harness runs. Rationale: [ADR-0001](/halos/adr/0001-environment-as-policy/).

## Why this is necessary

Claude Code's server-managed settings are not fetched with Bedrock or a custom `ANTHROPIC_BASE_URL`. On that path configuration must be a file on disk (`managed-settings.json`), an MDM payload, or environment variables. Halos writes those from a signed release.

## Sinks

| Sink | Mechanism | Strength | Verification status |
|---|---|---|---|
| Dev Container Feature (`features/halos`) | Installs `halod` (sha256-pinned), embeds the release key, runs `halod once --install` at start, optional gateway-only firewall | Strongest: rebuilt from release | Built with the devcontainer CLI in CI (pinned CLI and managed settings asserted); firewall option and a published Feature **UNVERIFIED** |
| Coder module (`features/coder`) | Terraform `coder_script` that installs `halod` (sha256-pinned) and runs `halod once --install` | Strong | **UNVERIFIED**: Terraform not executed |
| Codespaces | Prebuilds using the Feature; portal launcher builds a URL | Strong | **UNVERIFIED** in a real Codespace (the Feature and `.devcontainer` build in CI) |
| `halod` agent | `run` (loop, default every 15m), `once`, `status`; launchd unit, systemd unit | Medium: root can stop it, but then loses gateway access on rings with `posture: enforce` | Unit-tested with a fake root; CI runs it as a real launchd daemon (macOS runner) and a SYSTEM scheduled task (Windows runner), and as root in `make uat-clis` containers; not run on real fleets |
| MDM exports (`halo export jamf\|intune\|devcontainer`) | Jamf/Kandji `.mobileconfig` plus a `halod` postinstall; Intune PowerShell script writing the registry policy | Medium: slow, coarse | **UNVERIFIED**: no real Jamf, Kandji or Intune tenant; the Intune script itself is not executed (`install.ps1` and `enroll.ps1` are, in CI) |
| Self-service portal | Launchers and one-time enrollment for the above | n/a | Implemented in `halo-server`; see [portal](/halos/concepts/self-service-portal/) |

<img class="diagram dark:sl-hidden" src="/halos/diagrams/delivery-light.svg" alt="A signed release and pointer reach disposable environments (Dev Container Feature, Coder module, Codespaces prebuild) and laptops (halod, MDM export). Every path verifies pointer and signature: invalid means refuse and keep the last good release; valid means atomic apply and report the digest." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/delivery-dark.svg" alt="A signed release and pointer reach disposable environments (Dev Container Feature, Coder module, Codespaces prebuild) and laptops (halod, MDM export). Every path verifies pointer and signature: invalid means refuse and keep the last good release; valid means atomic apply and report the digest." width="760" />

## Why dev containers are primary

1. **Reproducible and disposable.** Drift is corrected by rebuild, so it does not accumulate.
2. **Egress control.** The reference firewall restricts the workspace to the gateway and the registry (default DROP for IPv4 and IPv6).
3. **Unattended agents live there.** Coder Tasks and CI agents run in environments, not on laptops.
4. **Rollback is a rebuild** from the previous release, or a new pointer.

## Where the files land

`halod` may write only under fixed, per-harness directories (a signed manifest naming anything else is refused). Files must be mode 0644 or tighter.

| Harness | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/` | `/etc/claude-code/` | `C:\Program Files\ClaudeCode\` |
| Codex | `/etc/codex/` (`requirements.toml`, `managed_config.toml`) | `/etc/codex/` | `C:\ProgramData\OpenAI\Codex\requirements.toml` only (no system-wide `managed_config.toml` exists) |
| Gemini CLI | `/Library/Application Support/GeminiCli/settings.json`, `/etc/profile.d/halos-*.sh` | `/etc/gemini-cli/settings.json`, `/etc/profile.d/halos-*.sh` | `C:\ProgramData\gemini-cli\settings.json` |
| Copilot CLI | `/Library/Application Support/GitHubCopilot/managed-settings.json` | `/etc/github-copilot/managed-settings.json` | `C:\Program Files\GitHubCopilot\managed-settings.json` |

Copilot CLI is in `halod`'s write allowlist too (from its adapter's `harness.Meta`), and `make uat-clis` verifies that `halod` writes its managed-settings.json and that the real CLI honours `allowedMcpServers`. Its `disableBypassPermissionsMode` and gateway routing remain UNVERIFIED; dev containers and MDM remain alternative delivery paths. Claude Code also supports MDM keys (`com.anthropic.claudecode` plist, `HKLM\SOFTWARE\Policies\ClaudeCode`).

`halod`'s own footprint is root-owned and fixed per OS:

| | macOS | Linux | Windows |
|---|---|---|---|
| Config | `/Library/Halos/etc/halod.yaml` | `/etc/halos/halod.yaml` | `C:\Program Files\Halos\etc\halod.yaml` |
| State | `/Library/Halos/var/state.json` | `/var/lib/halos/state.json` | `C:\Program Files\Halos\var\state.json` |
| Verified binaries | `/Library/Halos/bin` | `/usr/local/lib/halos/bin` | `C:\Program Files\Halos\bin` |
| npm-tgz artifacts | `/Library/Halos/npm` | `/usr/local/lib/halos/npm` | `C:\Program Files\Halos\npm` |
| Shims | `/usr/local/bin` | `/usr/local/bin` | none: add the bin dir to PATH via MDM |

## Version enforcement

- Claude Code: the release sets `requiredMinimumVersion` and `requiredMaximumVersion`; the CLI refuses to start outside that range.
- Codex, Gemini CLI and Copilot CLI: no CLI-side pin. `halod` and the Feature install the exact version and report drift.
- **The gateway checks the version on every model call.** With `versionGate: enforce` on a ring, `halo-proxy` and `halo-kong` parse the CLI version from the User-Agent and refuse (403) a version the ring does not pin, and a missing or unrecognised User-Agent. For Claude Code this is defence in depth. Copilot CLI's User-Agent is not known, so it counts as unrecognised. Default `warn`: logged and counted, not refused. See [gateway gates](#gateway-gates).
- **Installs are verified artifacts, not shell scripts.** The release carries, per OS and architecture, an https URL with an exact size and a sha256 (binary) or sha512 integrity (npm tarball). `halod` streams it under a size cap, refuses non-https redirects, checks the hash, and only then renames it into place. npm tarballs install with `--ignore-scripts` and empty user and global npmrc using a root-owned Node. The legacy `installCommand` (`curl | bash`, `npm install -g` with lifecycle scripts) runs only when `allowShellInstall: true` is set in `halod.yaml`, and `halod` logs a warning each time. Offline builds (`halo release build --no-artifacts`) therefore install nothing unless you opt in.

## Gateway gates

`halod` runs on a machine the developer administers. The gateway is the part they do not control, so two per-ring policies move enforcement there ([ADR-0011](/halos/adr/0011-gateway-enforced-posture-and-version/)):

| Ring field | Checks | Needs |
|---|---|---|
| `posture: off \| warn \| enforce` | Every enrolled device of the caller reported to `halo-server` within `--posture-max-age` (default 45m), with no drift, on the ring's current release or one of its experiment channels | `halo-server --gateway-token-file`; `halo-proxy` `posture.url` and `posture.tokenFile` (`halo-kong`: `posture_url`, `posture_token`) |
| `versionGate: off \| warn \| enforce` | The User-Agent's CLI version is one the ring pins (its profile or a variant profile of its running client-axis experiment) | Nothing extra |

Both default to `warn`: the request goes through, the request log line carries `gates=`, and `halo_proxy_gate_total{gate,ring,outcome}` counts it (`halo-kong` logs at NOTICE and tags the upstream request `x-halo-gate`). `enforce` answers 403 in the CLI's wire format with the reason and what to do: run `halod status`, make sure `halod` is running and current, retry.

The posture gate fails closed only on a verdict `halo-server` returned. If the server is unreachable, the last verdict serves for `grace` (default 15m, `halo-proxy` `posture.grace`); after that the posture is unknown, the request passes and is counted `outcome="unknown"`. Verdicts are cached per user for `posture.cacheTTL` (default 1m).

So root can still stop `halod` or edit managed config, but on an enforce ring the next report is missing or shows drift, and model access stops until `halod` runs clean again. Revoke devices you retire: a device that stops reporting keeps its user non-compliant.

### Immutable managed files

Set `immutable: true` in `halod.yaml` to have `halod` set the system-immutable flag on every managed file after writing it (`chflags schg` on macOS, `chattr +i` on Linux) and clear it just before a rewrite or removal. Edits then fail even for tools running under `sudo`, until someone clears the flag. A missing tool or permission (some filesystems do not support `chattr +i`; macOS clears `schg` only at securelevel 0) is logged once per run and `halod` carries on. Ignored on Windows.

Guides: [dev containers](/halos/guides/dev-containers/), [Coder](/halos/guides/coder-workspaces/), [laptops and MDM](/halos/guides/laptops-mdm/).
