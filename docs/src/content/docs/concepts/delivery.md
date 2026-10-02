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
| Dev Container Feature (`features/halos`) | Installs `halod` (sha256-pinned), embeds the release key, runs `halod once --install` at start, optional gateway-only firewall | Strongest: rebuilt from release | **UNVERIFIED** end to end: not built into a real dev container here |
| Coder module (`features/coder`) | Terraform `coder_script` that installs `halod` (sha256-pinned) and runs `halod once --install` | Strong | **UNVERIFIED**: Terraform not executed |
| Codespaces | Prebuilds using the Feature; portal launcher builds a URL | Strong | **UNVERIFIED** |
| `halod` agent | `run` (loop, default every 15m), `once`, `status`; launchd unit, systemd unit | Medium: local admin can stop it | Unit-tested with a fake root; not run as root on real hosts |
| MDM exports (`halo export jamf\|intune\|devcontainer`) | Jamf/Kandji `.mobileconfig` plus a `halod` postinstall; Intune PowerShell script writing the registry policy | Medium: slow, coarse | **UNVERIFIED**: no real Jamf, Kandji or Intune tenant; PowerShell not executed |
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
- Codex, Gemini CLI and Copilot CLI: no CLI-side pin. `halod` and the Feature install the exact version and report drift. Enforcement is Halos's, so a local admin can defeat it.
- **Installs are verified artifacts, not shell scripts.** The release carries, per OS and architecture, an https URL with an exact size and a sha256 (binary) or sha512 integrity (npm tarball). `halod` streams it under a size cap, refuses non-https redirects, checks the hash, and only then renames it into place. npm tarballs install with `--ignore-scripts` and empty user and global npmrc using a root-owned Node. The legacy `installCommand` (`curl | bash`, `npm install -g` with lifecycle scripts) runs only when `allowShellInstall: true` is set in `halod.yaml`, and `halod` logs a warning each time. Offline builds (`halo release build --no-artifacts`) therefore install nothing unless you opt in.

Guides: [dev containers](/halos/guides/dev-containers/), [Coder](/halos/guides/coder-workspaces/), [laptops and MDM](/halos/guides/laptops-mdm/).
