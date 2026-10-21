---
title: "ADR-0019: Harness coverage beyond the big four"
description: OpenCode and Cursor CLI get adapters that render only what their vendors document at an admin-controlled location, warn about everything else, and say where enforcement stops.
status: accepted
date: 2026-10-21
---

# ADR-0019: Harness coverage beyond the big four

## Context and problem statement

Halos covered Claude Code, Codex, Gemini CLI and Copilot CLI. Teams also run Cursor CLI (`cursor-agent`) and OpenCode (`opencode`, sst/opencode), and a policy that governs four of six CLIs on a laptop is a policy that governs none of the traffic the other two generate. Both vendors document less admin-controlled configuration than the first four, and neither matches an adapter's usual shape (a root-owned settings file that carries permissions, MCP, models and a gateway). What does an adapter promise when the CLI can enforce only part of a profile, and which CLIs are worth the surface?

## Decision drivers

- Invariants 1 and 2 hold for every adapter: never emit a permission-bypass mode, and warn rather than silently drop a field.
- `halod` runs as root and writes only root-owned paths from the adapter's `Meta`; a signed manifest naming any other path is refused. A per-user file such as `~/.cursor/cli-config.json` cannot be a managed target.
- Every key, path, header and wire must be checked against vendor documentation, the CLI's source or the running binary, and cited in `internal/harness/FACTS.md`. An unverifiable row is warned, not rendered.
- Adding an adapter must not need edits to the gateway, `halod` or the portal beyond what `harness.Meta` already derives.

## Considered options

1. **Adapters that render exactly the verified, admin-controlled subset** and warn on the rest, with the gaps stated in the capability matrix.
2. **Adapters that also write user-level files** (`~/.cursor/cli-config.json`, `~/.config/opencode/opencode.json`) to approximate enforcement. More of the profile lands, but a user can edit or delete it, so it is a default presented as a control, and `halod` would need per-user write paths.
3. **Defer both until the vendors ship fuller enterprise controls.** No false confidence, but the traffic and the version drift go unmanaged and unreported meanwhile.

## Decision outcome

Chosen: **option 1** for both CLIs.

**OpenCode** has a real managed layer: `opencode.json` in `/Library/Application Support/opencode/`, `/etc/opencode/` or `%ProgramData%\opencode`, loaded above user, project and inline config. The adapter renders a `halos` provider (`@ai-sdk/anthropic` or `@ai-sdk/openai`, so the Halos gateway's `/v1/messages` or `/v1/responses` wire; `bedrock-invoke` and `gemini` are refused) with the credential `{env:HALO_GATEWAY_TOKEN}`, `enabled_providers: ["halos"]` as the model allowlist, per-tool `permission` rules in deny-last order, MCP servers and name-based denies, instructions, and `autoupdate: false` when a version is pinned. It declares model lock, permissions, gateway, headers and instructions. It does not declare an MCP allowlist (OpenCode has none) or hooks lock (hooks are plugins). Two limits are warned on every release: the `OPENCODE_PERMISSION` environment variable overrides the managed permission block (observed on 1.19.3), and `--auto` approves every ask. The release check rejects a global allow (`permission: "allow"` or `"*": "allow"`) as the OpenCode form of invariant 1, and checks that every provider points under the gateway and only gateway providers are enabled.

**Cursor CLI** documents one admin-controlled file: the system-wide `hooks.json`. The adapter renders `hooks.items` there (five events, Claude-style tool matchers mapped to Cursor's, an unmappable matcher skips the hook and warns) and declares no capability, because hooks run alongside user and project hooks (no lock). Permissions, MCP, models, rules and telemetry live in per-user files or the team dashboard and are warned, as is the absence of a documented base-URL override. Cursor's installer takes no version argument, so `InstallCommand` is empty, `Meta.Installer` is unset (the portal does not offer it as an installable harness) and `halod` reports that it has no verified artifact; `halo doctor`, `detect_harnesses` and `halo onboard verify` (`cursor-agent -p`) still work.

Wiring: both register in `internal/harness/all`; `knownHarnesses`, the profile schemas and the override allowlist (`opencode`: cosmetic keys only; `cursor-agent`: none) accept them; `opencode` joins `toolProtocols` and `toolVendor`, so `halo validate` checks its start model against `anthropic-messages` (or `gateway.protocols.opencode`) and `halo init` can scaffold it. `cursor-agent` is deliberately absent from `toolProtocols`: the gateway does not route it, like `copilot-cli`. The gateway's UA map recognises `opencode/` from `Meta.UAPrefixes` (recorded: `opencode/1.19.3 ai-sdk/provider-utils/4.0.46 runtime/bun/1.3.14`), so posture and version gates apply to OpenCode traffic; Cursor sends no documented User-Agent and never reaches the gateway.

Amp and Aider were considered for this change and not built: neither was verified against its vendor's documentation or binary here, and an adapter built from memory would break the rule above.

## Consequences

- Good: OpenCode traffic can be routed through the Halos gateway, version-gated, permission-ruled and instruction-seeded with one policy, and its two unenforceable corners are visible in the manifest.
- Good: Cursor hooks (audit, deny, secret scrubbing) are delivered from a root-owned file, with the rest of Cursor's governance honestly pointed at the dashboard.
- Bad: Cursor's row in `halo harnesses` is empty, and its version cannot be installed or pinned by `halod`; teams must keep Cursor current themselves.
- Bad: OpenCode's schema is mid-migration (`permission`/`provider`/`mcp` deprecated for `permissions`/`providers`/`mcp.servers`); the adapter renders the keys 1.19.3 reads and FACTS.md names the re-check when a 2.x reaches `latest`.
- Neutral: neither CLI is in `make uat-clis` yet. Their rows are marked UNVERIFIED where no run exists, and a container smoke test with `halod` is the follow-up that would retire that.

## More information

- `internal/harness/FACTS.md` (OpenCode, Cursor CLI), `internal/harness/opencode`, `internal/harness/cursor`, `internal/release/check.go` (`checkOpenCode`, `checkCursor`), `internal/policy/wires.go`.
- [Harness matrix](/halos/reference/harness-matrix/), [Writing a harness adapter](/halos/guides/new-harness-adapter/).
