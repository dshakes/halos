---
title: "ADR-0001: Environment as policy"
description: Deliver AI tool configuration by defining the environment, not by chasing laptops.
status: accepted
date: 2026-09-30
---

# ADR-0001: Environment as policy

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

Claude Code's server-managed settings are not fetched when traffic goes through Bedrock or a custom `ANTHROPIC_BASE_URL`, which is exactly the gateway topology this project targets. Configuration must therefore arrive as files (`managed-settings.json`, `managed-settings.d/`), MDM profiles, or environment variables. Laptop agents and MDM are weak enforcement points: the user is often local admin, MDM is slow, and drift is common. Meanwhile a growing share of AI-assisted work runs in dev containers, Codespaces and Coder workspaces, and unattended agents (Coder Tasks, CI) run only there.

## Decision drivers

- Enforcement strength and drift resistance.
- Rollback speed.
- Ability to constrain egress to the gateway.
- Coverage of laptops, which cannot be ignored.

## Considered options

1. Laptop agent and MDM only.
2. Environment definition first (Dev Container Feature, Coder module, Codespaces prebuilds), with `halod` and MDM as secondary sinks.
3. Rely on vendor server-managed settings.

## Decision outcome

Chosen: **option 2**. The environment definition is the primary delivery path. A ring change is a rebuild from a signed release. `halod` (laptops) and MDM exports (Jamf, Kandji, Intune) are supported sinks that consume the same release artifact.

### Consequences

- Good: drift is prevented by construction; egress can be firewalled to the gateway; rollback is a rebuild.
- Good: one signed artifact feeds every sink.
- Bad: laptops get weaker guarantees, and long-lived containers can lag until rebuilt (mitigated by `halod` inside the container and by version-range pins where the CLI supports them).
- Bad: we maintain several delivery sinks.

## Rejected options

- Option 1: weakest enforcement, slowest rollback.
- Option 3: not available on the Bedrock/custom-gateway path.
