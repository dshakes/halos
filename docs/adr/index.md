---
title: Architecture decision records
description: Load-bearing decisions, in MADR format.
sidebar:
  order: 0
---

Decisions that shape Halos. New ADRs use [MADR](https://adr.github.io/madr/): context, drivers, options, outcome, consequences. Load-bearing changes get an ADR before code.

| ADR | Decision |
|---|---|
| [0001](/halos/adr/0001-environment-as-policy/) | Environment as policy is the primary delivery path |
| [0002](/halos/adr/0002-rings-point-at-immutable-releases/) | Rings point at immutable releases |
| [0003](/halos/adr/0003-experiments-on-traffic-plane-first/) | Experiments run on the traffic plane first |
| [0004](/halos/adr/0004-shadow-single-turn-only/) | Shadow traffic is single-turn only (amended by 0014) |
| [0005](/halos/adr/0005-signed-oci-bundles/) | Releases are signed OCI bundles |
| [0006](/halos/adr/0006-go-and-kong-go-pdk/) | Go, with the Kong Go PDK |
| [0007](/halos/adr/0007-guardrails-in-go-not-opa/) | Guardrails in Go, Rego pluggable later |
| [0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/) | Signed ring pointers and verified artifacts (refines 0005) |
| [0009](/halos/adr/0009-signed-kill-switch/) | Signed, poll-based kill switch for experiments |
| [0010](/halos/adr/0010-release-channels-for-client-experiments/) | Release channels for client-axis experiments (extends 0008) |
| [0011](/halos/adr/0011-gateway-enforced-posture-and-version/) | Gateway-enforced device posture and CLI version |
| [0012](/halos/adr/0012-policy-api-v1/) | halos.dev/v1 is the stable policy API |
| [0013](/halos/adr/0013-external-gateway-engine/) | Halos manages clients behind a gateway it does not run |
| [0014](/halos/adr/0014-step-level-multi-turn-shadow/) | Step-level shadowing of multi-turn agent sessions (amends 0004) |
| [0015](/halos/adr/0015-rbac-roles-for-halo-server/) | RBAC roles for halo-server |
| [0016](/halos/adr/0016-audit-export-to-siem/) | Audit export to SIEM, with rotation across a continuous hash chain |
| [0017](/halos/adr/0017-gateway-cost-budgets/) | Cost budgets and quotas enforced at the gateway |
| [0018](/halos/adr/0018-org-hierarchy-and-delegated-policy/) | Org hierarchy: units with delegated owners that can only tighten the baseline |
| [0019](/halos/adr/0019-harness-coverage-beyond-the-big-four/) | Harness coverage beyond the big four: OpenCode and Cursor CLI |
| [0020](/halos/adr/0020-harvest-shadow-sessions-into-replay-evals/) | Harvesting shadow sessions into replay evals (builds on 0014) |
| [0021](/halos/adr/0021-ha-control-plane-on-postgres/) | HA control plane on Postgres: shared state, leader lease, fencing |
| [0022](/halos/adr/0022-scim-provisioning/) | SCIM 2.0 provisioning: immediate deprovisioning, authoritative directory groups |
| [0023](/halos/adr/0023-workload-identity-federation/) | Workload identity federation for headless CI and cloud agents |
| [0024](/halos/adr/0024-agent-identity-and-delegation/) | Agent identity and delegation: RFC 8693 act chains, root-principal routing, remote A2A agent allowlist |
| [0025](/halos/adr/0025-vendor-admin-sync/) | Vendor admin sync: one policy drives the vendors' cloud admin consoles, with drift detection (amended after security review) |
| [0027](/halos/adr/0027-randomized-roi/) | Randomized delivery ROI: PR outcomes joined to experiment arms for causal effects; ring comparisons labelled observational |
| [0031](/halos/adr/0031-agent-session-ledger/) | Agent session ledger: one identity-linked, redacted record per agent session, stored in the audit chain |

The canonical files live in `docs/adr/` in the repository; the docs build copies them into the site.
