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
| [0004](/halos/adr/0004-shadow-single-turn-only/) | Shadow traffic is single-turn only |
| [0005](/halos/adr/0005-signed-oci-bundles/) | Releases are signed OCI bundles |
| [0006](/halos/adr/0006-go-and-kong-go-pdk/) | Go, with the Kong Go PDK |
| [0007](/halos/adr/0007-guardrails-in-go-not-opa/) | Guardrails in Go, Rego pluggable later |
| [0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/) | Signed ring pointers and verified artifacts (refines 0005) |
| [0009](/halos/adr/0009-signed-kill-switch/) | Signed, poll-based kill switch for experiments |
| [0012](/halos/adr/0012-policy-api-v1/) | halos.dev/v1 is the stable policy API |

The canonical files live in `docs/adr/` in the repository; the docs build copies them into the site.
