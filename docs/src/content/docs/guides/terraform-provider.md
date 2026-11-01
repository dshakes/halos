---
title: Terraform and OpenTofu provider
description: Manage halo-server service-account tokens and read fleet, release and rollout status from Terraform or OpenTofu. Policy and every irreversible decision stay with git and a human.
---

The `dshakes/halos` provider manages the server-side state of `halo-server` that is not policy-as-code: [service-account API tokens](/halos/guides/admin-access/) (ADR-0036, scoped by ADR-0037). It also has read-only data sources for status.

It lives in its own repository, [dshakes/terraform-provider-halos](https://github.com/dshakes/terraform-provider-halos), and is published on the [Terraform Registry](https://registry.terraform.io/providers/dshakes/halos) (v0.1.0). It is OpenTofu-compatible; and listed on the [OpenTofu Registry](https://search.opentofu.org/provider/dshakes/halos) under the same `source`.

## What it does not do

Halos policy is GitOps: it changes through pull requests that a human merges. So the provider has no resource for policy files, and no path to kill or unkill, approve, promote, advance or roll back a rollout, merge, or publish a release. Manage the policy repository with the GitHub or GitLab provider and PR review.

## Install

```hcl
terraform {
  required_providers {
    halos = { source = "dshakes/halos" }
  }
}

provider "halos" {
  endpoint = "https://halos.example.com" # or HALO_SERVER
  # token   = ...                        # or HALO_TOKEN   (service-account token)
  # session = ...                        # or HALO_SESSION (admin halo_session cookie; creating tokens only)
}

resource "halos_service_token" "dashboard" {
  name  = "fleet-dashboard"
  role  = "viewer"
  ttl   = "720h"
  scope = { rings = ["ring1-canary"] }
}
```

Provider arguments: `endpoint`, `token` (sensitive), `session` (sensitive), `ca_bundle_file`, `timeout` (default `30s`, max `10m`). `endpoint` must be https unless the host is loopback. Redirects are never followed.

## Authentication

The provider calls the `/api/v1` API with a service-account token (`halo_sat_...`, `HALO_TOKEN`). The token's role and scope apply as for any other client, so a `viewer` token limited to one ring sees only that ring.

Creating a token is the exception. `halo-server` lets only a signed-in admin create one ("a token cannot mint its successor", ADR-0036), so a `POST /service-tokens` made with a token answers 403. To apply a new `halos_service_token`, set `session` (or `HALO_SESSION`) to an admin's `halo_session` cookie value. Without it the provider fails the create before sending anything. A token can list, revoke, read data sources, refresh and destroy.

`halos_service_token.token` is returned once, at create, and is kept in state. Use an encrypted remote backend (or OpenTofu state encryption) and restrict who can read state; `sensitive` only hides the value from CLI output.

## Resource

| Resource | Behavior |
| --- | --- |
| `halos_service_token` | Create mints a token, destroy revokes it. Every argument forces replacement. Import by id (an imported token has no secret). |

## Data sources

All read-only `GET /api/v1/...`.

| Data source | Endpoint | Use |
| --- | --- | --- |
| `halos_me` | `/me` | Assert the credential's roles before a plan depends on them. |
| `halos_capabilities` | `/capabilities` | Whether the kill switch is configured, and the caller's scoped role bindings. |
| `halos_releases` | `/releases` | Ring pointers, convergence and drift. |
| `halos_experiments` | `/experiments` | Names and status. |
| `halos_rollouts` | `/rollouts` | Current step and halted state. |
| `halos_kill_switch` | `/killswitch` | `any_active`, for alerting. Read only. |
| `halos_fleet` | `/fleet` | Fleet size and per-ring drift. Per-host rows are dropped so no device data lands in state. |

See the repository README for known API gaps, such as the missing `GET /service-tokens/{id}`.
