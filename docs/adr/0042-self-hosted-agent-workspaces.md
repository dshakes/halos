---
title: "ADR-0042: Self-hosted agent workspaces and headless tasks"
description: Proposed. halo-server would provision per-engineer agent workspaces and run headless agent tasks on the customer's own Kubernetes, from a governed image, with gateway-only egress and no provider keys in the pod. Not implemented.
status: proposed
date: 2026-11-03
---

# ADR-0042: Self-hosted agent workspaces and headless tasks

- Status: proposed (not implemented; nothing in this ADR ships yet)
- Date: 2026-11-03

## Context and problem statement

Halos governs coding agents: signed config releases, rings, version pins, the gateway (identity, DLP, budgets, kill switch) and the audit log. It does not run them. Engineers run agents on laptops (delivered by `halod` or MDM), in dev containers, or in workspace platforms such as Coder and Codespaces that Halos configures (`features/halos`, `features/coder`, `make uat-coder`). Vendor-hosted cloud agents are observed only ([ADR-0034](/halos/adr/0034-cloud-agent-governance/)).

Some customers want Halos itself to provision and run agents on their own Kubernetes: a workspace per engineer and a headless task runner, inside the same trust boundary as the gateway and the audit chain, without buying a second control plane.

Today the recommended deployment is: laptops through MDM and `halod`, all agent traffic through the gateway, and Coder or Codespaces (with the Halos module or Feature) where a laptop is not acceptable. This ADR records how a built-in runtime would work if that is not enough.

## Decision (proposed)

1. **Policy.** A new kind `WorkspaceTemplate` and a root `workspaces:` section (namespace, who may create, quotas, idle minutes, git host, registry), loaded and validated like every other kind, with a JSON Schema in `schemas/`.
2. **Runtime.** A `workspace.Runtime` interface with a Kubernetes backend that calls the API server over `net/http` with the in-cluster service account (no `client-go`), and a fake backend for unit tests.
3. **Workspace.** A Pod with a persistent home volume, from a digest-pinned, cosign-verified image that contains the pinned agent CLIs. `halod` in the pod applies the managed settings for the user's ring from the signed release; the ring comes from `internal/assign`.
4. **Egress and credentials.** A per-workspace default-deny NetworkPolicy allows DNS, the gateway, the registry and the git host only, plus the in-pod firewall from `features/halos/init-firewall.sh`. No provider keys in the pod: the pod holds a short-lived credential bound to the user, minted by halo-server with the workload key ([ADR-0023](/halos/adr/0023-workload-identity-federation/)); the gateway injects upstream keys.
5. **API.** `POST/GET /api/v1/workspaces`, `GET /api/v1/workspaces/{id}`, `POST .../{id}/start|stop`, `DELETE .../{id}`, behind `authenticate()`, RBAC, the rate limiter and strict audit. State is event-sourced in the audit chain (newest version per id wins), as cloud tasks are in `internal/server/cloudagents.go`, so it is HA-safe on Postgres and exported to the SIEM with no new store.
6. **Attach.** A terminal proxied by halo-server: browser or `halo ws attach` over a websocket to halo-server, and halo-server to the `pods/exec` subresource. One new small dependency (`github.com/coder/websocket`). SSH and IDE remotes can be added later.
7. **Headless tasks.** `POST /api/v1/tasks {repo, ref, harness, prompt, template}` runs the agent non-interactively in a Kubernetes Job from the same image, streams logs, pushes a branch and opens a PR or MR through `internal/promote`. It never merges (invariant 5). Each task lands in the session ledger and the audit log.

## Security model

- Pod: `runAsNonRoot`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true` (the home volume is the only writable mount), `capabilities.drop: [ALL]`.
- Per-workspace service account with `automountServiceAccountToken: false`: workspaces have no Kubernetes API access.
- Workspaces run in a dedicated namespace. halo-server's service account gets a namespaced Role there only (pods, PVCs, services, network policies, jobs, `pods/exec`).
- The image is resolved to a digest and verified before the pod is created; the pod references the digest.
- Every lifecycle, attach and task action is audited with the human or service principal as actor. Client `x-halo-*` headers stay stripped at the gateway (invariant 4).

## Phases

Each phase is mergeable and tested on its own: (1) lifecycle on Kubernetes with the governed image and egress policy, e2e on kind with a NetworkPolicy-enforcing CNI; (2) attach; (3) headless tasks to a PR; (4) console pages, quotas, idle auto-stop, metrics, docs.

## Open questions

1. **Credential refresh.** A workspace outlives a short-lived user token. Re-mint on start and by `halod` heartbeat, with a bounded TTL and revocation on delete, needs a design review against ADR-0023 before phase 1.
2. **Who may start a task.** Tasks spend budget and push code. Proposal: workspaces by policy allowlist (like the portal launcher), tasks by an explicit role permission.
3. **NetworkPolicy on kind.** kindnet does not enforce NetworkPolicy; the e2e must install a policy-capable CNI.
4. **Governed image pipeline.** A signed image per release built from the Feature is a prerequisite.
5. **List cost.** State in the audit chain means a scan per list; add an index only if latency requires it.

## Consequences

- Halos would run customer code, not only configure it: a larger trust boundary and an operational burden (capacity, storage, image builds) on the customer's platform team.
- No new store and no `client-go`; one small websocket dependency for attach.

## Alternatives considered

- **Coder or Codespaces as the runtime** (current recommendation). Mature and already integrated and tested (`make uat-coder`); a second control plane and a second audit trail.
- **`client-go`.** Large dependency tree and vulnerability surface for six resource types.
- **A separate workspace database.** The audit chain already gives HA, history and SIEM export.
- **SSH-first attach.** Needs sshd in the image, a certificate authority and an ingress path per pod.

## What is unverified

Everything: this is a design. In particular exec over `v5.channel.k8s.io` without `client-go`, NetworkPolicy enforcement in the e2e, verify-before-schedule latency, credential refresh on long-lived workspaces and idle auto-stop across replicas.
