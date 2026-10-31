---
title: Admin access
description: Service-account API tokens for automation, the break-glass local admin and its rotation runbook, and console session timeouts.
---

How people and automation get into halo-server beyond the browser login. Design: [ADR-0036](/halos/adr/0036-admin-api-credentials-break-glass-and-session-policy/).

## Service-account tokens

Automation (CI, `halo mcp serve --server`, scripts) uses a service-account token, not a console cookie copied from a browser. A token holds one halo-server role, always expires, and shows up in the audit log as its own principal, `service-account:<name>:<id>`.

```bash
export HALO_SERVER=https://halo.acme.example
export HALO_SESSION=...        # your own interactive admin session, once, to mint the token
halo service-token create --name ci-killswitch --role operator --ttl 720h \
  --owner platform-oncall --description "kill switch from the incident pipeline"
# prints halo_sat_... once: put it in your secret manager now
```

Then, in the automation:

```bash
export HALO_SERVER=https://halo.acme.example HALO_TOKEN=halo_sat_...
halo toggle kill sonnet-next-route --reason "SEV2: error spike"
HALO_TOKEN=halo_sat_... halo mcp serve --policy-dir . --server "$HALO_SERVER"
```

`HALO_TOKEN` wins over `HALO_SESSION` everywhere the CLI and the MCP server call halo-server. Neither is ever a flag or a tool argument.

| Property | Behaviour |
|---|---|
| Format | `halo_sat_` + 80 hex digits. Add `halo_sat_[0-9a-f]{80}` to your secret scanner (GitHub custom pattern, gitleaks, trufflehog) |
| Role | One of `viewer`, `operator`, `approver`, `auditor`, `admin`; never more than the creator holds |
| Lifetime | `--ttl`, at least 1h; default and maximum `--service-token-max-ttl` (90 days unless configured, at most 365) |
| Storage | SHA-256 of the token only; the token is shown once |
| Who creates | An admin, from an interactive session. A token cannot create tokens; break-glass cannot either |
| Who revokes | Any admin principal: `halo service-token revoke <id> --reason ...`. Holds on every replica at the token's next request |
| What it cannot do | File, approve or deny access requests, or approve rollout steps: those need a person (403, audited as `authz.deny` with `need: human`). For every separation-of-duties check a token counts as its creator |
| Audit | Every action under the token's principal; `service-token.create`, `service-token.revoke`; `service-token.use` (method, path) at most hourly per token per replica |
| Failed attempts | 10 per minute per client address (shared across replicas), then 429. An expired token is a 401 without a penalty |

Rotation: create the replacement, deploy it, then revoke the old one. `halo service-token list` shows status, expiry, owner and creator, never secrets.

API: `POST /api/v1/service-tokens` `{"name","role","ttl","description","owner"}` (201, returns `token` once), `GET /api/v1/service-tokens`, `POST /api/v1/service-tokens/{id}/revoke` `{"reason"}`, all `admin`. A request carries the token as `Authorization: Bearer halo_sat_...`.

## Session timeouts

Console sessions end at whichever comes first:

| Flag | Helm | Default | Meaning |
|---|---|---|---|
| `--session-ttl` | `server.session.ttl` | `12h` | Absolute lifetime from login (5m to 168h). Never extended |
| `--session-idle-timeout` | `server.session.idleTimeout` | `1h` | No request for this long ends the session (1m to the TTL; `0` turns it off). Sliding: the cookie is re-issued as you use it |

A `HALO_SESSION` copied from a browser now stops working an hour after the browser last used it. Move that automation to `HALO_TOKEN`; set `--session-idle-timeout=0` only if you must keep the old behaviour.

## Break-glass

One local admin account for when the IdP is down or `identity` in policy is broken and nobody can log in. It is sealed (the endpoint answers 404) until you enable it, its session lasts 30 minutes and is never extended, and every login, failed attempt and request it makes is a high-severity audit entry (OCSF `severity_id` 4, syslog severity critical) on every SIEM sink. If the audit log cannot be written, the login is refused.

### Set it up once (sealed)

```bash
# a human, on a trusted machine
openssl rand -base64 33 > bg-password            # store in the vault, split custody if you can
halo-server breakglass-hash < bg-password > bg-hash
kubectl -n halos create secret generic halos-breakglass --from-file=hash=bg-hash
shred -u bg-hash
```

```yaml
server:
  breakGlass: {enabled: false, existingSecret: halos-breakglass, key: hash, user: breakglass, allowedCIDRs: "10.8.0.0/16"}
```

Without Helm: `--breakglass-hash-file=/path/bg-hash [--breakglass-user=breakglass] [--breakglass-allowed-cidrs=10.8.0.0/16]`. The hash is PBKDF2-HMAC-SHA256 with 600,000 iterations; passwords under 16 characters are refused.

Set `allowedCIDRs` to your VPN or bastion range: from anywhere else break-glass answers 404 as if sealed and an existing break-glass session is refused, so outside attackers cannot guess the password or trip the lockout. Twenty failed logins within 15 minutes, from any addresses on any replica, lock break-glass for 15 minutes (audited as `breakglass.lockout`, high severity); a correct password is refused while locked.

Alert on these audit actions in your SIEM: `breakglass.login`, `breakglass.login.failed`, `breakglass.lockout`, `breakglass.request`.

### Use it (incident)

1. Get approval under your incident process; record who and why.
2. Enable: `server.breakGlass.enabled: true` (`--breakglass-enabled`) and roll out. The server logs `BREAK-GLASS ENABLED` at start.
3. Log in and act:

   ```bash
   curl -sc jar -H 'Content-Type: application/json' https://halo.acme.example/auth/breakglass \
     -d "{\"user\":\"breakglass\",\"password\":\"$(cat bg-password)\"}"
   export HALO_SESSION=$(awk '$6=="halo_session"{print $7}' jar)
   halo freeze on --reason "SEV1: IdP outage"     # or kill, revoke, ...
   ```

   The session is `breakglass:breakglass` with the admin role, for 30 minutes. It cannot create service tokens, delegate to agents, or decide access requests and rollout approvals. Every change it makes is written to the audit log before it happens; if the log cannot be written the change is refused (503).

### Close it (rotate after every use)

1. Disable: `server.breakGlass.enabled: false` and roll out. Any open break-glass session ends at its next request.
2. Rotate: generate a new password and hash, update the Secret, roll out. A changed hash also ends old sessions.
3. Review the audit log (`GET /api/v1/audit`, or the SIEM) for every `breakglass.*` entry of the incident and attach them to the post-incident review.
4. Revoke anything created during the incident that should not outlive it (`halo agents revocations`, `halo service-token list`).

## OIDC login requirements

Group claims, Entra ID groups overage and MFA requirements are policy (`identity` in `halos.yaml`): see [Entra ID](/halos/guides/sso-entra/) and [Okta](/halos/guides/sso-okta/).
