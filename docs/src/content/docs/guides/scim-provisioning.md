---
title: SCIM provisioning (Okta, Entra ID)
description: Provision users and groups into halo-server from Okta or Microsoft Entra ID with SCIM 2.0, so deprovisioning revokes access at once and the IdP's groups drive rings, cohorts and admin rights.
---

`halo-server` is a SCIM 2.0 service provider at `/scim/v2`. Once your IdP provisions into it:

- Deactivating or deleting a user in the IdP immediately ends their console sessions, revokes every device token `halod` holds for them, and drops their pending enrollment tokens. It is recorded in the audit log with actor `scim`.
- With `--scim-authoritative`, the IdP's group assignments decide rings, toggle targeting and admin rights on halo-server, and changes apply without a re-login. Users the IdP has not provisioned are refused.
- With `directory.url` on the gateways, a verified caller's groups come from the same directory, and a deprovisioned user is refused (403).

Design and limits: [ADR-0022](/halos/adr/0022-scim-provisioning/). Endpoints: [API reference](/halos/reference/api/#scim-20-provisioning).

## Before you start

The SCIM `userName` must be the same value halo-server and the gateways see as the user's identity: the OIDC claim named by `identity.userClaim` in policy (`email` by default). It is compared case-insensitively; a different attribute (for example Entra's UPN when the token carries `mail`) leaves users unknown. Groups are matched by `displayName`, the same names policy uses in ring `membership.groups`, `identity.adminGroups` and toggle rules.

SCIM needs `--data-dir`: the directory is stored in `scim.jsonl` there.

## 1. Create the SCIM token

halo-server stores only the SHA-256 of the token.

```bash
TOKEN=$(openssl rand -base64 48 | tr -d '\n=+/')
printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1 > scim-token.sha256
```

Keep `$TOKEN` for the IdP (paste it into the IdP, then discard it). Mount `scim-token.sha256` where halo-server can read it and start it with:

```bash
halo-server --policy-dir /policy --token-file /secrets/fleet-token --data-dir /var/lib/halos \
  --scim-token-sha256-file /secrets/scim-token.sha256 \
  --scim-authoritative   # optional: the directory decides who is active and their groups
```

Check it (expect `"patch":{"supported":true}`):

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://halo.acme.example/scim/v2/ServiceProviderConfig
```

Turn `--scim-authoritative` on after the first full sync: before that, users the IdP has not pushed yet are refused.

## 2a. Okta

1. **Applications > Applications > Browse App Catalog**, add **SCIM 2.0 Test App (Header Auth)**, or open the existing app integration you use for halo-server login and enable SCIM provisioning on its **General** tab.
2. **Provisioning > Integration**:
   - SCIM connector base URL: `https://halo.acme.example/scim/v2`
   - Unique identifier field for users: `userName`
   - Supported provisioning actions: **Push New Users**, **Push Profile Updates**, **Push Groups**
   - Authentication Mode: **HTTP Header**, Authorization: `Bearer <TOKEN>`
   - **Test Connector Configuration**, then **Save**.
3. **Provisioning > To App**: enable **Create Users**, **Update User Attributes** and **Deactivate Users**.
4. **Sign On > Credentials Details**: set **Application username format** to **Email** (or whatever matches `identity.userClaim`).
5. **Assignments**: assign the people or groups who use Halos.
6. **Push Groups**: push each group policy refers to (for example `ai-platform`, `platform-admins`). Okta creates the group, then changes membership with PATCH.

Okta updates users with PUT and deactivates with `{"op":"replace","value":{"active":false}}`; both are supported. Unassigning a user or deactivating them in Okta deactivates them in Halos.

## 2b. Microsoft Entra ID

1. **Enterprise applications > New application > Create your own application**, "Integrate any other application you don't find in the gallery (Non-gallery)". You can reuse the application you use for halo-server login.
2. **Provisioning > Get started**, Provisioning Mode **Automatic**:
   - Tenant URL: `https://halo.acme.example/scim/v2`
   - Secret Token: `<TOKEN>`
   - **Test Connection**, then **Save**.
3. **Provisioning > Mappings > Provision Microsoft Entra ID Users**: map `userName` to the attribute your OIDC tokens carry as `identity.userClaim` (`mail` for the default `email` claim, or `userPrincipalName` if that is what the token carries). Keep `active` mapped from `Switch([IsSoftDeleted], , "False", "True", "True", "False")`. Extra attributes (title, the enterprise extension) are accepted and ignored.
4. **Provision Microsoft Entra ID Groups**: enabled. `displayName` maps to the group name policy uses.
5. **Settings > Scope**: "Sync only assigned users and groups". Assign them under **Users and groups**.
6. Set **Provisioning Status** to **On**. Use **Provision on demand** to push one user straight away; the regular cycle is incremental (about every 40 minutes).

Entra ID sends PATCH op names capitalised (`"Replace"`) and booleans as strings (`"value": "False"`); both are handled, with or without the `?aadOptscim062020` compliance flag on the tenant URL.

## 3. Make the gateways use the directory

Each gateway asks halo-server for the verified caller's entry with the existing gateway token (`--gateway-token-file`).

`halo-proxy` (YAML):

```yaml
directory:
  url: https://halo.acme.example/api/v1/gateway/directory
  tokenFile: /secrets/gateway-token
  cacheTTL: 1m   # how long a deprovisioned user can keep their cohort here
  grace: 5m      # serve the last entry this long if halo-server is unreachable
  failMode: open # past grace: open keeps the verified caller with no groups; closed answers 503
  # mode: revocations  # only the credential revocation list (ADR-0026), for a halo-server without SCIM
```

`halo-kong` plugin config: `directory_url`, `directory_token` (`{vault://env/halo-gateway-token}`), `directory_fail_mode` (`open` or `closed`), `directory_mode` (`full`, default, or `revocations`: only the ADR-0026 revocation list, no SCIM lookups), and `directory_allow_insecure_in_cluster` for a plain-http in-cluster URL.

With a directory configured, the token's groups claim and any groups header no longer count: an active user gets the directory's groups; a verified user the directory lists as inactive, deleted or never provisioned is refused with 403 (in the CLI's error format). If halo-server is unreachable past `grace` with nothing cached (or the `halo-kong` directory config is invalid), the caller is never made anonymous: with `failMode: open` (default) they keep their verified identity with no groups, so default routing and no experiments, while the posture gate and per-user budgets still apply to them; with `closed` they get 503 with `Retry-After: 30`. Only an outage fails open (a transport error or a 5xx): any other non-200 answer from halo-server refuses the caller (403), and a caller whose last cached entry was inactive stays refused however long halo-server is unreachable. halo-server keeps a separate failed-auth budget per endpoint class, so garbage sent to its public token-exchange or SCIM endpoints from an IP a gateway shares cannot lock the gateway out of the directory. Workload credentials skip the directory. `userName` must match the IdP's user claim, case aside, and must not start with `workload:`. The user id still comes only from the verified token or trusted header.

## 4. Verify

- `GET /api/v1/audit` (admin) shows `scim.user.create` and `scim.group.create` entries with actor `scim`.
- `GET /api/v1/me` for a provisioned user shows their SCIM groups and ring when `--scim-authoritative` is on.
- Deactivate a test user in the IdP and provision on demand: their console session is logged out, their `halod` gets 401 on its next ring lookup, and the audit entry carries `sessionsRevoked: true` and `devicesRevoked: <n>`.

## Rotate the token

1. Add the new token's hash as a second line in the hash file and restart halo-server (rolling restart; both tokens work).
2. Update the token in the IdP and test the connection.
3. Remove the old line and restart again.

## Limits

- Supported filters are `eq` on `userName`, `externalId`, `id` (users) and `displayName`, `externalId`, `id` (groups). Bulk, sort and `/Me` are not supported; neither IdP needs them.
- Group members must be users; nested groups are refused. A group holds at most 20,000 members.
- Deprovisioning does not revoke the user's IdP tokens. Gateway access with a still-valid IdP token is the IdP's to stop; Halos only drops the user's cohort (within `cacheTTL`).
