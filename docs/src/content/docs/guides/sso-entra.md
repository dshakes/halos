---
title: Single sign-on with Microsoft Entra ID
description: Register halo-server in Entra ID, emit group claims, handle the 200-group overage, and require MFA.
---

halo-server's console login is OpenID Connect authorization code with PKCE. These steps register it in Microsoft Entra ID. Roles come from groups mapped in policy ([ADR-0015](/halos/adr/0015-rbac-roles-for-halo-server/)); overage and MFA handling are [ADR-0036](/halos/adr/0036-admin-api-credentials-break-glass-and-session-policy/).

> Steps follow the Entra admin center as documented by Microsoft; they were not run against a live tenant for this release. Check the screen names against your tenant.

## 1. Register the application

1. **Entra admin center > Identity > Applications > App registrations > New registration.**
2. Name `Halos`, supported account types **Single tenant**.
3. Redirect URI: platform **Web**, `https://<portal baseURL>/auth/callback`.
4. **Certificates & secrets > New client secret.** Store the value as the Kubernetes Secret behind `server.oidcClientSecret.existingSecret` (key `client-secret`).
5. Note the **Application (client) ID** and **Directory (tenant) ID**.

## 2. Claims

1. **Token configuration > Add optional claim > ID:** `email`. halo-server refuses an unverified email; for Entra, set `userClaim` to a claim Entra vouches for if your users' `email` is not set or verified, for example `preferred_username` (the UPN) or `oid`.
2. **Token configuration > Add groups claim:** **Security groups** (or **Groups assigned to the application**, recommended, see below), ID token: **Group ID**. Entra emits group object ids (GUIDs); map those GUIDs in policy.

```yaml
identity:
  issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
  clientID: <application-client-id>
  userClaim: preferred_username      # or email when it is verified, or oid
  groupsClaim: groups
  roles:
    admin: [3f2b6c1e-0000-4000-8000-000000000001]     # AI platform admins
    operator: [3f2b6c1e-0000-4000-8000-000000000002]  # on-call
    auditor: [3f2b6c1e-0000-4000-8000-000000000003]
```

## 3. Groups overage

Entra puts at most 200 groups in a JWT. A user in more gets no `groups` claim, and instead `_claim_names: {"groups": "src1"}` (or `hasgroups: true`). halo-server never treats that as "no groups". Pick one:

- **Emit only groups assigned to the application** (recommended). In **Add groups claim**, choose **Groups assigned to the application**, then under **Enterprise applications > Halos > Users and groups** assign exactly the groups policy maps. Nobody reaches 200, and tokens stay small.
- **Resolve from Microsoft Graph.** Set `identity.groupsOverage: graph`. For overage users, halo-server calls `POST https://graph.microsoft.com/v1.0/me/getMemberObjects` with the login's access token (transitive memberships, group object ids). The login then requests `User.Read` and `GroupMember.Read.All`: under **API permissions > Add a permission > Microsoft Graph > Delegated**, add both and **Grant admin consent**. National clouds: `--entra-graph-url` (Helm `server.oidc.entraGraphURL`), e.g. `https://graph.microsoft.us/v1.0`.
- **Default (`deny`).** The overage user's login fails with a message naming these two fixes, audited as `login.denied` with `reason: groups_overage`.

If Graph fails (no consent, throttled, down), the login fails (503, `reason: groups_graph`). With SCIM provisioning authoritative ([SCIM](/halos/guides/scim-provisioning/)), the directory supplies groups and overage does not matter.

## 4. Require MFA

Enforce MFA in Entra with a **Conditional Access** policy targeting the Halos application. To have halo-server check it too, require the `mfa` authentication method in the ID token's `amr`:

```yaml
identity:
  requireAmr: [mfa]
```

A login without it is refused with "sign in again with MFA" and audited as `login.denied` (`reason: authn_context`). Entra v2.0 ID tokens carry `amr`; they do not carry a meaningful `acr`, so do not set `requireAcr` for Entra. These checks apply to the console login only; the gateways do not enforce them.

## 5. Verify

1. `halo validate` passes (an unknown `groupsOverage` value or a malformed `requireAmr` entry is an error, and halo-server refuses such a policy).
2. Sign in as a user in a mapped group; `GET /api/v1/me` shows the expected `roles`.
3. Sign in as a user in more than 200 groups (or test with a token tool) and confirm the behaviour you chose.

For automation, do not create Entra client credentials for halo-server: use [service-account tokens](/halos/guides/admin-access/#service-account-tokens).
