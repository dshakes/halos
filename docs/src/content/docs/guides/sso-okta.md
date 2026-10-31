---
title: Single sign-on with Okta
description: Register halo-server in Okta, emit group claims, and require MFA with acr or amr.
---

halo-server's console login is OpenID Connect authorization code with PKCE. These steps register it in Okta. Roles come from groups mapped in policy ([ADR-0015](/halos/adr/0015-rbac-roles-for-halo-server/)); MFA requirements are [ADR-0036](/halos/adr/0036-admin-api-credentials-break-glass-and-session-policy/).

> Steps follow the Okta Admin Console as documented by Okta; they were not run against a live org for this release. Check the screen names against your org.

## 1. Create the app integration

1. **Applications > Applications > Create App Integration:** **OIDC - OpenID Connect**, **Web Application**.
2. Grant type **Authorization Code** (PKCE is used by halo-server either way).
3. Sign-in redirect URI `https://<portal baseURL>/auth/callback`; no sign-out redirect is needed.
4. Assignments: the groups that should reach the console.
5. Store the **Client secret** as the Kubernetes Secret behind `server.oidcClientSecret.existingSecret` (key `client-secret`); note the **Client ID**.

## 2. Authorization server and claims

Use a custom authorization server (**Security > API > Authorization Servers**, e.g. `default`): the issuer is `https://<org>.okta.com/oauth2/default`. Under **Claims**, add a `groups` claim to the **ID Token**, value type **Groups**, filter e.g. **Starts with** `halos-` (keep it narrow: Okta limits a groups claim to 100 groups, and unlike Entra ID it has no overage pointer for halo-server to resolve). Okta emits group names.

```yaml
identity:
  issuer: https://acme.okta.com/oauth2/default
  clientID: <client-id>
  groupsClaim: groups
  roles:
    admin: [halos-admins]
    operator: [halos-oncall]
    viewer: [halos-viewers]
    auditor: [halos-audit]
```

`email` must be verified in Okta (it is for Okta-managed users); halo-server refuses `email_verified: false`.

## 3. Require MFA

Enforce MFA in Okta with an **authentication policy** on the app. To have halo-server check it too, use either claim:

```yaml
identity:
  requireAcr: [urn:okta:loa:2fa:any]   # sent as acr_values; the ID token's acr must match
  # or
  requireAmr: [mfa]                    # the ID token's amr must contain mfa (any listed value)
```

`requireAcr` is sent to Okta as `acr_values`, so Okta steps the user up before issuing the token; `urn:okta:loa:2fa:any` (two factors), `urn:okta:loa:2fa:any:ifpossible` and phishing-resistant values (`phr`, `phrh`) are Okta's documented values. A login that does not satisfy the requirement is refused with "sign in again with MFA" and audited as `login.denied` (`reason: authn_context`). These checks apply to the console login only; the gateways do not enforce them.

## 4. Verify

1. `halo validate` passes.
2. Sign in; `GET /api/v1/me` shows the expected `roles`.
3. Sign in with a password-only session and confirm the requirement holds.

For automation, use [service-account tokens](/halos/guides/admin-access/#service-account-tokens), not Okta API service apps.
