---
title: "PolicyTest"
description: "A suite of policy test cases for `halo test`: given an identity, the ring, experiment variants and rendered setting values the policy must produce. Lives under tests/ in the policy repo; the loader does not read it as policy."
---

A suite of policy test cases for `halo test`: given an identity, the ring, experiment variants and rendered setting values the policy must produce. Lives under tests/ in the policy repo; the loader does not read it as policy.

Generated from `schemas/policytest.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `cases` | array of object | yes |  |  | minItems 1 | The cases, each independent. Case names are unique within the suite. |
| `cases[]` | object |  |  |  |  | Resolves identity with the policy's own ring and variant assignment and compares the result with expect. |
| `cases[].description` | string |  |  |  |  |  |
| `cases[].expect` | object | yes |  |  |  | What the identity must get; at least one of ring, variants and settings. |
| `cases[].expect.ring` | string |  |  |  |  | The ring the identity lands in. The empty string asserts that no ring matches. |
| `cases[].expect.settings` | object |  |  |  |  | Harness name -> dotted key path in its rendered config (JSON or TOML; array elements by index, e.g. hooks.PreToolUse.0.matcher) -> the exact value it must have. null asserts the key is absent. Read from the identity's ring release, or from its variant release for a client-axis experiment; unit overlays and toggles are not applied. |
| `cases[].expect.settings.*` | object |  |  |  |  |  |
| `cases[].expect.variants` | object |  |  |  |  | Running experiment name -> variant the identity gets. The empty string asserts the identity is not enrolled in it. |
| `cases[].expect.variants.*` | string |  |  |  |  |  |
| `cases[].identity` | object | yes |  |  |  | The subject, as the IdP presents it. |
| `cases[].identity.groups` | array of string |  |  |  |  | IdP groups. |
| `cases[].identity.groups[]` | string |  |  |  |  |  |
| `cases[].identity.user` | string | yes |  |  | minLength 1 | User id. |
| `cases[].name` | string | yes |  |  | minLength 1 |  |
| `cases[].os` | string |  |  | darwin, linux, windows |  | The OS whose rendered files expect.settings reads (default linux). |
| `description` | string |  |  |  |  | What the suite pins. |
| `kind` | string | yes |  | const PolicyTest |  | Document kind. |
| `name` | string | yes |  |  | minLength 1 | Suite name; reported as &lt;suite>/&lt;case>. |
