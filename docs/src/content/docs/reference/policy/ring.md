---
title: "Ring"
description: "An ordered rollout cohort pointing at a profile."
---

An ordered rollout cohort pointing at a profile.

Generated from `schemas/ring.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1alpha1 |  | Document version. |
| `kind` | string | yes |  | const Ring |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `membership` | object | yes |  |  |  | Who belongs to the ring. |
| `membership.default` | boolean |  |  |  |  | Marks the catch-all (GA) ring. Exactly one ring must set this. |
| `membership.groups` | array of string |  |  |  |  | IdP groups always in this ring. |
| `membership.groups[]` | string |  |  |  |  |  |
| `membership.optIn` | boolean |  |  |  |  | Developers may join this ring themselves from the portal (recorded as a group membership request; admins may auto-approve). |
| `membership.percent` | number |  |  |  | minimum 0; maximum 100 | Percent of remaining users hashed into this ring (0-100, 0.01 precision). |
| `membership.users` | array of string |  |  |  |  | Explicit user ids always in this ring; checked before groups. A user may appear in only one ring. |
| `membership.users[]` | string |  |  |  |  |  |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `order` | integer | yes |  |  |  | Position in the rollout; earliest ring has the lowest order. Must be unique. |
| `profile` | string | yes |  |  |  | Name of the Profile applied to members. |
| `release` | string |  |  |  |  | Immutable published release digest to pin to; empty builds from the profile. |
