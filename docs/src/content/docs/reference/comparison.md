---
title: Comparison
description: An honest comparison of Halos with vendor admin consoles, LLM gateways such as LiteLLM, and feature-flag tools.
---

Halos overlaps with three kinds of tool without replacing any of them outright. This page says where each one is the better choice. Claims about other products are kept general on purpose; check their current docs before you decide.

## At a glance

| | Vendor consoles and managed settings | LLM gateways (LiteLLM and similar) | Feature-flag tools (LaunchDarkly, Unleash, GrowthBook) | Halos |
|---|---|---|---|---|
| Main job | Admin and enforce one vendor's tool | Route, meter and govern LLM API calls | Control app features and run experiments | Release and roll out AI-CLI configuration, route model traffic by cohort |
| Spans several AI CLIs | No, one vendor each | Indirectly, via API compatibility | Not designed for it | Yes: Claude Code, Codex, Gemini CLI, Copilot CLI (rendered and applied by `halod` on Linux; no gateway render) |
| Config as signed, versioned releases | No | No | No | Yes |
| Rings and rollback without a release | Limited to what the vendor offers | Not for client config | Rollouts, but for app code | Rings, signed pointers, kill switch |
| Spend limits, virtual keys, budgets | Vendor-specific | Core strength | No | Not a goal |
| Many providers behind one API | No | Core strength | No | A handful (Anthropic, Bedrock, Vertex, OpenAI, Azure OpenAI, Gemini) |
| Polished admin UI | Yes | Usually | Yes | Basic console and portal |
| Hosted option, vendor support | Yes | Often | Yes | No: self-hosted, community support |
| Maturity | Production | Widely deployed | Widely deployed | `v1alpha1`, no release tag yet |

## Vendor consoles and managed settings

Anthropic's and OpenAI's admin consoles, and the managed-settings mechanisms of each CLI, are first-party. They need no infrastructure from you, they track the vendor's features the day they ship, and they come with real support and identity integration. If you use one vendor and its controls are enough, use them and stop there.

Halos is for what they leave to you: one policy across several CLIs, version pinning and drift reporting, ring-by-ring rollout with signed rollback, and experiments with an eval gate before promotion. It does not compete with managed settings; it renders them (`managed-settings.json` for Claude Code) and delivers them, including on paths such as Bedrock or a custom base URL where server-managed settings are not fetched.

**Weaker:** every vendor feature Halos has not adapted is unavailable through it (an unsupported setting becomes a manifest warning), and its adapters trail the vendors.

## LLM gateways such as LiteLLM

A gateway is mature, broadly deployed infrastructure for the API call: many providers behind one interface, keys, budgets, rate limits, spend tracking, logging. If you need provider breadth or per-team budgets, a gateway is the right tool and Halos is not a substitute.

Halos does not replace one. `halo-proxy` can run in front of, behind or instead of a gateway, and `halo-kong` is a Kong plugin. What it adds is on the client and the rollout side: the configuration each CLI runs with, cohorts from verified identity, sticky A/B and canary routes, shadowing of single turns, and promotion gated on evals and metrics.

**Weaker:** Halos supports far fewer providers, has no budgeting or virtual-key system, and its proxy is younger than the gateways you may already run.

## Feature-flag tools

LaunchDarkly, Unleash and GrowthBook are built for application features: SDKs in many languages, mature targeting UIs, audit trails and statistics tooling. Use them for your product. They are not built to configure a developer's CLI on their laptop, to pin its version, or to move a model route at a gateway.

Halos borrows the vocabulary (toggles, percentage rollouts, a kill switch, experiments) and applies it to AI-dev-tool configuration and model routes. Cohorts hash deterministically from the authenticated user, so a developer's ring and variant do not depend on a header they can set.

**Weaker:** a small statistics engine (mSPRT and bootstrap) next to dedicated experimentation platforms, no general-purpose SDK, and a console that is not a flag product's UI.

## Honest limits

- The policy API is `halos.dev/v1` and stable ([Compatibility](/halos/reference/compatibility/)). There is no tagged release yet.
- It is an open-source project with a small maintainer group, not a vendor with an SLA.
- Several integrations are labelled **UNVERIFIED** in the docs (Kong Enterprise, real Bedrock traffic, MDM on real devices). Believe those labels.
- It is self-hosted only. You run the proxy, the registry and the telemetry store.

## When Halos is the wrong choice

One vendor, a small team, and its admin console already does what you need. Start there; revisit when you need a second CLI, a staged rollout or an A/B test. For a first look, copy [`startup-minimal`](/halos/examples/) and see how little it takes.
