---
title: Tutorials
description: Six hands-on paths, each a copy-pasteable sequence with real output, from first build to killing a bad change.
---

Each tutorial is a numbered path you can run top to bottom. Every command was run against this repo and the output shown is real, trimmed with `…` where long. Start with the first; the rest stand alone.

| Tutorial | You will | Time |
|---|---|---|
| [Your first 10 minutes](/halos/tutorials/first-10-minutes/) | Build `halo`, create a policy repo, render a ring's config, sign and publish a release to a local registry, and see releases in the console | 10 min |
| [Roll out a Claude Code upgrade safely](/halos/tutorials/claude-code-upgrade/) | Bump a pin on a `-next` profile, plan against the published release, simulate the rollout, and see the promote patch | 20 min |
| [Canary a new model](/halos/tutorials/canary-a-model/) | Route a slice of a ring to a new model at the gateway, check who gets which route, and roll back without touching a client | 15 min |
| [Kill a bad change in 10 seconds](/halos/tutorials/kill-a-bad-change/) | Trip the signed kill switch on a toggle and an experiment in the playground and time the effect | 5 min |
| [Add a feature toggle](/halos/tutorials/add-a-toggle/) | Write a toggle, validate it, see who gets it and why, and inspect what the release records | 10 min |
| [Gate upgrades on evals](/halos/tutorials/gate-upgrades-on-evals/) | Run an eval suite, get a SHIP or BLOCK verdict, fail a pipeline on it, and watch for upstream upgrades | 15 min |

Prerequisites across the set: Go, Docker and `curl`. Two use the [playground](/halos/getting-started/playground/) (`make demo`). Installers and Homebrew arrive with the first tagged release, so the tutorials build from source with `make build`.
