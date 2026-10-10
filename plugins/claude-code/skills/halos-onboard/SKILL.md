---
name: halos-onboard
description: Onboard a person or a company onto Halos from inside an AI coding CLI. Use when asked to set up, try, install or roll out Halos, to manage this machine's Claude Code/Codex/Gemini/Copilot config with Halos, or when a user says "get started with halos".
---

# Halos onboarding

Three paths. Ask which one, or infer it: "try it" / "demo" is **Try it**; "my laptop", "my config", one developer is **My machine**; IdP, gateway, fleet, rollout, "our engineers" is **My company**.

Tools come from the `halos` MCP server (`halo mcp serve`) and mirror `halo doctor` / `halo onboard`. Every tool that writes defaults to `dry_run: true`; `dry_run: false` works only when the human started the server with `--allow-writes`, otherwise the tool returns the exact `halo ...` command for the human to run. Prefer the tool; fall back to the printed command.

## Hard rules

- Ask before every write: show the dry run (which files, create/update/unchanged) and wait for a yes. One yes covers one step, not the session.
- Never print, echo, paste or ask for an API key or token. `doctor` and `detect_harnesses` report only whether a variable is set. If a key is missing, tell the human which variable to export in their own shell and continue.
- Never publish a release, enroll a device or fleet, retag a registry ring, push, merge or deploy. When a path reaches one of those, stop and hand the human the command.
- Never emit `bypassPermissions` or `danger-full-access`.
- `local_install` with `dry_run: false` writes admin-owned paths and usually needs sudo: show the plan, then give the human `sudo halo onboard install --policy-dir DIR --apply`, or stage with `root` and let them copy.

## Always first

Call `doctor`. For each `fail`, give the human its `fix` verbatim and re-run until no `fail` remains (a `warn` is fine to continue on; say what it means). Then `detect_harnesses`: list each CLI with its version, and say which credential variables are set, never values.

## Try it (about 2 minutes, Docker)

1. `doctor` must show `docker` and `git` ok.
2. Tell the human to run `halo quickstart` in a terminal (it runs `make demo`: whole stack, mock IdP and models, throwaway keys, DEV ONLY), then opens the console at `http://localhost:18080` and prints a six-step tour. Walk them through the tour; `halo quickstart down` tears it down.
3. Offer **My machine** next.

## My machine

1. **Interview.** Confirm the CLIs to manage (default: every one `detect_harnesses` found, pinned at its installed version), the provider (default: `suggested_provider`, from which key is exported), models (default: the provider's current ones), and whether they want a local halo-proxy (default yes: the CLIs then call `http://127.0.0.1:8088`, which forwards to the provider with the key from their environment).
2. **Policy.** `init_policy` (dry run): show the `halos.yaml` it returns and the validation result. Fix errors by changing answers, not by hand-editing. On a yes, `init_policy` with `dry_run: false` (or `halo onboard local --apply` with the same flags). It never overwrites an existing `halos.yaml`.
3. **Plan.** `plan` for the ring (default the GA ring), then `local_install` (dry run, `show: true` once so they can read what lands): list each file, destination and action. Explain the managed-settings semantics: those paths are admin-owned and the CLI reads them first.
4. **Install.** On a yes: `local_install` with `dry_run: false`, or the sudo command. Run it again: it must report nothing to write (idempotent). A file Halos did not write (MDM-managed, say) plans as `foreign` and blocks the apply: stop and ask the human; only they run `--replace-existing`, which keeps the original at `<file>.halos-backup`.
5. **Proxy (if chosen).** `local_proxy` (dry run, then real): it writes `<policy>/.halos/local/halo-proxy.yaml`, loopback only, keys read from the environment at start. Give the human the start command it returns and ask them to run it in another terminal.
6. **Verify.** For each managed CLI: `verify_harness` with `dry_run: true` to show the command, then `dry_run: false` to make one short model call through the configured endpoint (it spends their credentials, so it is gated like a write: on a read-only server, hand them the `halo onboard verify` command instead). `skipped` with "no credential variable set" is not a failure: ask whether the CLI is logged in and retry with `assume_auth: true`. Report pass/fail per CLI with the redacted output.
7. **Hand off.** Point at the `halos-rollout` skill for upgrades, and at `halos://policy/halos.yaml` for what they now own.

## My company

1. **Interview** (one question at a time, defaults in brackets): org name; CLIs and the versions to pin; provider [anthropic] (bedrock, vertex, openai, gemini, multi) and models; gateway kind [halo-proxy] or kong, and its https URL; IdP OIDC issuer URL, client id [halos], admin group(s); delivery channels [halod] (devcontainer, mdm); OCI registry for releases; git URL of the policy repo; console URL; safety [standard], rollout [standard].
2. **Generate.** `onboard_company` (dry run): list every file it would write (halos.yaml, `.halos/helm-values.yaml`, `.halos/oidc-client.yaml`, `.halos/enroll/*`, CI workflow, smoke eval, README of human steps) and the validation result. On a yes, write it (`dry_run: false` or `halo onboard company --apply`). It refuses to overwrite differing files.
3. **Check.** `validate`, `plan` for ring0 and ring1, `harness_matrix` for the pinned CLIs, and `eval_scorecard` if a scorecard exists. If the human has provider credentials and Docker, offer `halo eval run` for the generated smoke suite; ask first, it spends money.
4. **PR.** Commit on a branch and open a PR with the generated README's human steps as the body (`gh pr create`); ask before pushing, and never push to main.
5. **STOP.** Everything after the merge is a human step with a real blast radius: creating the IdP client, deploying the Helm values, `halo release publish`, enrolling devices, pointing a ring. List them in order from the generated README and stop.
