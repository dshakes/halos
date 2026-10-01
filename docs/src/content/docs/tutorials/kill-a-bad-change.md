---
title: Kill a bad change in 10 seconds
description: Trip the signed kill switch on a toggle and an experiment from the CLI, and watch the gateway change its routing within seconds, with no release and no PR.
---

A rollout goes wrong at 2am. You do not want a PR, a review and a release: you want the change off now. The kill switch does that: `halo-server` adds the change to a signed kill list and every gateway drops it at its next poll. You will do it against the [playground](/halos/getting-started/playground/) and time it.

**Prerequisites:** Docker, a built `halo` ([Your first 10 minutes](/halos/tutorials/first-10-minutes/)), `curl`, and the repo checkout. The playground is dev only: the IdP signs in anyone and the models are mocks.

## 1. Start the stack and send a request

```console
$ make demo
…
$ TOK=$(curl -s 'localhost:18081/token?user=alice@acme.com&groups=ai-platform')
$ ask() { curl -s localhost:18088/v1/messages -H "Authorization: Bearer $TOK" \
    -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
    -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}' \
    | grep -o 'served-by=[a-z]* model=[^ ]*'; }
$ ask
served-by=anthropic model=claude-sonnet-5-5
```

The token is a mock-IdP JWT; `halo-proxy` (`:18088`) verifies it, resolves alice into `ring0-harness-team`, and the `sonnet-next-route` toggle sends `sonnet` to the next model.

## 2. Get an admin session

Killing needs an admin session cookie, passed as `HALO_SESSION` and never as a flag. Sign in through the mock IdP's authorization-code flow with `curl`, or in the browser at `http://localhost:18080`:

```console
$ AUTHZ=$(curl -s -c jar -o /dev/null -w '%{redirect_url}' localhost:18080/auth/login)
$ curl -s -b jar -c jar -o /dev/null "$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ&user=alice@acme.com")"
$ export HALO_SESSION=$(awk '$6=="halo_session"{print $7}' jar)    # a cookie value: never paste it into docs or tickets
```

## 3. Kill the toggle

`halo kill` and `halo toggle kill` resolve the name in a policy repo, so run them from a copy of the example the demo was seeded from:

```console
$ cp -r examples/acme-corp policy && cd policy
$ time (halo toggle kill sonnet-next-route --server http://localhost:18080 --reason "sonnet-next 5xx"; \
    until ask | grep -q orch; do sleep 0.2; done)
toggle sonnet-next-route: killed=true changed=true

real	0m0.699s
$ ask
served-by=orch model=us.anthropic.claude-sonnet-4-5-v1:0
```

Routing changed 0.7 seconds after the command started. The proxy polls the signed kill list every 2 seconds in the playground, so expect 0 to 2 seconds (the unkill below took 1.8). The reason is recorded in the audit log, and the `--server` URL must be https or loopback because the call carries your session.

## 4. Unkill

```console
$ time (halo toggle kill sonnet-next-route --unkill --server http://localhost:18080 --reason "fixed"; \
    until ask | grep -q served-by=anthropic; do sleep 0.2; done)
toggle sonnet-next-route: killed=false changed=true

real	0m1.808s
$ ask
served-by=anthropic model=claude-sonnet-5-5
```

## 5. Kill an experiment or a rollout

`halo kill NAME` works on experiments, toggles and rollouts (`--kind` disambiguates):

```console
$ halo kill opus-5-5-canary --server http://localhost:18080 --reason "p95 spike"
experiment opus-5-5-canary: killed=true changed=true
$ halo kill opus-5-5-canary --unkill --server http://localhost:18080 --reason "false alarm"
experiment opus-5-5-canary: killed=false changed=true
$ halo kill opus-5-5-upgrade --server http://localhost:18080 --reason "rollout drill"
experiment opus-5-5-canary: killed=true changed=true
next: halo rollout rollback opus-5-5-upgrade --reason ...   (opens the PR that aborts it and re-points rings)
```

A rollout kills its backing experiment. The kill stops the exposure; the policy still says the rollout is active, so follow it with the abort PR from the `next:` line. Clear the drill with `--unkill`, and check the kill is admin-only:

```console
$ HALO_SESSION=<bob's cookie> halo toggle kill sonnet-next-route --server http://localhost:18080 --reason nope
error: toggle kill "sonnet-next-route": server answered 403: {"error":"admin role required"}
```

Tear down when done:

```console
$ make demo-down
```

## What just happened

- `halo kill` posted to `halo-server`, which appended the name to its kill store with an audit entry and re-signed the list with the kill-list key (separate from the release key).
- `halo-proxy` polled the list, verified signature, freshness and replay order, and dropped the killed toggle from routing. No release, ring move or PR was involved, and no client changed.
- The kill is a state change, not a policy change. Policy still says the toggle exists; `--unkill` brings it back, and the abort PR makes a rollback permanent.
- Client toggles work the same way, but `halod` on each device polls on its own interval (60 seconds by default), so those take up to a minute.

## Next

- [Feature toggles](/halos/concepts/toggles/#the-kill-path) and [experiments](/halos/concepts/experiments/#kill-switch)
- [Canary a new model](/halos/tutorials/canary-a-model/): the slower, reviewed rollback path
- [Add a feature toggle](/halos/tutorials/add-a-toggle/)
