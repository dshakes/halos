---
title: Notifications
description: Tell humans what the controller did. Slack, Microsoft Teams, PagerDuty and a signed generic webhook, with per-sink event filters, retries, and PagerDuty incidents that open and resolve themselves.
---

The controller (`halo-server --controller`, or `halo controller run`) acts on verdicts and tells people. This guide wires that to four sinks:

| Sink | What it is | Default events |
|---|---|---|
| Slack | Incoming webhook, `{text, blocks}` | every event |
| Microsoft Teams | Workflows (Power Automate) webhook, Adaptive Card | every event |
| PagerDuty | Events API v2: `trigger` and `resolve` per incident | only what needs a human now, plus the all-clear |
| Webhook | `POST` of the JSON event, HMAC-signed | every event (all-clears are opt-in) |

A notification informs; it never approves. Nothing here merges, promotes or advances anything: a human still merges the PR. Each sink is optional and independent: a sink that is down does not hold back the others, the kill switch or the PR.

## Events and routing

Every sink has an event filter (`--notify-<sink>-events`, a comma-separated list of kinds; `all` means every kind). The kinds, what raises them, and how PagerDuty treats them:

| Kind | Raised when | PagerDuty severity | Default sinks |
|---|---|---|---|
| `experiment.rollback` | A running experiment's verdict is rollback. The kill switch is tripped first when the evidence is gateway-sourced; the message says what happened to it | `error` if the kill is enforced, else `critical` (exposure continues until the pause PR merges) | Slack, Teams, webhook, PagerDuty |
| `experiment.killed` | A running experiment is found killed (an admin kill, or one left from an earlier run). It is not evaluated until someone unkills it | `warning` | Slack, Teams, webhook, PagerDuty |
| `experiment.promote` | The verdict is promote; the controller opened a PR concluding the experiment | `info` (not paged) | Slack, Teams, webhook |
| `experiment.expired` | `maxDays` or `maxSpendUSD` reached without a decision; PR opened | `info` (not paged) | Slack, Teams, webhook |
| `rollout.rollback` | A rollout gate failed and `onFailure` is rollback | as `experiment.rollback` | Slack, Teams, webhook, PagerDuty |
| `rollout.pause` | A rollout gate failed and `onFailure` is pause | `warning` | Slack, Teams, webhook, PagerDuty |
| `rollout.killed` | A rollout's backing experiment is killed; the rollout is held | `warning` | Slack, Teams, webhook, PagerDuty |
| `rollout.advance` | Every gate of the step passed (or the rollout can start); PR opened to move on | `info` (not paged) | Slack, Teams, webhook |
| `rollout.complete` | The last step passed; PR opened for general availability | `info` (not paged) | Slack, Teams, webhook |
| `rollout.frozen` | A change freeze or incident freeze is what holds the rollout | `info` (not paged) | Slack, Teams, webhook |
| `rollout.awaiting_approval` | A step an approval rule covers is waiting for approvals | `info` (not paged) | Slack, Teams, webhook |
| `resolved` | The condition behind an earlier `rollback`, `pause` or `killed` is over (see below) | closes the incident | PagerDuty; webhook if listed |

Each event is delivered once per channel. Informational events (a PR was opened, a freeze holds a rollout) never page: PagerDuty's default filter is `experiment.rollback,experiment.killed,rollout.rollback,rollout.pause,rollout.killed,resolved`. To see one anyway, list it, for example `--notify-pagerduty-events=all,resolved`; it then arrives with severity `info`.

Slack and Teams cannot carry an all-clear, so they reject `resolved`. Slack's payload is byte-for-byte what it was before these sinks existed, and its default (every event) is unchanged.

### Incidents open and resolve themselves

A PagerDuty `trigger` carries a stable `dedup_key` per condition: `halos/experiment/<name>/<verdict>` or `halos/rollout/<name>/<verdict>`. A repeat of the same condition folds into one incident. The matching `resolve` is sent, once, when:

- an experiment that rolled back leaves `running` (a human merged the pause PR);
- an experiment or rollout hold clears because the kill was lifted (unkill);
- an experiment or rollout is deleted from policy while an incident is open (the controller notices a tracked name missing from the loaded policy, sends the `resolve` to each sink that opened one, once, then drops its state);
- a rollout's `rollback` or `pause` clears because the rollout left `active` in policy (a human merged the pause or rollback) or a human moved it to another step.

A `resolve` is sent only for an incident that sink actually opened. If the controller restarts or another replica takes over, no incident is duplicated: the trigger and the resolve are each recorded per sink, and the event id (`event_id` in `custom_details`) is the same on every attempt.

Limits to know: an all-clear is best effort. If it still fails after the retries below, the controller does not hold its own state for it (a restarted experiment must be evaluated regardless), so it is logged and counted (a deletion's all-clear follows the same rule: state is dropped even if it failed) in `halo_controller_notifications_total{result="error"}`, and that incident has to be resolved in PagerDuty by hand. A kill that is lifted and then re-applied within the same experiment run is not announced a second time (the hold is told once per run).

## Reliability

- **Timeouts and redirects.** Each attempt has a 10 second timeout and does not follow redirects.
- **Bounded retries.** A delivery makes up to 3 attempts, waiting 1s then 2s, or the receiver's `Retry-After` when it sends one (up to 15s; a longer one ends the retrying), within 30s in all. Transport errors, timeouts, 429 and 5xx are retried. Any other 4xx (a revoked URL, a bad routing key, a rejected payload) is not: it will not heal.
- **A failed delivery is not lost.** The controller records a notification only once a sink accepted it, so a sink that still fails is tried again on the next tick, alone, without re-posting to the others.
- **Never in the way.** Failures are returned as tick errors (`halo_controller_errors_total`), logged, and counted per sink; they never stop the loop, the kill switch or PR opening.
- **Secrets stay secret.** Webhook URLs (they embed a token) and routing keys are read from files, never flags, never ConfigMaps; no error, log line or metric contains them.
- **Metrics and alert.** `halo_controller_notifications_total{sink,result}` with `result` of `ok`, `error` or `filtered`. The `HaloControllerNotifyFailing` alert (ticket) fires when a sink keeps failing after retries.

## Slack

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel and put the URL in a file or Secret.

```sh
halo-server --controller ... --notify-slack-url-file /secrets/slack-url
```

## Microsoft Teams

Halos targets a Teams **Workflows** (Power Automate) webhook and posts an Adaptive Card, not the legacy Office 365 connector ("Incoming Webhook", MessageCard). Microsoft has retired Office 365 connectors in Teams in favour of Workflows, so a connector URL (`*.webhook.office.com`, `outlook.office.com/webhook`) no longer delivers. Halos refuses those URLs at startup with an explicit error instead of failing quietly later.

1. In Teams, open the channel, then **⋯ > Workflows**.
2. Pick the **Post to a channel when a webhook request is received** template (also listed as "Send webhook alerts to a channel"), name it, choose the team and channel, and finish.
3. Copy the **HTTP POST URL** it shows. It contains a signature, so treat it like a password: put it in a file or Secret.
4. Make sure the workflow's owner account is allowed to post to the channel; the workflow runs as that account, and it stops delivering if the owner leaves or the flow is turned off.

```sh
halo-server --controller ... --notify-teams-url-file /secrets/teams-url
```

The card shows the title (colored red for a rollback, green for a promotion or advance, amber otherwise), the summary sentence, a fact table (verdict, experiment, axis, kill-switch outcome, time) and, when a PR was opened, an **Open pull request** button (https links only). Free text such as the reason has its Markdown escaped, so it cannot inject formatting or links.

## PagerDuty

Use an **Events API v2** integration on the service that should be paged.

1. In PagerDuty: **Services > (your service) > Integrations > Add an integration**, choose **Events API v2**.
2. Copy the **Integration Key**; that is the routing key. Put it in a file or Secret (key `routingKey` in the Helm Secret).
3. Start the controller with the key file. The default endpoint is `https://events.pagerduty.com/v2/enqueue`; for the EU service region pass `--notify-pagerduty-url https://events.eu.pagerduty.com/v2/enqueue`.

```sh
halo-server --controller ... --notify-pagerduty-routing-key-file /secrets/pagerduty-key
```

Payload details: `summary` is the same sentence Slack shows (truncated to PagerDuty's 1024 characters), `source` is `halos-controller`, `component` is `controller`, `group` is the rollout or experiment name, `class` is the event kind, and `custom_details` holds the verdict, reason, kill-switch outcome, PR URL and the idempotency `event_id`. A PR URL is also attached as a link. The routing key travels only in the request body.

Severity mapping:

| Severity | When |
|---|---|
| `critical` | A rollback whose exposure continues: the kill failed, is not configured, is recorded but not enforced, or the evidence was not gateway-sourced (a human must merge the pause PR) |
| `error` | A rollback whose kill switch is enforced: mitigated, needs follow-up |
| `warning` | A rollout paused on a gate breach; a killed experiment or rollout held until someone unkills it |
| `info` | Anything else, only if you list it in `--notify-pagerduty-events` |

Route by severity or by `class` with PagerDuty event rules or the service's urgency settings.

## Generic webhook

`--notify-webhook-url-file` posts the controller's JSON event (`id`, `rollout`, `experiment`, `axis`, `verdict`, `reason`, `killed`, `killOutcome`, `prURL`, `report`, `at`, and `resolved` on an all-clear). With `--notify-webhook-secret-file` it is signed with the same scheme as the SIEM audit export, so a receiver verifies both the same way:

```
X-Halo-Timestamp: <unix seconds>
X-Halo-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
X-Halo-Event-Id:  <idempotency key, also "id" in the body>
```

Verify the HMAC over the raw body, compare in constant time, and reject timestamps more than 5 minutes off. Go and Python snippets: [reference](/halos/reference/binaries/#verifying-the-webhook-signature). Add `resolved` to `--notify-webhook-events` to receive all-clears (`"resolved": true`). Use `X-Halo-Event-Id` to drop a duplicate sent across a controller failover.

## Helm

Create one Secret per sink (or reuse one) and reference it. Never put a URL or key in values.

```sh
kubectl create secret generic halos-pagerduty --from-file=routingKey=./routing-key
kubectl create secret generic halos-teams --from-file=url=./teams-url
```

```yaml
server:
  controller:
    enabled: true
    notify:
      slack:     {existingSecret: halos-slack}                       # key: url
      teams:     {existingSecret: halos-teams, events: "experiment.rollback,rollout.rollback,rollout.pause"}
      webhook:   {existingSecret: halos-webhook, events: "all,resolved"}   # keys: url, secret
      pagerduty: {existingSecret: halos-pagerduty, key: routingKey}        # url: EU endpoint if needed
```

The chart mounts each Secret as a file and passes the matching `--notify-*-file` flags; `values.schema.json` rejects a malformed `events` list. If you use the chart's NetworkPolicy, allow the controller's egress to the sinks with `networkPolicy.controllerEgress.webhook` (port 443): `hooks.slack.com`, `*.logic.azure.com`, `events.pagerduty.com` and your webhook host.

## Flags

| Flag | Purpose |
|---|---|
| `--notify-slack-url-file`, `--notify-slack-events` | Slack webhook URL; event filter |
| `--notify-teams-url-file`, `--notify-teams-events` | Teams Workflows webhook URL; event filter |
| `--notify-webhook-url-file`, `--notify-webhook-secret-file`, `--notify-webhook-events` | Generic webhook URL, HMAC secret; event filter (may include `resolved`) |
| `--notify-pagerduty-routing-key-file`, `--notify-pagerduty-url`, `--notify-pagerduty-events` | Routing key; endpoint override; event filter (may include `resolved`) |

An events flag without its sink's URL or key file is an error, as is an unknown kind. Valid kinds: `experiment.rollback`, `experiment.promote`, `experiment.expired`, `experiment.killed`, `rollout.rollback`, `rollout.pause`, `rollout.advance`, `rollout.complete`, `rollout.killed`, `rollout.frozen`, `rollout.awaiting_approval`, `resolved`, and `all`.
