package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PagerDutyEventsURL is the Events API v2 endpoint (the EU service region
// uses https://events.eu.pagerduty.com/v2/enqueue).
const PagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDuty raises and clears incidents through the Events API v2.
//
// A paging event is a "trigger" with a stable dedup_key, so a repeat for the
// same rollout or experiment folds into one incident; the all-clear (the
// condition ended: a human merged the pause or advanced the rollout, or the
// kill was lifted) is a "resolve" with the same dedup_key. Informational
// events (a PR opened, a promotion proposed, a freeze) do not page: the
// default event filter excludes them, and they map to severity "info" if an
// operator opts them in.
//
// The routing key is a secret: it travels only in the request body, and no
// error or log line contains it.
type PagerDuty struct {
	RoutingKey string
	URL        string // default PagerDutyEventsURL
	Source     string // payload.source, the affected system (default "halos-controller")
	Client     *http.Client
	Retry      RetryPolicy // zero: one attempt
}

// Name implements Named.
func (PagerDuty) Name() string { return "pagerduty" }

// PagerDutyPagingKinds is the default event filter of the PagerDuty sink:
// everything that needs a human now, plus the all-clear.
var PagerDutyPagingKinds = []string{
	KindExperimentRollback, KindExperimentKilled,
	KindRolloutRollback, KindRolloutPause, KindRolloutKilled,
	KindResolved,
}

// DedupKey is the stable PagerDuty dedup_key of the condition e reports: one
// per rollout (or, for a standalone experiment, per experiment) and verdict.
func (e Event) DedupKey() string {
	if e.Rollout != "" {
		return "halos/rollout/" + e.Rollout + "/" + string(e.Verdict)
	}
	return "halos/experiment/" + e.Experiment + "/" + string(e.Verdict)
}

// PagerDutySeverity maps e to a PagerDuty severity.
//
//	critical  a rollback whose exposure continues: the kill switch is not
//	          enforced (failed, not configured, recorded only, or the
//	          evidence was not gateway-sourced), so users stay on the
//	          treatment until a human merges the pause PR
//	error     a rollback whose kill switch is enforced (mitigated, needs
//	          follow-up)
//	warning   a rollout paused on a gate breach, or a killed experiment
//	          held until someone unkills it
//	info      anything else (only delivered when an operator opts it in)
func (e Event) PagerDutySeverity() string {
	switch e.Verdict {
	case "rollback":
		if e.KillOutcome == KillEnforced {
			return "error"
		}
		return "critical"
	case "pause", VerdictKilled:
		return "warning"
	}
	return "info"
}

const pagerDutySummaryMax = 1024 // Events API v2 limit

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (p PagerDuty) Notify(ctx context.Context, e Event) error {
	var msg map[string]any
	if e.Resolved {
		msg = map[string]any{"routing_key": p.RoutingKey, "event_action": "resolve", "dedup_key": e.DedupKey()}
	} else {
		source := p.Source
		if source == "" {
			source = "halos-controller"
		}
		details := map[string]any{"verdict": string(e.Verdict), "reason": e.Reason}
		for k, v := range map[string]string{
			"experiment": e.Experiment, "rollout": e.Rollout, "axis": e.Axis, "kill_outcome": string(e.KillOutcome),
			"kill_error": e.KillError, "pr_url": e.PRURL, "pr_error": e.PRError, "event_id": e.ID,
		} {
			if v != "" {
				details[k] = v
			}
		}
		at := e.At
		if at.IsZero() {
			at = time.Now()
		}
		group := e.Experiment
		if e.Rollout != "" {
			group = e.Rollout
		}
		msg = map[string]any{
			"routing_key": p.RoutingKey, "event_action": "trigger", "dedup_key": e.DedupKey(),
			"payload": map[string]any{
				"summary":        truncateRunes(e.Text(), pagerDutySummaryMax),
				"source":         source,
				"severity":       e.PagerDutySeverity(),
				"timestamp":      at.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
				"component":      "controller",
				"group":          group,
				"class":          e.Kind(),
				"custom_details": details,
			},
		}
		if httpsURL(e.PRURL) {
			msg["links"] = []any{map[string]string{"href": e.PRURL, "text": "Pull request"}}
		}
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("pagerduty notify: encode: %w", err)
	}
	u := p.URL
	if u == "" {
		u = PagerDutyEventsURL
	}
	return deliver(ctx, p.Retry, p.Client, "pagerduty", u, body, http.Header{})
}
