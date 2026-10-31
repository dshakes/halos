package controller

import (
	"context"
	"net/http"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

// TestSlackGolden pins the exact bytes posted to Slack. The notifier refactor
// (sinks, filters, retries) must not change what an existing Slack channel
// receives.
func TestSlackGolden(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		want string
	}{
		{"rollback enforced", testEvent(), `{"blocks":[{"text":{"text":"Halos experiment exp-\u0026lt;a\u0026gt;: ROLLBACK (guardrail regressed). Kill switch tripped: gateways route everyone to control. PR: https://gh/pr/1","type":"mrkdwn"},"type":"section"}],"text":"Halos experiment exp-\u0026lt;a\u0026gt;: ROLLBACK (guardrail regressed). Kill switch tripped: gateways route everyone to control. PR: https://gh/pr/1"}`},
		{"rollout halt", Event{Rollout: "r-1", Experiment: "e", Axis: "traffic", Verdict: promote.Rollback, Reason: "gate x failed & y", KillOutcome: KillNotGateway, KillError: "ignored"}, `{"blocks":[{"text":{"text":"Halos rollout r-1: ROLLBACK (gate x failed \u0026amp; y). Not auto-killed: rollback decided on non-gateway (CLI or eval) evidence; merge the pause PR","type":"mrkdwn"},"type":"section"}],"text":"Halos rollout r-1: ROLLBACK (gate x failed \u0026amp; y). Not auto-killed: rollback decided on non-gateway (CLI or eval) evidence; merge the pause PR"}`},
		{"promote pr failed", Event{Experiment: "e", Verdict: promote.Promote, Reason: "wins", PRError: "PR failed"}, `{"blocks":[{"text":{"text":"Halos experiment e: PROMOTE (wins). PR not opened yet (PR failed); will retry","type":"mrkdwn"},"type":"section"}],"text":"Halos experiment e: PROMOTE (wins). PR not opened yet (PR failed); will retry"}`},
		{"killed", Event{Experiment: "e", Verdict: VerdictKilled, Reason: "experiment e is killed", Killed: true}, `{"blocks":[{"text":{"text":"Halos experiment e: KILLED (experiment e is killed)","type":"mrkdwn"},"type":"section"}],"text":"Halos experiment e: KILLED (experiment e is killed)"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, ch := capture(t, http.StatusOK)
			if err := (Slack{URL: srv.URL}).Notify(context.Background(), tt.ev); err != nil {
				t.Fatal(err)
			}
			got := <-ch
			if string(got.body) != tt.want {
				t.Fatalf("slack body changed:\n got: %s\nwant: %s", got.body, tt.want)
			}
			if ct := got.hdr.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type %q", ct)
			}
		})
	}
}
