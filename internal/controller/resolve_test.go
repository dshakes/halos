package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// pdFake is a PagerDuty Events API v2 double: it records every event and
// answers status (settable) with 202.
type pdFake struct {
	mu     sync.Mutex
	events []pdBody
	status int
	srv    *httptest.Server
}

func newPDFake(t *testing.T) *pdFake {
	t.Helper()
	f := &pdFake{status: http.StatusAccepted}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.status/100 == 2 {
			var p pdBody
			if err := json.Unmarshal(b, &p); err == nil {
				f.events = append(f.events, p)
			}
		}
		w.WriteHeader(f.status)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *pdFake) setStatus(s int) { f.mu.Lock(); f.status = s; f.mu.Unlock() }

// actions lists "<action> <dedup_key>" in arrival order.
func (f *pdFake) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.EventAction+" "+e.DedupKey)
	}
	return out
}

// wirePagerDuty makes PagerDuty (default filter, resolves on) and a plain
// webhook the rig's notifiers. Retries are off so a failing fake fails fast.
func wirePagerDuty(t *testing.T, r *rig) (*pdFake, *fakeNotifier) {
	t.Helper()
	pd := newPDFake(t)
	hook := &fakeNotifier{}
	r.c.Notifier = Notifiers{
		&Sink{SinkName: "pagerduty", Notifier: PagerDuty{RoutingKey: "k", URL: pd.srv.URL}, Events: pagerDutyDefaultFilter()},
		&Sink{SinkName: "webhook", Notifier: hook},
	}
	return pd, hook
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestExperimentRollbackTriggersOnceAndResolvesWhenPauseMerges(t *testing.T) {
	r := newRig(t, promote.Rollback)
	pd, hook := wirePagerDuty(t, r)
	ticks(t, r.c, 3)
	eq(t, pd.actions(), "trigger halos/experiment/exp-a/rollback") // repeated ticks never re-page
	if p := pd.events[0].Payload; p.Severity != "error" || p.CustomDetails["pr_url"] == "" {
		t.Fatalf("trigger payload %+v", p)
	}

	r.org.Experiments[0].Status = "paused" // a human merged the pause PR
	ticks(t, r.c, 3)
	eq(t, pd.actions(), "trigger halos/experiment/exp-a/rollback", "resolve halos/experiment/exp-a/rollback")

	// The plain webhook never receives all-clears unless it opts in.
	if len(hook.events) != 1 || hook.events[0].Resolved {
		t.Fatalf("webhook events = %+v", hook.events)
	}

	// A restarted experiment (after an admin lifts the kill) that rolls back
	// again opens a new incident.
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "restart"); err != nil {
		t.Fatal(err)
	}
	r.org.Experiments[0].Status = "running"
	ticks(t, r.c, 1)
	eq(t, pd.actions(), "trigger halos/experiment/exp-a/rollback", "resolve halos/experiment/exp-a/rollback", "trigger halos/experiment/exp-a/rollback")
}

func TestInformationalVerdictsDoNotPage(t *testing.T) {
	for _, v := range []promote.Verdict{promote.Promote, promote.Expired} {
		t.Run(string(v), func(t *testing.T) {
			r := newRig(t, v)
			pd, hook := wirePagerDuty(t, r)
			ticks(t, r.c, 2)
			r.org.Experiments[0].Status = "concluded"
			ticks(t, r.c, 2)
			eq(t, pd.actions()) // nothing, not even an all-clear
			if len(hook.events) != 1 || len(r.w.calls) != 1 {
				t.Fatalf("webhook %d events, %d PRs: the other channels are unaffected", len(hook.events), len(r.w.calls))
			}
		})
	}
}

func TestKilledExperimentPagesAndClearsOnUnkill(t *testing.T) {
	r := newRig(t, promote.Continue)
	pd, _ := wirePagerDuty(t, r)
	if _, err := r.kills.Kill(context.Background(), "exp-a", "alice", "looks wrong"); err != nil {
		t.Fatal(err)
	}
	ticks(t, r.c, 2)
	eq(t, pd.actions(), "trigger halos/experiment/exp-a/killed")
	if sev := pd.events[0].Payload.Severity; sev != "warning" {
		t.Fatalf("severity %s", sev)
	}
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "false alarm"); err != nil {
		t.Fatal(err)
	}
	ticks(t, r.c, 3)
	eq(t, pd.actions(), "trigger halos/experiment/exp-a/killed", "resolve halos/experiment/exp-a/killed")
}

// An all-clear needs a trigger this channel actually sent: no incident was
// opened (the sink was down, or filtered the kind), so none is closed.
func TestNoResolveForAnIncidentNeverOpened(t *testing.T) {
	r := newRig(t, promote.Rollback)
	pd := newPDFake(t)
	pd.setStatus(http.StatusInternalServerError)
	r.c.Notifier = Notifiers{&Sink{SinkName: "pagerduty", Notifier: PagerDuty{RoutingKey: "k", URL: pd.srv.URL}, Events: pagerDutyDefaultFilter()}}
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "pagerduty") {
		t.Fatalf("want the failed page reported, got %v", err)
	}
	r.org.Experiments[0].Status = "paused"
	pd.setStatus(http.StatusAccepted)
	ticks(t, r.c, 2)
	eq(t, pd.actions())

	// Filtered out of the sink's events: also nothing to clear.
	r2 := newRig(t, promote.Rollback)
	pd2 := newPDFake(t)
	r2.c.Notifier = Notifiers{&Sink{SinkName: "pagerduty", Notifier: PagerDuty{RoutingKey: "k", URL: pd2.srv.URL}, Events: EventFilter{KindResolved: true}}}
	ticks(t, r2.c, 1)
	r2.org.Experiments[0].Status = "paused"
	ticks(t, r2.c, 2)
	eq(t, pd2.actions())
}

// A failing sink never stops the controller from resetting its own state: a
// restarted experiment is evaluated even if the all-clear could not be sent.
func TestFailedResolveDoesNotBlockReset(t *testing.T) {
	r := newRig(t, promote.Rollback)
	pd, _ := wirePagerDuty(t, r)
	ticks(t, r.c, 1)
	pd.setStatus(http.StatusServiceUnavailable)
	r.org.Experiments[0].Status = "paused"
	if err := r.c.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "resolve exp-a") {
		t.Fatalf("want the failed all-clear reported, got %v", err)
	}
	if _, done := r.c.State.Done("exp-a", string(promote.Rollback), ActionRollback); done {
		t.Fatal("state not reset: a restarted experiment would be treated as already rolled back")
	}
	pd.setStatus(http.StatusAccepted)
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "restart"); err != nil {
		t.Fatal(err)
	}
	r.org.Experiments[0].Status = "running"
	ticks(t, r.c, 1)
	if got := pd.actions(); len(got) != 2 || got[1] != "trigger halos/experiment/exp-a/rollback" {
		t.Fatalf("actions %q", got)
	}
	var m strings.Builder
	r.c.WriteMetrics(&m)
	if !strings.Contains(m.String(), `halo_controller_notifications_total{sink="pagerduty",result="error"} 1`) {
		t.Fatalf("failure not counted:\n%s", m.String())
	}
}

// With "resolved" opted in, the generic webhook gets a signed all-clear too.
func TestWebhookOptsIntoResolved(t *testing.T) {
	r := newRig(t, promote.Rollback)
	var mu sync.Mutex
	var got []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		var e Event
		_ = json.Unmarshal(b, &e)
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	r.c.Notifier = Notifiers{&Sink{SinkName: "webhook", Notifier: Webhook{URL: srv.URL}, Events: EventFilter{KindExperimentRollback: true, KindResolved: true}}}
	ticks(t, r.c, 1)
	r.org.Experiments[0].Status = "paused"
	ticks(t, r.c, 2)
	if len(got) != 2 || got[0].Resolved || !got[1].Resolved || got[1].Verdict != promote.Rollback || got[1].ID == "" || got[1].ID == got[0].ID {
		t.Fatalf("events = %+v", got)
	}
}

func TestRolloutHaltTriggersAndResolvesWhenPolicyLeavesActive(t *testing.T) {
	r, _, _ := rolloutRig(t, promote.Rollback, "c5")
	pd, _ := wirePagerDuty(t, r)
	ticks(t, r.c, 3)
	eq(t, pd.actions(), "trigger halos/rollout/ro/rollback")
	p := pd.events[0].Payload
	if p.Severity != "error" || p.Class != "rollout.rollback" || p.Group != "ro" {
		t.Fatalf("payload %+v", p)
	}
	r.org.Rollouts[0].Status, r.org.Experiments[0].Status = policy.RolloutAborted, "paused"
	ticks(t, r.c, 3)
	eq(t, pd.actions(), "trigger halos/rollout/ro/rollback", "resolve halos/rollout/ro/rollback")
	if !strings.Contains(string(mustJSON(t, pd.events[1])), `"resolve"`) || pd.events[1].Payload != nil {
		t.Fatalf("resolve event %+v", pd.events[1])
	}
}

func TestRolloutHumanAdvanceClearsPause(t *testing.T) {
	r, _, now := rolloutRig(t, promote.Rollback, "c5")
	r.org.Rollouts[0].Steps[0].OnFailure = "pause"
	pd, _ := wirePagerDuty(t, r)
	ticks(t, r.c, 2)
	eq(t, pd.actions(), "trigger halos/rollout/ro/pause")
	if sev := pd.events[0].Payload.Severity; sev != "warning" {
		t.Fatalf("pause severity %s", sev)
	}
	// A human merges a different step while the pause is open (the policy
	// stays active): the incident is cleared before the controller forgets it.
	*now = now.Add(time.Minute)
	r.org.Rollouts[0].Step = "c25"
	ticks(t, r.c, 1)
	acts := pd.actions()
	if len(acts) < 2 || acts[1] != "resolve halos/rollout/ro/pause" {
		t.Fatalf("actions %q", acts)
	}
}

func TestRolloutKilledExperimentPagesAndClears(t *testing.T) {
	r, _, _ := rolloutRig(t, promote.Continue, "c5")
	pd, _ := wirePagerDuty(t, r)
	if _, err := r.kills.Kill(context.Background(), "exp-a", "alice", "stop"); err != nil {
		t.Fatal(err)
	}
	ticks(t, r.c, 2)
	eq(t, pd.actions(), "trigger halos/rollout/ro/killed")
	if _, err := r.kills.Unkill(context.Background(), "exp-a", "alice", "ok"); err != nil {
		t.Fatal(err)
	}
	ticks(t, r.c, 3)
	acts := pd.actions()
	if len(acts) != 2 || acts[1] != "resolve halos/rollout/ro/killed" {
		t.Fatalf("actions %q", acts)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
