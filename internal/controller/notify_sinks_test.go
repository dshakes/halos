package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/promote"
)

// script serves the given statuses in order (the last repeats) and records
// every request body. retryAfter, when non-empty, is sent on non-2xx answers.
type script struct {
	mu         sync.Mutex
	statuses   []int
	retryAfter string
	bodies     [][]byte
	hdrs       []http.Header
	srv        *httptest.Server
}

func newScript(t *testing.T, retryAfter string, statuses ...int) *script {
	t.Helper()
	s := &script{statuses: statuses, retryAfter: retryAfter}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		i := min(len(s.bodies), len(s.statuses)-1)
		s.bodies = append(s.bodies, b)
		s.hdrs = append(s.hdrs, r.Header.Clone())
		code := s.statuses[i]
		s.mu.Unlock()
		if code/100 != 2 && s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *script) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

// fakeClock drives a RetryPolicy without sleeping: Sleep advances Now.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) policy(attempts int, base, maxWait, budget time.Duration) RetryPolicy {
	return RetryPolicy{
		Attempts: attempts, Base: base, MaxWait: maxWait, Budget: budget,
		Now: func() time.Time { return c.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.sleeps = append(c.sleeps, d)
			c.now = c.now.Add(d)
			return nil
		},
	}
}

func TestDeliverRetry(t *testing.T) {
	epoch := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		statuses   []int
		retryAfter string
		policy     func(c *fakeClock) RetryPolicy
		wantCalls  int
		wantSleeps []time.Duration
		wantErr    string // "" = success
	}{
		{"5xx then ok: exponential backoff", []int{500, 502, 202}, "", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			3, []time.Duration{time.Second, 2 * time.Second}, ""},
		{"429 honours Retry-After seconds", []int{429, 202}, "7", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			2, []time.Duration{7 * time.Second}, ""},
		{"429 honours Retry-After http-date", []int{429, 202}, epoch.Add(9 * time.Second).UTC().Format(http.TimeFormat), func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			2, []time.Duration{9 * time.Second}, ""},
		{"gives up after Attempts", []int{503}, "", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			3, []time.Duration{time.Second, 2 * time.Second}, "HTTP 503"},
		{"400 is never retried", []int{400, 202}, "", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			1, nil, "HTTP 400"},
		{"404 is never retried", []int{404}, "", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			1, nil, "HTTP 404"},
		{"Retry-After beyond MaxWait ends retrying", []int{429, 202}, "600", func(c *fakeClock) RetryPolicy { return c.policy(3, time.Second, 15*time.Second, 0) },
			1, nil, "HTTP 429"},
		{"backoff capped at MaxWait", []int{500}, "", func(c *fakeClock) RetryPolicy { return c.policy(4, 10*time.Second, 15*time.Second, 0) },
			4, []time.Duration{10 * time.Second, 15 * time.Second, 15 * time.Second}, "HTTP 500"},
		{"Budget stops before another wait", []int{500}, "", func(c *fakeClock) RetryPolicy { return c.policy(5, 10*time.Second, 60*time.Second, 25*time.Second) },
			2, []time.Duration{10 * time.Second}, "HTTP 500"},
		{"zero policy: one attempt", []int{500, 202}, "", func(*fakeClock) RetryPolicy { return RetryPolicy{} },
			1, nil, "HTTP 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newScript(t, tt.retryAfter, tt.statuses...)
			clock := &fakeClock{now: epoch}
			err := deliver(context.Background(), tt.policy(clock), nil, "slack", srv.srv.URL+"/services/SECRET", []byte(`{"a":1}`), http.Header{})
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if got := srv.calls(); got != tt.wantCalls {
				t.Errorf("calls = %d, want %d", got, tt.wantCalls)
			}
			if fmt.Sprint(clock.sleeps) != fmt.Sprint(tt.wantSleeps) {
				t.Errorf("sleeps = %v, want %v", clock.sleeps, tt.wantSleeps)
			}
			for i, b := range srv.bodies {
				if string(b) != `{"a":1}` {
					t.Errorf("attempt %d body = %q: a retry must resend the same body", i, b)
				}
			}
			if err != nil && (strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), srv.srv.URL)) {
				t.Errorf("error leaks the URL: %v", err)
			}
		})
	}
}

// A transport failure is retried; a cancelled context is not.
func TestDeliverTransportRetry(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close() // reset mid-request
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	clock := &fakeClock{now: time.Now()}
	if err := deliver(context.Background(), clock.policy(3, time.Second, 5*time.Second, 0), nil, "teams", srv.URL, []byte(`{}`), nil); err != nil {
		t.Fatalf("want success after a reset: %v", err)
	}
	if n.Load() != 2 || len(clock.sleeps) != 1 {
		t.Fatalf("calls %d sleeps %v", n.Load(), clock.sleeps)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n.Store(0)
	clock = &fakeClock{now: time.Now()}
	err := deliver(ctx, clock.policy(3, time.Second, 5*time.Second, 0), nil, "teams", srv.URL, []byte(`{}`), nil)
	if !errors.Is(err, context.Canceled) || len(clock.sleeps) != 0 {
		t.Fatalf("cancelled: err %v sleeps %v", err, clock.sleeps)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":     0,
		"5":    5 * time.Second,
		" 5 ":  5 * time.Second,
		"-3":   0,
		"soon": 0,
		now.Add(time.Minute).Format(http.TimeFormat):  time.Minute,
		now.Add(-time.Minute).Format(http.TimeFormat): 0,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTeamsCard(t *testing.T) {
	srv := newScript(t, "", http.StatusAccepted)
	ev := Event{Rollout: "ro", Experiment: "exp-a", Axis: "traffic", Verdict: promote.Rollback, Reason: "cost *regressed* [x](http://evil)",
		Killed: true, KillOutcome: KillEnforced, PRURL: "https://github.test/pr/9", At: start}
	if err := (Teams{URL: srv.srv.URL + "/workflows/SECRET"}).Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Schema  string `json:"$schema"`
				Type    string `json:"type"`
				Version string `json:"version"`
				Body    []struct {
					Type  string `json:"type"`
					Text  string `json:"text"`
					Color string `json:"color"`
					Facts []struct{ Title, Value string }
				} `json:"body"`
				Actions []struct{ Type, Title, URL string } `json:"actions"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(srv.bodies[0], &m); err != nil {
		t.Fatal(err)
	}
	if m.Type != "message" || len(m.Attachments) != 1 || m.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("envelope: %s", srv.bodies[0])
	}
	c := m.Attachments[0].Content
	if c.Type != "AdaptiveCard" || c.Version != "1.4" || !strings.HasPrefix(c.Schema, "http://adaptivecards.io/schemas/") || len(c.Body) != 3 {
		t.Fatalf("card: %s", srv.bodies[0])
	}
	if c.Body[0].Color != "Attention" || !strings.Contains(c.Body[0].Text, "rollout ro: ROLLBACK") {
		t.Errorf("title block: %+v", c.Body[0])
	}
	if !strings.Contains(c.Body[1].Text, `\*regressed\*`) || !strings.Contains(c.Body[1].Text, `\[x\]`) || strings.Contains(c.Body[1].Text, " *regressed*") {
		t.Errorf("markdown in the reason must be escaped: %q", c.Body[1].Text)
	}
	if len(c.Actions) != 1 || c.Actions[0].Type != "Action.OpenUrl" || c.Actions[0].URL != "https://github.test/pr/9" {
		t.Errorf("actions: %+v", c.Actions)
	}
	facts := map[string]string{}
	for _, f := range c.Body[2].Facts {
		facts[f.Title] = f.Value
	}
	if facts["Verdict"] != "rollback" || facts["Kill switch"] != "enforced" || facts["Experiment"] != "exp-a" || facts["Axis"] != "traffic" {
		t.Errorf("facts: %v", facts)
	}

	// A non-https PR link is not offered as a button.
	ev.PRURL = "javascript:alert(1)"
	if err := (Teams{URL: srv.srv.URL}).Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(srv.bodies[1], []byte("Action.OpenUrl")) {
		t.Errorf("unsafe PR URL became an action: %s", srv.bodies[1])
	}
}

func TestTeamsColor(t *testing.T) {
	for _, tc := range []struct {
		ev   Event
		want string
	}{
		{Event{Verdict: promote.Rollback}, "Attention"},
		{Event{Verdict: promote.Promote}, "Good"},
		{Event{Verdict: "pause"}, "Warning"},
		{Event{Verdict: "frozen"}, "Warning"},
	} {
		if got := teamsColor(tc.ev); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.ev.Verdict, got, tc.want)
		}
	}
}

type pdBody struct {
	RoutingKey  string `json:"routing_key"`
	EventAction string `json:"event_action"`
	DedupKey    string `json:"dedup_key"`
	Payload     *struct {
		Summary       string         `json:"summary"`
		Source        string         `json:"source"`
		Severity      string         `json:"severity"`
		Timestamp     string         `json:"timestamp"`
		Component     string         `json:"component"`
		Group         string         `json:"group"`
		Class         string         `json:"class"`
		CustomDetails map[string]any `json:"custom_details"`
	} `json:"payload"`
	Links []struct{ Href, Text string } `json:"links"`
}

func decodePD(t *testing.T, b []byte) pdBody {
	t.Helper()
	var p pdBody
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("pagerduty body: %v\n%s", err, b)
	}
	return p
}

func TestPagerDutyTriggerAndResolve(t *testing.T) {
	srv := newScript(t, "", http.StatusAccepted)
	pd := PagerDuty{RoutingKey: "R0UTINGKEY", URL: srv.srv.URL}
	ev := Event{ID: "intent-1", Experiment: "exp-a", Axis: "traffic", Verdict: promote.Rollback, Reason: "guardrail regressed",
		KillOutcome: KillEnforced, Killed: true, PRURL: "https://github.test/pr/1", At: time.Date(2026, 3, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))}
	if err := pd.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	res := ev
	res.Resolved, res.Reason = true, "the experiment left running"
	if err := pd.Notify(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	trig, clear := decodePD(t, srv.bodies[0]), decodePD(t, srv.bodies[1])

	if trig.RoutingKey != "R0UTINGKEY" || trig.EventAction != "trigger" || trig.DedupKey != "halos/experiment/exp-a/rollback" {
		t.Fatalf("trigger: %+v", trig)
	}
	p := trig.Payload
	if p == nil || p.Severity != "error" || p.Source != "halos-controller" || p.Group != "exp-a" || p.Class != "experiment.rollback" ||
		p.Timestamp != "2026-03-01T11:00:00.000Z" || !strings.HasPrefix(p.Summary, "Halos experiment exp-a: ROLLBACK") {
		t.Fatalf("payload: %+v", p)
	}
	if p.CustomDetails["event_id"] != "intent-1" || p.CustomDetails["pr_url"] != "https://github.test/pr/1" || p.CustomDetails["kill_outcome"] != "enforced" {
		t.Errorf("custom_details: %v", p.CustomDetails)
	}
	if len(trig.Links) != 1 || trig.Links[0].Href != "https://github.test/pr/1" {
		t.Errorf("links: %+v", trig.Links)
	}
	// The all-clear carries the same dedup_key and nothing else of substance.
	if clear.EventAction != "resolve" || clear.DedupKey != trig.DedupKey || clear.RoutingKey != "R0UTINGKEY" || clear.Payload != nil {
		t.Fatalf("resolve: %+v", clear)
	}
	if got := srv.hdrs[0].Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type %q", got)
	}
}

func TestPagerDutySeverityAndDedup(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		sev  string
		key  string
	}{
		{"rollback, kill enforced", Event{Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillEnforced}, "error", "halos/experiment/e/rollback"},
		{"rollback, kill failed", Event{Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillFailed}, "critical", "halos/experiment/e/rollback"},
		{"rollback, kill not configured", Event{Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillNotConfigured}, "critical", "halos/experiment/e/rollback"},
		{"rollback, kill recorded only", Event{Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillRecorded}, "critical", "halos/experiment/e/rollback"},
		{"rollback, non-gateway evidence", Event{Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillNotGateway}, "critical", "halos/experiment/e/rollback"},
		{"rollout rollback", Event{Rollout: "ro", Experiment: "e", Verdict: promote.Rollback, KillOutcome: KillEnforced}, "error", "halos/rollout/ro/rollback"},
		{"rollout pause", Event{Rollout: "ro", Experiment: "e", Verdict: "pause"}, "warning", "halos/rollout/ro/pause"},
		{"experiment killed", Event{Experiment: "e", Verdict: VerdictKilled}, "warning", "halos/experiment/e/killed"},
		{"rollout killed", Event{Rollout: "ro", Verdict: VerdictKilled}, "warning", "halos/rollout/ro/killed"},
		{"promote is informational", Event{Experiment: "e", Verdict: promote.Promote}, "info", "halos/experiment/e/promote"},
		{"expired is informational", Event{Experiment: "e", Verdict: promote.Expired}, "info", "halos/experiment/e/expired"},
		{"advance is informational", Event{Rollout: "ro", Verdict: "advance"}, "info", "halos/rollout/ro/advance"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.PagerDutySeverity(); got != tt.sev {
				t.Errorf("severity = %s, want %s", got, tt.sev)
			}
			// The key is stable: the same condition always has the same key,
			// whatever the event id, time, reason or PR.
			a, b := tt.ev, tt.ev
			b.ID, b.At, b.Reason, b.PRURL = "other", start, "another reason", "https://x/2"
			if a.DedupKey() != tt.key || b.DedupKey() != tt.key {
				t.Errorf("dedup keys %q / %q, want %q", a.DedupKey(), b.DedupKey(), tt.key)
			}
			// A resolve closes the incident its trigger opened.
			r := tt.ev
			r.Resolved = true
			if r.DedupKey() != tt.key {
				t.Errorf("resolve key %q != trigger key %q", r.DedupKey(), tt.key)
			}
		})
	}
}

func TestPagerDutySummaryTruncated(t *testing.T) {
	srv := newScript(t, "", http.StatusAccepted)
	ev := Event{Experiment: "e", Verdict: promote.Rollback, Reason: strings.Repeat("é", 3000), At: start}
	if err := (PagerDuty{RoutingKey: "k", URL: srv.srv.URL}).Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	s := decodePD(t, srv.bodies[0]).Payload.Summary
	if n := len([]rune(s)); n != pagerDutySummaryMax || !strings.HasSuffix(s, "…") {
		t.Fatalf("summary is %d runes", n)
	}
}

// The routing key is a secret: it goes in the body only, never into an error.
func TestPagerDutyRoutingKeyNeverInErrors(t *testing.T) {
	const key = "ROUTINGKEY-LEAKCANARY"
	for _, code := range []int{400, 429, 500} {
		srv := newScript(t, "", code)
		clock := &fakeClock{now: start}
		err := (PagerDuty{RoutingKey: key, URL: srv.srv.URL, Retry: clock.policy(3, time.Second, 5*time.Second, 0)}).Notify(context.Background(), testEvent())
		if err == nil || strings.Contains(err.Error(), key) || strings.Contains(err.Error(), srv.srv.URL) {
			t.Fatalf("HTTP %d: err = %v", code, err)
		}
		for k, v := range srv.hdrs[0] {
			if strings.Contains(strings.Join(v, ","), key) {
				t.Fatalf("routing key in header %s", k)
			}
		}
	}
	err := (PagerDuty{RoutingKey: key, URL: "http://127.0.0.1:1/v2/enqueue"}).Notify(context.Background(), testEvent())
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("transport error: %v", err)
	}
}

// The generic webhook signs with the scheme the audit export documents
// (internal/server): receivers verify both the same way with Verify.
func TestWebhookResolvedEventIsSigned(t *testing.T) {
	srv := newScript(t, "", http.StatusAccepted)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ev := testEvent()
	ev.Resolved, ev.Reason = true, "cleared"
	if err := (Webhook{URL: srv.srv.URL, Secret: []byte("k-0123456789abcdef"), Now: func() time.Time { return now }}).Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte("k-0123456789abcdef"), srv.hdrs[0], srv.bodies[0], now, WebhookTolerance); err != nil {
		t.Fatalf("receiver cannot verify: %v", err)
	}
	var got Event
	if err := json.Unmarshal(srv.bodies[0], &got); err != nil || !got.Resolved {
		t.Fatalf("resolved flag lost: %s", srv.bodies[0])
	}
	if got.Text() != "Halos experiment exp-<a>: ROLLBACK resolved (cleared)" {
		t.Errorf("text %q", got.Text())
	}
}

func TestParseEventFilter(t *testing.T) {
	tests := []struct {
		name          string
		spec          string
		allowResolved bool
		want          []string // sorted kinds; nil = default filter
		wantErr       string
	}{
		{"empty is the default", "", true, nil, ""},
		{"one kind", "experiment.rollback", false, []string{"experiment.rollback"}, ""},
		{"several, spaced", " experiment.rollback , rollout.pause ", false, []string{"experiment.rollback", "rollout.pause"}, ""},
		{"all is every trigger", "all", true, append([]string(nil), EventKinds[:len(EventKinds)-1]...), ""},
		{"resolved where allowed", "experiment.rollback,resolved", true, []string{"experiment.rollback", "resolved"}, ""},
		{"resolved where not", "resolved", false, nil, "cannot deliver"},
		{"unknown kind", "rollback", true, nil, "unknown event kind"},
		{"only commas", ",", true, nil, "no event kinds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseEventFilter("--x-events", tt.spec, tt.allowResolved)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == nil && f != nil {
				t.Fatalf("filter = %v, want nil", f)
			}
			for _, k := range tt.want {
				if !f[k] {
					t.Errorf("missing %s in %v", k, f)
				}
			}
			if len(f) != len(tt.want) {
				t.Errorf("filter = %v, want exactly %v", f, tt.want)
			}
		})
	}
}

// Every kind the filter accepts is a kind the controller can emit, and the
// documented list matches the code.
func TestEventKinds(t *testing.T) {
	for _, tc := range []struct {
		ev   Event
		want string
	}{
		{Event{Verdict: promote.Rollback}, KindExperimentRollback},
		{Event{Verdict: promote.Promote}, KindExperimentPromote},
		{Event{Verdict: promote.Expired}, KindExperimentExpired},
		{Event{Verdict: VerdictKilled}, KindExperimentKilled},
		{Event{Rollout: "r", Verdict: "rollback"}, KindRolloutRollback},
		{Event{Rollout: "r", Verdict: "pause"}, KindRolloutPause},
		{Event{Rollout: "r", Verdict: "advance"}, KindRolloutAdvance},
		{Event{Rollout: "r", Verdict: "complete"}, KindRolloutComplete},
		{Event{Rollout: "r", Verdict: VerdictKilled}, KindRolloutKilled},
		{Event{Rollout: "r", Verdict: "frozen"}, KindRolloutFrozen},
		{Event{Rollout: "r", Verdict: "awaiting_approval"}, KindRolloutAwaitingApproval},
		{Event{Rollout: "r", Verdict: "rollback", Resolved: true}, KindResolved},
	} {
		if got := tc.ev.Kind(); got != tc.want {
			t.Errorf("%+v: kind %q, want %q", tc.ev, got, tc.want)
		}
		found := false
		for _, k := range EventKinds {
			found = found || k == tc.want
		}
		if !found {
			t.Errorf("%q is not in EventKinds", tc.want)
		}
	}
}

func TestSinkFilterAndMetrics(t *testing.T) {
	srv := newScript(t, "", http.StatusOK)
	bad := newScript(t, "", http.StatusForbidden)
	slack := &Sink{SinkName: "slack", Notifier: Slack{URL: srv.srv.URL}, Events: EventFilter{KindExperimentRollback: true}}
	hook := &Sink{SinkName: "webhook", Notifier: Webhook{URL: bad.srv.URL}} // default filter: all but resolved
	ns := Notifiers{slack, hook}

	rb, pr := testEvent(), Event{Experiment: "e", Verdict: promote.Promote}
	res := rb
	res.Resolved = true
	for _, ev := range []Event{rb, pr, res} {
		_ = ns.Notify(context.Background(), ev)
	}
	if srv.calls() != 1 {
		t.Errorf("slack got %d posts, want 1 (promote filtered, resolved never sent to a filter without it)", srv.calls())
	}
	if bad.calls() != 2 {
		t.Errorf("webhook got %d posts, want 2 (rollback and promote; resolved is opt-in)", bad.calls())
	}
	// A filtered event is a success: nothing to retry on the next tick.
	if err := slack.Notify(context.Background(), pr); err != nil {
		t.Errorf("filtered event reported %v", err)
	}
	var out bytes.Buffer
	ns.WriteMetrics(&out)
	for _, want := range []string{
		"# TYPE halo_controller_notifications_total counter\n",
		`halo_controller_notifications_total{sink="slack",result="ok"} 1`,
		`halo_controller_notifications_total{sink="slack",result="error"} 0`,
		`halo_controller_notifications_total{sink="slack",result="filtered"} 3`,
		`halo_controller_notifications_total{sink="webhook",result="ok"} 0`,
		`halo_controller_notifications_total{sink="webhook",result="error"} 2`,
		`halo_controller_notifications_total{sink="webhook",result="filtered"} 1`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics missing %q in:\n%s", want, out.String())
		}
	}
}

func TestSinkResolvesFor(t *testing.T) {
	pd := &Sink{SinkName: "pagerduty", Notifier: PagerDuty{}, Events: pagerDutyDefaultFilter()}
	only := &Sink{SinkName: "pagerduty", Notifier: PagerDuty{}, Events: EventFilter{KindExperimentRollback: true, KindResolved: true}}
	noResolve := &Sink{SinkName: "pagerduty", Notifier: PagerDuty{}, Events: EventFilter{KindExperimentRollback: true}}
	hook := &Sink{SinkName: "webhook", Notifier: Webhook{}}
	roll, killed := Event{Experiment: "e", Verdict: promote.Rollback}, Event{Experiment: "e", Verdict: VerdictKilled}
	for _, tc := range []struct {
		name string
		s    *Sink
		ev   Event
		want bool
	}{
		{"default pagerduty, rollback", pd, roll, true},
		{"default pagerduty, killed", pd, killed, true},
		{"promote never opened an incident", pd, Event{Experiment: "e", Verdict: promote.Promote}, false},
		{"killed filtered out: no resolve for an incident never opened", only, killed, false},
		{"rollback", only, roll, true},
		{"did not opt into resolved", noResolve, roll, false},
		{"webhook default: no all-clears", hook, roll, false},
	} {
		if got := tc.s.ResolvesFor(tc.ev); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNotifyConfigBuild(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	slack := write("slack", "https://hooks.slack.test/SECRETPATH")
	teams := write("teams", "https://prod-12.westus.logic.azure.com:443/workflows/SECRETPATH/triggers/manual/paths/invoke?sig=SECRETSIG")
	legacy := write("legacy", "https://contoso.webhook.office.com/webhookb2/SECRETPATH")
	legacy2 := write("legacy2", "https://outlook.office.com/webhook/SECRETPATH")
	hook := write("hook", "https://hooks.test/SECRETPATH")
	key := write("key", "R0UTINGKEYSECRET")
	spacey := write("spacey", "ROUTING KEY SECRET")
	cfg := func(f func(*NotifyConfig)) NotifyConfig {
		var c NotifyConfig
		f(&c)
		return c
	}
	tests := []struct {
		name    string
		c       NotifyConfig
		want    []string
		wantErr string
	}{
		{"none", NotifyConfig{}, nil, ""},
		{"all four", cfg(func(c *NotifyConfig) {
			c.SlackURLFile, c.TeamsURLFile, c.WebhookURLFile, c.PagerDutyRoutingKeyFile = slack, teams, hook, key
		}), []string{"slack", "teams", "webhook", "pagerduty"}, ""},
		{"filters", cfg(func(c *NotifyConfig) {
			c.SlackURLFile, c.SlackEvents, c.PagerDutyRoutingKeyFile, c.PagerDutyEvents = slack, "experiment.rollback", key, "all,resolved"
		}), []string{"slack", "pagerduty"}, ""},
		{"legacy O365 connector (webhook.office.com)", cfg(func(c *NotifyConfig) { c.TeamsURLFile = legacy }), nil, "retired Office 365 connector"},
		{"legacy O365 connector (outlook.office.com)", cfg(func(c *NotifyConfig) { c.TeamsURLFile = legacy2 }), nil, "retired Office 365 connector"},
		{"slack events without slack", cfg(func(c *NotifyConfig) { c.SlackEvents = "all" }), nil, "without --notify-slack-url-file"},
		{"teams events without teams", cfg(func(c *NotifyConfig) { c.TeamsEvents = "all" }), nil, "without --notify-teams-url-file"},
		{"webhook events without webhook", cfg(func(c *NotifyConfig) { c.WebhookEvents = "all" }), nil, "without --notify-webhook-url-file"},
		{"pagerduty url without key", cfg(func(c *NotifyConfig) { c.PagerDutyURL = "https://events.eu.pagerduty.com/v2/enqueue" }), nil, "without --notify-pagerduty-routing-key-file"},
		{"unknown kind", cfg(func(c *NotifyConfig) { c.SlackURLFile, c.SlackEvents = slack, "nope" }), nil, "unknown event kind"},
		{"slack cannot resolve", cfg(func(c *NotifyConfig) { c.SlackURLFile, c.SlackEvents = slack, "resolved" }), nil, "cannot deliver"},
		{"teams cannot resolve", cfg(func(c *NotifyConfig) { c.TeamsURLFile, c.TeamsEvents = teams, "resolved" }), nil, "cannot deliver"},
		{"routing key with whitespace", cfg(func(c *NotifyConfig) { c.PagerDutyRoutingKeyFile = spacey }), nil, "not a routing key"},
		{"pagerduty over plain http", cfg(func(c *NotifyConfig) { c.PagerDutyRoutingKeyFile, c.PagerDutyURL = key, "http://events.example.com/x" }), nil, "must be https"},
		{"pagerduty over loopback http", cfg(func(c *NotifyConfig) { c.PagerDutyRoutingKeyFile, c.PagerDutyURL = key, "http://127.0.0.1:9/x" }), []string{"pagerduty"}, ""},
		{"missing key file", cfg(func(c *NotifyConfig) { c.PagerDutyRoutingKeyFile = filepath.Join(dir, "nope") }), nil, "--notify-pagerduty-routing-key-file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, err := tt.c.Build()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Fatalf("error leaks a secret: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, n := range ns {
				got = append(got, n.(*Sink).SinkName)
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("sinks = %v, want %v", got, tt.want)
			}
		})
	}

	// Defaults: PagerDuty pages only on what needs a human; the others keep
	// delivering everything (nil filter), so existing Slack setups are unchanged.
	var c NotifyConfig
	c.SlackURLFile, c.PagerDutyRoutingKeyFile = slack, key
	ns, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	s, p := ns[0].(*Sink), ns[1].(*Sink)
	if s.Events != nil {
		t.Errorf("slack default filter = %v, want nil (everything)", s.Events)
	}
	for _, k := range EventKinds {
		want := false
		for _, pk := range PagerDutyPagingKinds {
			want = want || pk == k
		}
		if got := p.Events[k]; got != want {
			t.Errorf("pagerduty default filter[%s] = %v, want %v", k, got, want)
		}
	}
	// The retry policy reaches every sink.
	c.Retry = DefaultRetry
	ns, _ = c.Build()
	if ns[0].(*Sink).Notifier.(Slack).Retry.Attempts != 3 || ns[1].(*Sink).Notifier.(PagerDuty).Retry.Attempts != 3 {
		t.Error("retry policy not applied")
	}
}

// Informational events never page, under the default configuration.
func TestPagerDutyDefaultsDoNotPageInformationalEvents(t *testing.T) {
	srv := newScript(t, "", http.StatusAccepted)
	sink := &Sink{SinkName: "pagerduty", Notifier: PagerDuty{RoutingKey: "k", URL: srv.srv.URL}, Events: pagerDutyDefaultFilter()}
	for _, ev := range []Event{
		{Experiment: "e", Verdict: promote.Promote, PRURL: "https://x/1"},
		{Experiment: "e", Verdict: promote.Expired},
		{Rollout: "r", Verdict: "advance"}, {Rollout: "r", Verdict: "complete"},
		{Rollout: "r", Verdict: "frozen"}, {Rollout: "r", Verdict: "awaiting_approval"},
	} {
		if err := sink.Notify(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	if srv.calls() != 0 {
		t.Fatalf("%d informational events reached PagerDuty", srv.calls())
	}
	for _, ev := range []Event{
		{Experiment: "e", Verdict: promote.Rollback}, {Experiment: "e", Verdict: VerdictKilled},
		{Rollout: "r", Verdict: "rollback"}, {Rollout: "r", Verdict: "pause"}, {Rollout: "r", Verdict: VerdictKilled},
	} {
		if err := sink.Notify(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	if srv.calls() != 5 {
		t.Fatalf("paging events delivered: %d, want 5", srv.calls())
	}
}

// halo-server (stdlib flag) and `halo controller run` (pflag) share one set of
// flags through NotifyFlags.
func TestNotifyFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	var c NotifyConfig
	NotifyFlags(fs, &c)
	args := []string{
		"--notify-slack-url-file=a", "--notify-slack-events=experiment.rollback",
		"--notify-teams-url-file=b", "--notify-teams-events=all",
		"--notify-webhook-url-file=c", "--notify-webhook-secret-file=d", "--notify-webhook-events=all,resolved",
		"--notify-pagerduty-routing-key-file=e", "--notify-pagerduty-url=https://events.eu.pagerduty.com/v2/enqueue", "--notify-pagerduty-events=resolved",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	want := NotifyConfig{
		SlackURLFile: "a", SlackEvents: "experiment.rollback", TeamsURLFile: "b", TeamsEvents: "all",
		WebhookURLFile: "c", WebhookSecretFile: "d", WebhookEvents: "all,resolved",
		PagerDutyRoutingKeyFile: "e", PagerDutyURL: "https://events.eu.pagerduty.com/v2/enqueue", PagerDutyEvents: "resolved",
	}
	if fmt.Sprintf("%+v", c) != fmt.Sprintf("%+v", want) {
		t.Fatalf("config = %+v", c)
	}
}
