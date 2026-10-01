package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/promote"
)

func testEvent() Event {
	return Event{Experiment: "exp-<a>", Verdict: promote.Rollback, Reason: "guardrail regressed", Killed: true, KillOutcome: KillEnforced, PRURL: "https://gh/pr/1", At: start}
}

type captured struct {
	body []byte
	hdr  http.Header
}

func capture(t *testing.T, status int) (*httptest.Server, chan captured) {
	t.Helper()
	ch := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- captured{b, r.Header.Clone()}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func TestSlackNotify(t *testing.T) {
	srv, ch := capture(t, http.StatusOK)
	if err := (Slack{URL: srv.URL + "/services/T/B/secret"}).Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	var p struct {
		Text   string `json:"text"`
		Blocks []struct {
			Type string `json:"type"`
			Text struct{ Type, Text string }
		} `json:"blocks"`
	}
	if err := json.Unmarshal(got.body, &p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Text, "ROLLBACK") || !strings.Contains(p.Text, "exp-&lt;a&gt;") || !strings.Contains(p.Text, "Kill switch tripped") {
		t.Fatalf("text = %q", p.Text)
	}
	if len(p.Blocks) != 1 || p.Blocks[0].Type != "section" || p.Blocks[0].Text.Type != "mrkdwn" {
		t.Fatalf("blocks = %+v", p.Blocks)
	}
}

func TestWebhookSignature(t *testing.T) {
	srv, ch := capture(t, http.StatusAccepted)
	secret := []byte("s3cret")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := (Webhook{URL: srv.URL, Secret: secret, Now: func() time.Time { return now }}).Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if ts := got.hdr.Get(TimestampHeader); ts != strconv.FormatInt(now.Unix(), 10) {
		t.Fatalf("timestamp header %q", ts)
	}
	if sig := got.hdr.Get(SignatureHeader); sig != Sign(secret, now.Unix(), got.body) || !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("signature %q does not match timestamp.body", sig)
	}
	var ev Event
	if err := json.Unmarshal(got.body, &ev); err != nil || ev.Experiment != "exp-<a>" || !ev.Killed {
		t.Fatalf("event %+v err %v", ev, err)
	}
	// No secret: no signature or timestamp header.
	if err := (Webhook{URL: srv.URL}).Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if got := <-ch; got.hdr.Get(SignatureHeader) != "" || got.hdr.Get(TimestampHeader) != "" {
		t.Fatal("signature without a secret")
	}
}

func TestWebhookVerify(t *testing.T) {
	secret, body := []byte("s3cret"), []byte(`{"a":1}`)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	hdr := func(ts int64, sig string) http.Header {
		h := http.Header{}
		h.Set(TimestampHeader, strconv.FormatInt(ts, 10))
		h.Set(SignatureHeader, sig)
		return h
	}
	tests := []struct {
		name    string
		h       http.Header
		body    []byte
		wantErr string
	}{
		{"valid", hdr(now.Unix(), Sign(secret, now.Unix(), body)), body, ""},
		{"valid within tolerance", hdr(now.Add(-4*time.Minute).Unix(), Sign(secret, now.Add(-4*time.Minute).Unix(), body)), body, ""},
		{"replayed (old)", hdr(now.Add(-6*time.Minute).Unix(), Sign(secret, now.Add(-6*time.Minute).Unix(), body)), body, "tolerance"},
		{"future", hdr(now.Add(6*time.Minute).Unix(), Sign(secret, now.Add(6*time.Minute).Unix(), body)), body, "tolerance"},
		{"timestamp swapped after signing", hdr(now.Unix(), Sign(secret, now.Add(-time.Second).Unix(), body)), body, "mismatch"},
		{"wrong secret", hdr(now.Unix(), Sign([]byte("x"), now.Unix(), body)), body, "mismatch"},
		{"tampered body", hdr(now.Unix(), Sign(secret, now.Unix(), body)), []byte(`{"a":2}`), "mismatch"},
		{"missing timestamp", http.Header{SignatureHeader: {Sign(secret, now.Unix(), body)}}, body, "Timestamp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(secret, tt.h, tt.body, now, WebhookTolerance)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNotifyErrorsNeverLeakURL(t *testing.T) {
	const secretPath = "/services/T000/B000/XXXXSECRET"
	srv, ch := capture(t, http.StatusForbidden)
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer slow.Close()
	defer close(release) // before Close, which waits for handlers
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for name, n := range map[string]Notifier{
		"non-2xx":       Slack{URL: srv.URL + secretPath},
		"unreachable":   Webhook{URL: "http://127.0.0.1:1" + secretPath},
		"timeout":       Webhook{URL: slow.URL + secretPath},
		"malformed url": Slack{URL: "http://[::1" + secretPath},
	} {
		c := context.Background()
		if name == "timeout" {
			c = ctx
		}
		err := n.Notify(c, testEvent())
		if err == nil {
			t.Fatalf("%s: want error", name)
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "services") {
			t.Fatalf("%s: error leaks the URL: %v", name, err)
		}
	}
	<-ch
	// Fan-out joins errors and still calls every notifier.
	ok, okCh := capture(t, http.StatusOK)
	err := Notifiers{Slack{URL: srv.URL}, Webhook{URL: ok.URL}}.Notify(context.Background(), testEvent())
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("got %v", err)
	}
	<-ch
	<-okCh
}

func TestNotifiersFromFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	slack, hook, secret := write("slack", "https://hooks.slack.test/x"), write("hook", "https://hooks.test/y"), write("secret", "k")
	bad, empty := write("bad", "ftp://nope/SECRET"), write("empty", "  ")
	for _, tc := range []struct {
		name                string
		slack, hook, secret string
		want                int
		wantErr             bool
	}{
		{"none", "", "", "", 0, false},
		{"all", slack, hook, secret, 2, false},
		{"missing file", filepath.Join(dir, "nope"), "", "", 0, true},
		{"empty file", empty, "", "", 0, true},
		{"not http", bad, "", "", 0, true},
		{"secret without url", "", "", secret, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := NotifiersFromFiles(tc.slack, tc.hook, tc.secret)
			if (err != nil) != tc.wantErr || len(ns) != tc.want {
				t.Fatalf("ns=%d err=%v", len(ns), err)
			}
			if err != nil && strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error leaks URL: %v", err)
			}
		})
	}
	ns, _ := NotifiersFromFiles("", hook, secret)
	if w := ns[0].(Webhook); string(w.Secret) != "k" || w.URL != "https://hooks.test/y" {
		t.Fatalf("webhook = %+v", w)
	}
}

func TestEventText(t *testing.T) {
	for _, tc := range []struct {
		ev   Event
		want string
	}{
		{Event{Verdict: promote.Rollback, Killed: true, KillOutcome: KillEnforced, Axis: "client"}, "client-axis variants stay"},
		{Event{Verdict: promote.Rollback, KillOutcome: KillFailed, KillError: "boom"}, "KILL SWITCH FAILED: boom"},
		{Event{Verdict: promote.Promote, PRError: "PR failed"}, "will retry"},
		{Event{Verdict: promote.Expired, PRURL: "https://x/1"}, "PR: https://x/1"},
	} {
		if got := tc.ev.Text(); !strings.Contains(got, tc.want) {
			t.Errorf("%q missing %q", got, tc.want)
		}
	}
}

func TestKillOutcomeWording(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		want string
		not  string
	}{
		{"enforced", Event{KillOutcome: KillEnforced, Killed: true}, "Kill switch tripped: gateways route everyone to control", "FAILED"},
		{"not gateway", Event{KillOutcome: KillNotGateway, KillError: "x"}, "Not auto-killed: rollback decided on non-gateway (CLI or eval) evidence; merge the pause PR", "FAILED"},
		{"not configured", Event{KillOutcome: KillNotConfigured, KillError: "x"}, "Kill switch not configured \u2014 merge the pause PR urgently", "FAILED"},
		{"recorded only", Event{KillOutcome: KillRecorded, KillError: "no gateway ack"}, "Kill recorded only, not enforced by a gateway (no gateway ack)", "FAILED"},
		{"failed", Event{KillOutcome: KillFailed, KillError: "boom"}, "KILL SWITCH FAILED: boom", "Not auto-killed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.ev
			ev.Experiment, ev.Verdict = "e", promote.Rollback
			if txt := ev.Text(); !strings.Contains(txt, tc.want) || strings.Contains(txt, tc.not) {
				t.Fatalf("text = %q", txt)
			}
			slackSrv, sch := capture(t, http.StatusOK)
			if err := (Slack{URL: slackSrv.URL}).Notify(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			var sp struct{ Text string }
			if err := json.Unmarshal((<-sch).body, &sp); err != nil || !strings.Contains(sp.Text, tc.want) {
				t.Fatalf("slack text = %q err %v", sp.Text, err)
			}
			hookSrv, hch := capture(t, http.StatusOK)
			if err := (Webhook{URL: hookSrv.URL}).Notify(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			var got Event
			if err := json.Unmarshal((<-hch).body, &got); err != nil || got.KillOutcome != tc.ev.KillOutcome || got.Text() != ev.Text() {
				t.Fatalf("webhook event = %+v err %v", got, err)
			}
		})
	}
}
