package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// forwardedModels returns every top-level key of a forwarded JSON body that a
// case-insensitive or duplicate-tolerant upstream parser could read as "model",
// with its value, in order.
func forwardedModels(t testing.TB, body []byte) [][2]string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil // not an object: nothing an upstream would read a model from
	}
	var out [][2]string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return out
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return out
		}
		if ks, _ := k.(string); strings.EqualFold(ks, "model") {
			var s string
			_ = json.Unmarshal(v, &s)
			out = append(out, [2]string{ks, s})
		}
	}
	return out
}

// An alias that equals its upstream model id needs no rewrite, so the body is
// forwarded as the client sent it. Go's encoding/json matches keys
// case-insensitively and keeps the last duplicate; a case-sensitive or
// first-wins upstream parser must not be able to read a different model.
func TestModelSmugglingViaDuplicateOrCaseVariantKeys(t *testing.T) {
	org := testOrg()
	org.Gateway.Models["claude-sonnet-4-5"] = policy.ModelRoute{Upstream: "anthropic", Model: "claude-sonnet-4-5"}
	org.Experiments = nil
	sub := &policy.Subject{ID: "alice"}
	for _, tc := range []struct{ name, path, body string }{
		{"case variant after", PathMessages, `{"model":"claude-opus-4","Model":"claude-sonnet-4-5","messages":[]}`},
		{"case variant before", PathMessages, `{"MODEL":"claude-opus-4","model":"claude-sonnet-4-5","messages":[]}`},
		{"duplicate key", PathMessages, `{"model":"claude-opus-4","model":"claude-sonnet-4-5","messages":[]}`},
		{"responses wire", PathResponses, `{"model":"gpt-5-pro","mOdEl":"claude-sonnet-4-5","input":"hi"}`},
		{"plain", PathMessages, `{"model":"claude-sonnet-4-5","messages":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := PrepareVerified(org, sub, http.Header{}, tc.path, []byte(tc.body))
			if res.Reject != nil {
				return // refusing is fine
			}
			ms := forwardedModels(t, res.Body)
			if len(ms) != 1 || ms[0] != [2]string{"model", "claude-sonnet-4-5"} {
				t.Fatalf("forwarded body %s: model keys %v, want exactly model=claude-sonnet-4-5", res.Body, ms)
			}
		})
	}
}

// SSE produced from a Bedrock event stream is well formed whatever the event
// type or chunk JSON holds: no line breaks inside a field (event injection).
func TestEventStreamToSSENoInjection(t *testing.T) {
	for _, ev := range []string{
		`{"type":"x\nevent: message_stop\ndata: {}\n\nevent: y","delta":{}}`,
		`{"type":"x\rdata: injected"}`,
		"{\n\"type\": \"message_start\",\n\"message\": {}\n}",
		`not json at all` + "\n\nevent: error\ndata: {}",
	} {
		out, _ := io.ReadAll(EventStreamToSSE(io.NopCloser(bytes.NewReader(chunk(ev)))))
		if err := checkSSE(out); err != nil {
			t.Errorf("event %q: %v\n%q", ev, err, out)
		}
	}
}

// The kill-list fetch carries the gateway bearer token: a redirect is a failed
// refresh and the token never reaches the redirect target.
func TestKillSwitchNeverFollowsRedirects(t *testing.T) {
	pub, _ := killKeys(t)
	var leaked atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
	}))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	k, err := NewKillSwitch(redir.URL, "gw-token-0123456789", pub, 0, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Refresh(context.Background()); err == nil {
		t.Fatal("a redirect must fail the refresh")
	}
	if leaked.Load() != 0 {
		t.Fatal("gateway token followed a redirect")
	}
}

// Kills do not expire: once accepted, a list stays in force however long the
// control plane is unreachable or serves stale lists.
func TestKillsDoNotExpire(t *testing.T) {
	pub, priv := killKeys(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	ks := &killServer{}
	srv := httptest.NewServer(ks)
	defer srv.Close()
	k, err := NewKillSwitch(srv.URL, "gw-token", pub, 0, slog.New(slog.NewTextHandler(io.Discard, nil)), false)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	k.Now = func() time.Time { return clock }
	env, _ := SignKillList(priv, KillList{Version: 1, Experiments: []string{"sonnet-canary"}, IssuedAt: now})
	ks.set(http.StatusOK, env)
	if err := k.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(30 * 24 * time.Hour) // the same envelope is now stale
	if err := k.Refresh(context.Background()); err == nil {
		t.Fatal("stale list accepted")
	}
	ks.set(http.StatusServiceUnavailable, KillEnvelope{})
	if err := k.Refresh(context.Background()); err == nil {
		t.Fatal("down server: want error")
	}
	if got := k.Killed().Experiments; !slices.Equal(got, []string{"sonnet-canary"}) {
		t.Fatalf("kill lapsed: %v", got)
	}
	for _, e := range k.Apply(testOrg()).Experiments {
		if e.Name == "sonnet-canary" && e.Status != "paused" {
			t.Fatalf("killed experiment status %q", e.Status)
		}
	}
}
