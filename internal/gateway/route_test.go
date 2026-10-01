package gateway

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func names(ts []policy.RouteTarget) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Upstream)
	}
	return out
}

func TestRouteOrder(t *testing.T) {
	split := policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "a", Model: "m1", Weight: 90}, {Upstream: "b", Model: "m2", Weight: 10}}}
	failover := policy.ModelRoute{Targets: []policy.RouteTarget{
		{Upstream: "backup", Model: "m", Priority: 1}, {Upstream: "primary", Model: "m"}, {Upstream: "tertiary", Model: "m", Priority: 2}}}
	weightedThenBackup := policy.ModelRoute{Targets: []policy.RouteTarget{
		{Upstream: "a", Weight: 1}, {Upstream: "b", Weight: 1}, {Upstream: "backup", Priority: 1}}}

	tests := []struct {
		name  string
		route policy.ModelRoute
		key   string
		want  []string
	}{
		// Known answers: bucket(route/default/0, key) / 10000 * 100 against the 90/10 split.
		{"kat alice s1 -> a", split, StickyKey("alice@acme.com", "s1"), []string{"a", "b"}},
		{"kat alice s2 -> a", split, StickyKey("alice@acme.com", "s2"), []string{"a", "b"}},
		{"kat alice s5 -> b (bucket 9283)", split, StickyKey("alice@acme.com", "s5"), []string{"b", "a"}},
		{"kat alice s7 -> b (bucket 9808)", split, StickyKey("alice@acme.com", "s7"), []string{"b", "a"}},
		{"kat bob s1 -> a", split, StickyKey("bob@acme.com", "s1"), []string{"a", "b"}},
		{"anonymous without session: policy order", split, StickyKey("", ""), []string{"a", "b"}},
		{"priority tiers ascend, ties keep policy order", failover, "k", []string{"primary", "backup", "tertiary"}},
		{"later tier only after the weighted tier", weightedThenBackup, StickyKey("alice@acme.com", "s1"), nil}, // checked below
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := names(RouteOrder("default", tc.route, tc.key))
			if tc.want == nil {
				if len(got) != 3 || got[2] != "backup" || !slices.Contains(got[:2], "a") || !slices.Contains(got[:2], "b") {
					t.Fatalf("got %v, want a/b then backup", got)
				}
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteOrderDeterministicAndSticky(t *testing.T) {
	r := policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "a", Weight: 1}, {Upstream: "b", Weight: 1}}}
	for i := range 50 {
		k := StickyKey("u", fmt.Sprint("s", i))
		if a, b := names(RouteOrder("x", r, k)), names(RouteOrder("x", r, k)); !slices.Equal(a, b) {
			t.Fatalf("same key, different order: %v vs %v", a, b)
		}
	}
}

func TestRouteOrderWeightedDistribution(t *testing.T) {
	r := policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "a", Model: "m1", Weight: 90}, {Upstream: "b", Model: "m2", Weight: 10}}}
	const n = 20000
	var b int
	for i := range n {
		if RouteOrder("default", r, StickyKey(fmt.Sprint("user", i), fmt.Sprint("sess", i)))[0].Upstream == "b" {
			b++
		}
	}
	if got := float64(b) / n; got < 0.09 || got > 0.11 {
		t.Fatalf("share of b = %.4f, want 0.10 +/- 0.01", got)
	}
}

func TestRouteOrderSingleTarget(t *testing.T) {
	got := RouteOrder("a", policy.ModelRoute{Upstream: "u", Model: "m"}, "k")
	if len(got) != 1 || got[0].Upstream != "u" || got[0].Model != "m" {
		t.Fatalf("got %+v", got)
	}
	if RouteOrder("a", policy.ModelRoute{}, "k") != nil {
		t.Fatal("empty route should have no targets")
	}
}

func TestBreaker(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &Breaker{Threshold: 2, Cooldown: 10 * time.Second, now: func() time.Time { return now }}
	const k = "up/model"

	if !b.Allow(k) {
		t.Fatal("closed breaker must allow")
	}
	b.Done(k, false)
	if !b.Allow(k) || b.State(k) != "closed" {
		t.Fatal("one failure below threshold must stay closed")
	}
	b.Done(k, false) // second consecutive failure: open
	if b.Allow(k) || b.State(k) != "open" {
		t.Fatal("threshold reached: must be open")
	}

	now = now.Add(11 * time.Second) // cooldown over: exactly one probe
	if b.State(k) != "half-open" {
		t.Fatalf("state %s, want half-open", b.State(k))
	}
	if !b.Allow(k) {
		t.Fatal("half-open must admit a probe")
	}
	if b.Allow(k) {
		t.Fatal("half-open must admit only one probe at a time")
	}
	b.Done(k, false) // probe fails: open again for a full cooldown
	if b.Allow(k) {
		t.Fatal("failed probe must re-open")
	}
	now = now.Add(11 * time.Second)
	if !b.Allow(k) {
		t.Fatal("second probe expected")
	}
	b.Cancel(k) // client went away: slot released, no verdict
	if !b.Allow(k) {
		t.Fatal("cancelled probe must free the slot")
	}
	b.Done(k, true) // probe succeeds: closed
	if b.State(k) != "closed" || !b.Allow(k) {
		t.Fatal("successful probe must close")
	}
	b.Done(k, false)
	if !b.Allow(k) {
		t.Fatal("failure count must restart after a success")
	}
}

func TestDecideAndPrepareWithTargets(t *testing.T) {
	org := testOrg()
	org.Gateway.Models["opus"] = policy.ModelRoute{Targets: []policy.RouteTarget{
		{Upstream: "anthropic", Model: "claude-opus-4-1", Priority: 1}, {Upstream: "orch", Model: "arn:opus"}}}
	// A traffic-axis variant may swap a whole route, targets included.
	org.Experiments[0].Variants[1].Routes["opus"] = policy.ModelRoute{Targets: []policy.RouteTarget{{Upstream: "anthropic", Model: "opus-next"}}}

	sub := &policy.Subject{ID: "alice@acme.com"}
	h := http.Header{"X-Claude-Code-Session-Id": {"s1"}}
	body := []byte(`{"model":"opus","messages":[{"role":"user","content":"hi"}]}`)
	var sawControl, sawVariant bool
	for i := 0; i < 300 && (!sawControl || !sawVariant); i++ {
		sub.ID = fmt.Sprintf("user%d@acme.com", i)
		res := PrepareVerified(org, sub, h, PathMessages, body)
		if res.Reject != nil {
			t.Fatalf("rejected: %v", res.Reject)
		}
		d := res.Decision
		switch d.Variant {
		case "direct":
			sawVariant = true
			if got := names(d.Route); !slices.Equal(got, []string{"anthropic"}) || d.UpstreamModel != "opus-next" {
				t.Fatalf("variant route not applied: %+v", d)
			}
		default:
			sawControl = true
			if got := names(d.Route); !slices.Equal(got, []string{"orch", "anthropic"}) {
				t.Fatalf("route %v", got)
			}
			if d.UpstreamName != "orch" || d.UpstreamModel != "arn:opus" || d.Upstream != "https://orch.internal:8443" {
				t.Fatalf("first-target fields for halo-kong: %+v", d)
			}
		}
	}
	if !sawControl || !sawVariant {
		t.Fatal("did not observe both control and variant users")
	}

	// Fail closed: an alias with no route is refused even though other aliases have targets.
	res := PrepareVerified(org, sub, h, PathMessages, []byte(`{"model":"unlisted","messages":[]}`))
	if res.Reject == nil || res.Reject.Status != http.StatusBadRequest {
		t.Fatalf("unlisted alias must be 400, got %+v", res.Reject)
	}
}

// A denied model is a permanent client error (400, never retried by the CLIs)
// whose message names the alias and says policy does not permit it, on every wire.
func TestModelDeniedIsPermanentAndNamesTheAlias(t *testing.T) {
	org := testOrg()
	for _, tc := range []struct{ path, body, shape string }{
		{PathMessages, `{"model":"rogue","messages":[]}`, "invalid_request_error"},
		{PathResponses, `{"model":"rogue","input":"hi"}`, "model_not_allowed"},
		{"/model/rogue/invoke", `{}`, `"message"`},
		{"/v1beta/models/rogue:generateContent", `{}`, "INVALID_ARGUMENT"},
	} {
		res := PrepareVerified(org, nil, http.Header{}, tc.path, []byte(tc.body))
		if res.Reject == nil || res.Reject.Status != http.StatusBadRequest {
			t.Fatalf("%s: %+v", tc.path, res.Reject)
		}
		js := string(res.Reject.JSON())
		if !strings.Contains(js, `model \"rogue\" is not permitted by the Halos gateway policy`) || !strings.Contains(js, tc.shape) {
			t.Errorf("%s: %s", tc.path, js)
		}
	}
}
