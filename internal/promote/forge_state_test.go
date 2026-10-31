package promote

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

const stateMarker = "<!-- halos:propose=abc -->"

// openOnly requests must match only open PRs/MRs; FindPR (the controller's
// intent lookup) must keep matching every state.
func TestFindOpenVersusAnyState(t *testing.T) {
	type item struct{ url, state string }
	items := []item{{"https://x/merged", "merged"}, {"https://x/closed", "closed"}, {"https://x/open", "open"}}

	// Each fake honours the state query the way the real API does.
	gitlab := func(w http.ResponseWriter, r *http.Request) {
		want := r.URL.Query().Get("state")
		var out []map[string]string
		for _, it := range items {
			gl := map[string]string{"merged": "merged", "closed": "closed", "open": "opened"}[it.state]
			if want == "all" || want == gl {
				out = append(out, map[string]string{"web_url": it.url, "description": "d " + stateMarker})
			}
		}
		jsonOut(w, 200, out)
	}
	github := func(w http.ResponseWriter, r *http.Request) {
		want := r.URL.Query().Get("state")
		var out []map[string]string
		for _, it := range items {
			gh := map[string]string{"merged": "closed", "closed": "closed", "open": "open"}[it.state]
			if want == "all" || want == gh {
				out = append(out, map[string]string{"html_url": it.url, "body": "d " + stateMarker})
			}
		}
		jsonOut(w, 200, out)
	}
	for _, tc := range []struct {
		name    string
		kind    string
		handler http.HandlerFunc
		// onlyOne drops the other items so the first match is the one asserted.
	}{
		{"gitlab", ForgeGitLab, gitlab}, {"github", ForgeGitHub, github},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeForge(t, tc.handler)
			env := map[string]string{"GITLAB_TOKEN": testToken, "GITHUB_TOKEN": testToken}
			f := &ForgeOpener{Kind: tc.kind, BaseURL: srv.URL, Getenv: tokenEnv(env), Exec: forgeExec("git@h.example:acme/policy.git", new([]string))}
			ctx := context.Background()
			// (c) an open one is returned.
			if u, ok, err := f.FindOpenPR(ctx, t.TempDir(), stateMarker); err != nil || !ok || u != "https://x/open" {
				t.Fatalf("FindOpenPR = %q %v %v", u, ok, err)
			}
			// (d) the controller lookup still matches the first of any state (merged).
			if u, ok, err := f.FindPR(ctx, t.TempDir(), stateMarker); err != nil || !ok || u != "https://x/merged" {
				t.Fatalf("FindPR = %q %v %v", u, ok, err)
			}
			// (a)/(b) with only merged and closed present, open-only finds nothing.
			items = items[:2]
			defer func() { items = append(items, item{"https://x/open", "open"}) }()
			if u, ok, err := f.FindOpenPR(ctx, t.TempDir(), stateMarker); err != nil || ok || u != "" {
				t.Fatalf("FindOpenPR with only merged/closed = %q %v %v", u, ok, err)
			}
			if u, ok, err := f.FindPR(ctx, t.TempDir(), stateMarker); err != nil || !ok || u != "https://x/merged" {
				t.Fatalf("FindPR still sees merged: %q %v %v", u, ok, err)
			}
			// The state query is what narrows it.
			var sawOpen, sawAll bool
			for _, r := range srv.requests() {
				sawOpen = sawOpen || strings.Contains(r.URI, "state=open")
				sawAll = sawAll || strings.Contains(r.URI, "state=all")
			}
			if !sawOpen || !sawAll {
				t.Fatalf("state queries: open=%v all=%v", sawOpen, sawAll)
			}
		})
	}
}

func TestGHFindOpenUsesStateOpen(t *testing.T) {
	var got []string
	g := GHOpener{Exec: func(_ context.Context, _, name string, a ...string) ([]byte, error) {
		got = append(got, strings.Join(a, " "))
		return []byte(`[{"url":"https://gh/pr/1","body":"` + stateMarker + `"}]`), nil
	}}
	if u, ok, err := g.FindOpenPR(context.Background(), ".", stateMarker); err != nil || !ok || u != "https://gh/pr/1" {
		t.Fatalf("%q %v %v", u, ok, err)
	}
	if _, _, err := g.FindPR(context.Background(), ".", stateMarker); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0], "--state open") || !strings.Contains(got[1], "--state all") {
		t.Fatalf("gh args: %q", got)
	}
}
