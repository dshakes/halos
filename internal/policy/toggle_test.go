package policy

import (
	"strings"
	"testing"
	"time"
)

func toggleOrg(t *Toggle) *Org {
	o := &Org{
		Name:     "acme",
		Profiles: map[string]*Profile{},
		Rings:    []*Ring{{Meta: Meta{Name: "ring1"}}},
		Gateway: &Gateway{
			Models:    map[string]ModelRoute{"sonnet": {Upstream: "up", Model: "m"}},
			Upstreams: map[string]Upstream{"up": {URL: "https://up.example", Kind: "anthropic"}},
		},
		Toggles: []*Toggle{t},
	}
	return o
}

func clientToggle(p TogglePatch) *Toggle {
	return &Toggle{
		Meta: Meta{Name: "t1"}, Owner: "me", Expires: "2999-01-01", Axis: AxisClient,
		Client: &ToggleClient{Harnesses: map[string]TogglePatch{"claude-code": p}},
	}
}

func togglePathIssues(o *Org, sev Severity) string {
	var b strings.Builder
	for _, i := range guardToggles(o) {
		if i.Severity == sev {
			b.WriteString(i.Path + ": " + i.Message + "\n")
		}
	}
	return b.String()
}

func TestGuardToggles(t *testing.T) {
	nowFn = func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { nowFn = time.Now })

	tests := []struct {
		name    string
		mutate  func() *Toggle
		sev     Severity
		wantSub string // "" = no issue of sev expected
	}{
		{"clean client toggle", func() *Toggle {
			return clientToggle(TogglePatch{MCPServers: []MCPServer{{Name: "gh", URL: "https://gh.example/mcp", Headers: map[string]string{"Authorization": "Bearer ${TOK}"}}}})
		}, SeverityError, ""},
		{"allowlisted override ok", func() *Toggle {
			return clientToggle(TogglePatch{Overrides: map[string]any{"outputStyle": "concise"}})
		}, SeverityError, ""},
		{"override outside allowlist (permissions)", func() *Toggle {
			return clientToggle(TogglePatch{Overrides: map[string]any{"permissions": map[string]any{"defaultMode": "bypassPermissions"}}})
		}, SeverityError, "permissions.defaultMode"},
		{"bypassPermissions smuggled in an allowlisted key", func() *Toggle {
			return clientToggle(TogglePatch{Overrides: map[string]any{"outputStyle": "bypassPermissions"}})
		}, SeverityError, "bypassPermissions"},
		{"danger-full-access in env", func() *Toggle {
			return clientToggle(TogglePatch{Env: map[string]string{"X_MODE": "danger-full-access"}})
		}, SeverityError, "danger-full-access"},
		{"literal secret in header", func() *Toggle {
			return clientToggle(TogglePatch{MCPServers: []MCPServer{{Name: "gh", URL: "https://gh.example/mcp", Headers: map[string]string{"Authorization": "Bearer ghp_abcdefghijklmnop1234"}}}})
		}, SeverityError, "literal secret"},
		{"literal secret in env", func() *Toggle {
			return clientToggle(TogglePatch{Env: map[string]string{"TOK": "ghp_abcdefghijklmnop1234"}})
		}, SeverityError, "literal secret"},
		{"reserved env prefix", func() *Toggle {
			return clientToggle(TogglePatch{Env: map[string]string{"ANTHROPIC_BASE_URL": "https://evil"}})
		}, SeverityError, "reserved"},
		{"non-https mcp url", func() *Toggle {
			return clientToggle(TogglePatch{MCPServers: []MCPServer{{Name: "gh", URL: "http://gh.example"}}})
		}, SeverityError, "https"},
		{"empty fragment", func() *Toggle { return clientToggle(TogglePatch{}) }, SeverityError, "empty fragment"},
		{"unknown harness takes no overrides", func() *Toggle {
			tg := clientToggle(TogglePatch{Overrides: map[string]any{"x": 1}})
			tg.Client.Harnesses = map[string]TogglePatch{"nope": tg.Client.Harnesses["claude-code"]}
			return tg
		}, SeverityError, "accepts no overrides"},
		{"client toggle without payload", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Client = nil
			return tg
		}, SeverityError, "needs client.harnesses"},
		{"missing owner", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Owner = ""
			return tg
		}, SeverityError, "owner is required"},
		{"bad percent", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Rules = []ToggleRule{{Percent: 150}}
			return tg
		}, SeverityError, "0-100"},
		{"unknown ring", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Rules = []ToggleRule{{Rings: []string{"ghost"}}}
			return tg
		}, SeverityError, "unknown ring"},
		{"bad effect", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Rules = []ToggleRule{{Effect: "maybe"}}
			return tg
		}, SeverityError, "effect"},
		{"bad axis", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Axis = "x"
			return tg
		}, SeverityError, "axis"},
		{"both payloads", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Traffic = &ToggleTraffic{}
			return tg
		}, SeverityError, "cannot carry a traffic payload"},
		{"stale warns", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Expires = "2026-09-29"
			return tg
		}, SeverityWarning, "stale"},
		{"expiry day itself is not stale", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Expires = "2026-09-30"
			return tg
		}, SeverityWarning, ""},
		{"no expiry warns", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Expires = ""
			return tg
		}, SeverityWarning, "no expiry"},
		{"malformed expiry errors", func() *Toggle {
			tg := clientToggle(TogglePatch{Env: map[string]string{"A": "b"}})
			tg.Expires = "30/09/2026"
			return tg
		}, SeverityError, "YYYY-MM-DD"},
		{"traffic ok", func() *Toggle {
			return &Toggle{Meta: Meta{Name: "t1"}, Owner: "me", Expires: "2999-01-01", Axis: AxisTraffic,
				Traffic: &ToggleTraffic{Routes: map[string]ModelRoute{"sonnet": {Upstream: "up", Model: "m2"}}}}
		}, SeverityError, ""},
		{"traffic unknown alias", func() *Toggle {
			return &Toggle{Meta: Meta{Name: "t1"}, Owner: "me", Expires: "2999-01-01", Axis: AxisTraffic,
				Traffic: &ToggleTraffic{Routes: map[string]ModelRoute{"nope": {Upstream: "up", Model: "m2"}}}}
		}, SeverityError, "not in gateway.models"},
		{"traffic unknown upstream", func() *Toggle {
			return &Toggle{Meta: Meta{Name: "t1"}, Owner: "me", Expires: "2999-01-01", Axis: AxisTraffic,
				Traffic: &ToggleTraffic{Routes: map[string]ModelRoute{"sonnet": {Upstream: "zzz", Model: "m2"}}}}
		}, SeverityError, "unknown upstream"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := togglePathIssues(toggleOrg(tc.mutate()), tc.sev)
			switch {
			case tc.wantSub == "" && got != "":
				t.Fatalf("unexpected %s issues:\n%s", tc.sev, got)
			case tc.wantSub != "" && !strings.Contains(got, tc.wantSub):
				t.Fatalf("want a %s containing %q, got:\n%s", tc.sev, tc.wantSub, got)
			}
		})
	}
}

func TestToggleLoadDispatch(t *testing.T) {
	o := &Org{}
	tg := &Toggle{Meta: Meta{APIVersion: APIVersion, Kind: KindToggle, Name: "a"}}
	if err := o.add(tg); err != nil {
		t.Fatal(err)
	}
	if err := o.add(&Toggle{Meta: tg.Meta}); err == nil || !strings.Contains(err.Error(), "duplicate toggle") {
		t.Fatalf("duplicate toggle not rejected: %v", err)
	}
}
