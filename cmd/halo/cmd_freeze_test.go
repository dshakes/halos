package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// governed copies the example with gov as its only governance section.
func governed(t *testing.T, gov string) string {
	t.Helper()
	dir := copyDir(t, example)
	p := filepath.Join(dir, "halos.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if i := strings.Index(s, "\ngovernance:"); i >= 0 { // drop the example's own sample
		j := i + 1 + len("governance:")
		for j < len(s) {
			nl := strings.IndexByte(s[j:], '\n')
			if nl < 0 {
				j = len(s)
				break
			}
			j += nl + 1
			if j < len(s) && s[j] != ' ' && s[j] != '#' && s[j] != '\n' {
				break
			}
		}
		s = s[:i+1] + s[j:]
	}
	if err := os.WriteFile(p, []byte(s+"\n"+gov), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFreezeCLI(t *testing.T) {
	dir := governed(t, `governance:
  freezes:
    - name: ga-weekend
      reason: no GA changes on weekends
      timezone: America/New_York
      scope: {rings: [ring3-ga]}
      weekly: {from: "Fri 18:00", to: "Mon 06:00"}
`)
	sat := "2026-03-07T12:00:00-05:00" // Saturday; DST starts the next day
	tests := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"status on a Saturday", []string{"freeze", "status", "--policy-dir", dir, "--at", sat}, 0, []string{"ring3-ga", "yes", "2026-03-09T06:00:00-04:00", "no GA changes on weekends", "ring1-canary"}},
		{"status json", []string{"freeze", "status", "--policy-dir", dir, "--at", sat, "--ring", "ring3-ga", "--output", "json"}, 0, []string{`"frozen": true`, `"nextOpen": "2026-03-09T06:00:00-04:00"`}},
		{"check fails for GA", []string{"freeze", "check", "--policy-dir", dir, "--at", sat, "--ring", "ring3-ga"}, 1, []string{"ga-weekend", "next open 2026-03-09T06:00:00-04:00", "Rollbacks"}},
		{"check passes for canary", []string{"freeze", "check", "--policy-dir", dir, "--at", sat, "--ring", "ring1-canary"}, 0, []string{"no change freeze"}},
		{"check passes on Monday", []string{"freeze", "check", "--policy-dir", dir, "--at", "2026-03-09T06:00:00-04:00"}, 0, []string{"no change freeze"}},
		{"a rollback branch name proves nothing", []string{"freeze", "check", "--policy-dir", dir, "--at", sat, "--branch", "halos/rollout-claude-code-2.1.300-rollback"}, 1, []string{"no longer trusted"}},
		{"unknown ring", []string{"freeze", "status", "--policy-dir", dir, "--ring", "nope"}, 1, []string{"unknown ring"}},
		{"bad --at", []string{"freeze", "status", "--policy-dir", dir, "--at", "Saturday"}, 1, []string{"--at"}},
		{"on needs a reason", []string{"freeze", "on"}, 1, []string{"--reason is required"}},
		{"on needs a server", []string{"freeze", "on", "--reason", "SEV1"}, 1, []string{"HALO_SESSION"}},
	}
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := halo(t, tc.args...)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out, errs)
			}
			for _, w := range tc.want {
				if !strings.Contains(out+errs, w) {
					t.Errorf("missing %q in\n%s%s", w, out, errs)
				}
			}
		})
	}
}

// TestRolloutAdvanceRefusedWhileFrozen: a live freeze refuses the advance PR
// (--force does not override it) but never the rollback.
func TestRolloutAdvanceRefusedWhileFrozen(t *testing.T) {
	now := time.Now().UTC()
	dir := governed(t, "governance:\n  freezes:\n    - name: incident-review\n      reason: postmortem in progress\n      start: \""+
		now.Add(-time.Hour).Format(time.RFC3339)+"\"\n      end: \""+now.Add(2*time.Hour).Format(time.RFC3339)+"\"\n")
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	code, out, errs := halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go", "--force")
	if code == 0 || !strings.Contains(errs, "incident-review (postmortem in progress)") || !strings.Contains(errs, "next open") {
		t.Fatalf("advance during a freeze: exit %d\n%s%s", code, out, errs)
	}
	code, out, errs = halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go", "--dry-run")
	if code != 0 || !strings.Contains(errs, "warning:") || !strings.Contains(out, "+step: canary-25") {
		t.Fatalf("dry run shows the patch and warns: exit %d\n%s%s", code, out, errs)
	}
	code, out, errs = halo(t, "rollout", "rollback", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "bad", "--dry-run")
	if code != 0 || strings.Contains(errs, "freeze") {
		t.Fatalf("rollback during a freeze: exit %d\n%s%s", code, out, errs)
	}
}

// TestAdvanceWarnsWithoutIncidentCheck: without halo-server the CLI says it
// checked the policy windows only; with one it does not, and the incident
// freeze it reports refuses the advance.
func TestAdvanceWarnsWithoutIncidentCheck(t *testing.T) {
	dir := copyDir(t, example)
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	const warn = "policy's freeze windows only, not the incident freeze"
	code, out, errs := halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go", "--dry-run")
	if code != 0 || !strings.Contains(errs, warn) {
		t.Fatalf("no server: exit %d\n%s%s", code, out, errs)
	}
	incident := false
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/freeze" && incident:
			_, _ = w.Write([]byte(`{"incident":{"name":"incident","reason":"SEV1","by":"oncall@x","incident":true}}`))
		case r.URL.Path == "/api/v1/freeze":
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/api/v1/me":
			_, _ = w.Write([]byte(`{"id":"dev@x"}`))
		default:
			_, _ = w.Write([]byte(`{"approvals":[]}`))
		}
	}))
	defer hs.Close()
	t.Setenv("HALO_SESSION", "s")
	code, out, errs = halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go", "--dry-run", "--server", hs.URL)
	if code != 0 || strings.Contains(errs, warn) {
		t.Fatalf("with server: exit %d\n%s%s", code, out, errs)
	}
	incident = true
	code, out, errs = halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go", "--server", hs.URL)
	if code == 0 || !strings.Contains(errs, "SEV1") {
		t.Fatalf("incident freeze: exit %d\n%s%s", code, out, errs)
	}
}

func TestRolloutAdvanceNeedsQuorum(t *testing.T) {
	dir := governed(t, "governance:\n  approvals:\n    - name: two-person\n      quorum: 2\n      groups: [sre]\n")
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	code, out, errs := halo(t, "rollout", "advance", "opus-5-5-upgrade", "--policy-dir", dir, "--reason", "go")
	if code == 0 || !strings.Contains(errs, "0/2 approvals from sre") || !strings.Contains(errs, "recorded on halo-server") {
		t.Fatalf("advance without quorum: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs := halo(t, "rollout", "status", "opus-5-5-upgrade", "--policy-dir", dir); code != 0 || !strings.Contains(out, "approval") {
		t.Fatalf("status: exit %d\n%s%s", code, out, errs)
	}
}
