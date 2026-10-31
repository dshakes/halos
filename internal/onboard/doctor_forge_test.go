package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDoctorPolicyForge(t *testing.T) {
	for _, tc := range []struct {
		name, remote, token string
		wantID, wantStatus  string
		absent              string
	}{
		{"github remote keeps the gh check", "git@github.com:acme/policy.git", "", "tool/gh", StatusWarn, "forge/gitlab"},
		{"gitlab remote without token", "git@gitlab.com:acme/sub/policy.git", "", "forge/gitlab", StatusWarn, "tool/gh"},
		{"self-managed gitlab with token", "https://gitlab.corp.example/acme/policy.git", "glpat-NEVER-PRINT", "forge/gitlab", StatusOK, "tool/gh"},
		{"unreadable remote falls back to gh", "", "", "tool/gh", StatusWarn, "forge/gitlab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fake("", nil)
			e.Getenv = func(k string) string {
				if k == "GITLAB_TOKEN" {
					return tc.token
				}
				return ""
			}
			e.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "git" && len(args) > 0 && args[len(args)-1] == "origin" {
					if tc.remote == "" {
						return nil, errors.New("no origin")
					}
					return []byte(tc.remote + "\n"), nil
				}
				return []byte("2.1.280 (Claude Code)\n"), nil
			}
			r := Doctor(context.Background(), e, t.TempDir())
			if got := status(r, tc.wantID); got != tc.wantStatus {
				t.Fatalf("%s = %q, want %q: %+v", tc.wantID, got, tc.wantStatus, r.Checks)
			}
			for _, c := range r.Checks {
				if c.ID == tc.absent {
					t.Fatalf("%s must not be reported: %+v", tc.absent, c)
				}
			}
			b, _ := json.Marshal(r)
			if tc.token != "" && strings.Contains(string(b), tc.token) {
				t.Fatal("report leaks the token")
			}
			for _, c := range r.Checks {
				if c.ID == "forge/gitlab" && c.Status == StatusWarn && !strings.Contains(c.Fix, "GITLAB_TOKEN") {
					t.Errorf("fix must name GITLAB_TOKEN: %q", c.Fix)
				}
			}
		})
	}
}
