package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEgressTest(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		code     int
		allowed  bool
		rule     string
		enforced map[string]bool
	}{
		{"allowlisted url", []string{"https://registry.npmjs.org/left-pad"}, 0, true, "egress allow registry.npmjs.org",
			map[string]bool{"claude-code": true, "codex": true, "gemini-cli": false}},
		{"host with port", []string{"GitHub.com:443"}, 0, true, "egress allow github.com", nil},
		{"unlisted host denied by default", []string{"evil.example"}, 1, false, "egress.default deny", nil},
		{"deny rule wins", []string{"https://pastebin.com/raw/x"}, 1, false, "egress.deniedDomains pastebin.com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errs := halo(t, append([]string{"egress", "test", "--ring", "ring3-ga", "--os", "linux", "--policy-dir", example, "--output", "json"}, tt.args...)...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d: %s %s", code, tt.code, out, errs)
			}
			var res egressResult
			if err := json.Unmarshal([]byte(out), &res); err != nil {
				t.Fatalf("json: %v\n%s", err, out)
			}
			if res.Allowed != tt.allowed || res.Rule != tt.rule || res.Profile == "" {
				t.Fatalf("result = %+v", res)
			}
			got := map[string]bool{}
			for _, h := range res.Harnesses {
				got[h.Name] = h.Enforced
			}
			for h, want := range tt.enforced {
				if got[h] != want {
					t.Errorf("%s enforced = %v, want %v (%+v)", h, got[h], want, res.Harnesses)
				}
			}
		})
	}
}

func TestEgressTestErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown ring": {"egress", "test", "github.com", "--ring", "nope", "--policy-dir", example},
		"no ring":      {"egress", "test", "github.com", "--policy-dir", example},
		"not a host":   {"egress", "test", "https://", "--ring", "ring3-ga", "--policy-dir", example},
		"unknown unit": {"egress", "test", "github.com", "--ring", "ring3-ga", "--unit", "nope", "--policy-dir", example},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, errs := halo(t, args...); code == 0 || !strings.Contains(errs, "error") {
				t.Fatalf("exit %d, stderr %q: want an error", code, errs)
			}
		})
	}
}
