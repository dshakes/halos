package onboard

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestDoctorPosture(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		env    map[string]string
		bins   []string
		detail string // posture/<h> ok detail substring
		warns  []string
	}{
		{"claude managed sandbox", map[string]string{
			"/etc/claude-code/managed-settings.json": `{"sandbox":{"enabled":true,"network":{"allowManagedDomainsOnly":true,"allowedDomains":["a.example"]}}}`,
		}, nil, []string{"claude"}, "sandbox: on (managed); egress: default deny, 1 allowed, 0 denied (managed)", nil},
		{"no managed file", nil, nil, []string{"claude"}, "sandbox: not managed; egress: not managed", nil},
		{"gemini env turns the sandbox off", map[string]string{"/etc/gemini-cli/settings.json": `{"tools":{"sandbox":true}}`},
			map[string]string{"GEMINI_SANDBOX": "false"}, []string{"gemini"}, "tools.sandbox=true", []string{"GEMINI_SANDBOX is set"}},
		{"gemini SANDBOX skips the sandbox", map[string]string{"/etc/gemini-cli/settings.json": `{"tools":{"sandbox":true}}`},
			map[string]string{"SANDBOX": "1"}, []string{"gemini"}, "tools.sandbox=true", []string{"SANDBOX is set"}},
		{"codex user escape", map[string]string{
			"/etc/codex/requirements.toml": "allowed_sandbox_modes = ['read-only']\n",
			"/home/u/.codex/config.toml":   `sandbox_mode = "danger-full-access"`,
		}, nil, []string{"codex"}, "modes [read-only] (managed)", []string{`sandbox_mode = "danger-full-access"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fake("", nil)
			e.LookPath = func(b string) (string, error) {
				for _, x := range tt.bins {
					if b == x {
						return "/usr/bin/" + b, nil
					}
				}
				return "", errors.New("not found")
			}
			e.Run = func(context.Context, string, ...string) ([]byte, error) { return []byte("1.0.0\n"), nil }
			e.Getenv = func(k string) string { return tt.env[k] }
			e.Home = "/home/u"
			e.ReadFile = func(p string) ([]byte, error) {
				if s, ok := tt.files[p]; ok {
					return []byte(s), nil
				}
				return nil, fs.ErrNotExist
			}
			r := Doctor(context.Background(), e, "")
			if len(r.Posture) != 1 {
				t.Fatalf("posture = %+v, want one installed harness", r.Posture)
			}
			var ok bool
			var warns []string
			for _, c := range r.Checks {
				if !strings.HasPrefix(c.ID, "posture/") {
					continue
				}
				switch c.Status {
				case StatusOK:
					ok = strings.Contains(c.Detail, tt.detail)
				case StatusWarn:
					if c.Fix == "" {
						t.Errorf("%s warn has no fix", c.ID)
					}
					warns = append(warns, c.Detail)
				}
			}
			if !ok {
				t.Errorf("no ok posture check containing %q in %+v", tt.detail, r.Checks)
			}
			if len(warns) != len(tt.warns) {
				t.Fatalf("warns = %q, want %q", warns, tt.warns)
			}
			for i, w := range tt.warns {
				if !strings.Contains(warns[i], w) {
					t.Errorf("warn %d = %q, want ~%q", i, warns[i], w)
				}
			}
		})
	}
}
