package harness_test

import (
	"io/fs"
	"testing"

	"github.com/dshakes/halos/internal/harness"
)

func TestReadPosture(t *testing.T) {
	const home = "/home/alice"
	claudeOn := `{"sandbox":{"enabled":true,"network":{"allowManagedDomainsOnly":true,"allowedDomains":["a.example","b.example"],"deniedDomains":["x.example"]}}}`
	codexReq := "allowed_sandbox_modes = ['read-only', 'workspace-write']\n[experimental_network]\nenabled = true\nmanaged_allowed_domains_only = true\n[experimental_network.domains]\n'a.example' = 'allow'\n"
	tests := []struct {
		name     string
		harness  string
		files    map[string]string
		sandbox  string
		egress   string
		findings int
	}{
		{"claude managed", "claude-code", map[string]string{"/etc/claude-code/managed-settings.json": claudeOn},
			"on (managed)", "default deny, 2 allowed, 1 denied (managed)", 0},
		{"claude unmanaged", "claude-code", nil, "not managed", "not managed", 0},
		{"codex user escape", "codex", map[string]string{"/etc/codex/requirements.toml": codexReq, home + "/.codex/config.toml": `sandbox_mode = "danger-full-access"`},
			"modes [read-only workspace-write] (managed)", "default deny, 1 allowed, 0 denied (managed)", 1},
		{"codex user escape ignored without managed sandbox", "codex", map[string]string{home + "/.codex/config.toml": `sandbox_mode = "danger-full-access"`},
			"not managed", "not managed", 0},
		{"codex harmless user config", "codex", map[string]string{"/etc/codex/requirements.toml": codexReq, home + "/.codex/config.toml": `sandbox_mode = "read-only"`},
			"modes [read-only workspace-write] (managed)", "default deny, 1 allowed, 0 denied (managed)", 0},
		{"gemini user off", "gemini-cli", map[string]string{"/etc/gemini-cli/settings.json": `{"tools":{"sandbox":true}}`, home + "/.gemini/settings.json": `{"tools":{"sandbox":false}}`},
			"tools.sandbox=true (system default; --sandbox and GEMINI_SANDBOX override it)", "not managed", 1},
		{"copilot deny all", "copilot-cli", map[string]string{"/etc/github-copilot/managed-settings.json": `{"sandbox":{"enabled":true,"userPolicy":{"network":{"allowOutbound":false}}}}`},
			"on (managed minimum)", "default deny, nothing allowed (managed)", 0},
		{"opencode webfetch", "opencode", map[string]string{"/etc/opencode/opencode.json": `{"permission":{"webfetch":"deny"}}`},
			"not managed", "webfetch deny (managed; bash is not sandboxed)", 0},
		{"cursor user sandbox off", "cursor-agent", map[string]string{home + "/.cursor/sandbox.json": `{"type":"insecure_none"}`},
			"not managed", "not managed", 1},
		{"corrupt file is not managed", "claude-code", map[string]string{"/etc/claude-code/managed-settings.json": `{`}, "not managed", "not managed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				if s, ok := tt.files[p]; ok {
					return []byte(s), nil
				}
				return nil, fs.ErrNotExist
			}
			got := harness.ReadPosture(tt.harness, harness.Linux, home, read)
			if got.Sandbox != tt.sandbox || got.Egress != tt.egress || len(got.Findings) != tt.findings {
				t.Fatalf("posture = %+v, want sandbox %q egress %q with %d findings", got, tt.sandbox, tt.egress, tt.findings)
			}
			for _, f := range got.Findings {
				if f.Problem == "" || f.Fix == "" {
					t.Errorf("finding without problem or fix: %+v", f)
				}
			}
		})
	}
}
