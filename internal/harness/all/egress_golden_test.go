package all_test

import (
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

// TestEgressSandboxGolden renders one sandbox + egress policy (ADR-0032) with
// every adapter on every OS: the files each harness gets and the warnings for
// what it cannot hold. Run with -update to rewrite testdata/egress.
func TestEgressSandboxGolden(t *testing.T) {
	p := &policy.Profile{
		Meta: policy.Meta{APIVersion: policy.APIVersion, Kind: policy.KindProfile, Name: "egress"},
		Harnesses: map[string]policy.HarnessSpec{
			"claude-code": {Version: "2.1.280"}, "codex": {Version: "0.99.0"}, "gemini-cli": {Version: "0.34.0"},
			"copilot-cli": {Version: "1.0.93"}, "opencode": {Version: "1.19.3"}, "cursor-agent": {},
		},
		Permissions: policy.Permissions{DisableBypass: true, SandboxRequired: true},
		Sandbox: policy.Sandbox{Mode: "workspace-write", WritableRoots: []string{"/opt/build-cache"},
			ProtectedPaths: []string{"~/.ssh", "~/.aws", "/etc/secrets", ".env*"}},
		Egress: policy.Egress{Default: policy.EgressDeny, AllowedDomains: []string{"gw.example.com"},
			DeniedDomains: []string{"pastebin.com"}, Presets: []string{"package-registries"}},
	}
	p.Permissions.Sandbox = p.Sandbox.Mode // what ResolveProfile does
	for _, name := range harness.Names() {
		ad, _ := harness.Get(name)
		for _, os := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
			files, warns, err := ad.Render(p, harness.Context{Ring: "ga", Release: "1.0.0", OS: os})
			if err != nil {
				t.Fatalf("%s/%s: %v", name, os, err)
			}
			for _, f := range files {
				if tok := policy.BypassToken(string(f.Data)); tok != "" {
					t.Errorf("%s/%s %s: bypass token %q (invariant 1)", name, os, f.Path, tok)
				}
				hutiltest.Golden(t, "egress/"+name+"/"+string(os)+"_"+f.Path[strings.LastIndexAny(f.Path, `/\`)+1:], f.Data)
			}
			hutiltest.Golden(t, "egress/"+name+"/"+string(os)+"_warnings.txt", []byte(strings.Join(warns, "\n")+"\n"))
		}
	}
}
