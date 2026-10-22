package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVendorAdminValidate(t *testing.T) {
	tests := []struct {
		name string
		va   *VendorAdmin
		want string // substring of an issue; "" = no issue
		sev  Severity
	}{
		{"ok", &VendorAdmin{Copilot: &VendorTarget{Org: "acme"}, Gemini: &VendorTarget{Project: "acme-dev", ReleaseChannel: "stable"}, Claude: &VendorTarget{}}, "", ""},
		{"copilot needs org", &VendorAdmin{Copilot: &VendorTarget{}}, "vendorAdmin.copilot.org", SeverityError},
		{"copilot org path", &VendorAdmin{Copilot: &VendorTarget{Org: "a/../b"}}, "not a valid id", SeverityError},
		{"claude org traversal", &VendorAdmin{Claude: &VendorTarget{Org: ".."}}, "vendorAdmin.claude.org", SeverityError},
		{"cursor org escape", &VendorAdmin{Cursor: &VendorTarget{Org: "a\x1b[2J"}}, "vendorAdmin.cursor.org", SeverityError},
		{"org too long", &VendorAdmin{Codex: &VendorTarget{Org: strings.Repeat("a", 40)}}, "vendorAdmin.codex.org", SeverityError},
		{"project uppercase", &VendorAdmin{Gemini: &VendorTarget{Project: "Acme_Dev"}}, "vendorAdmin.gemini.project", SeverityError},
		{"project traversal", &VendorAdmin{Gemini: &VendorTarget{Project: "../../x"}}, "vendorAdmin.gemini.project", SeverityError},
		{"location traversal", &VendorAdmin{Gemini: &VendorTarget{Project: "acme-dev", Location: "../x"}}, "location", SeverityError},
		{"uuid org ok", &VendorAdmin{Claude: &VendorTarget{Org: "4f9c2a1e-0b6d-4e1a-9c2f-7a3b5d8e1f00"}}, "", ""},
		{"gemini needs project", &VendorAdmin{Gemini: &VendorTarget{}}, "vendorAdmin.gemini.project", SeverityError},
		{"bad channel", &VendorAdmin{Gemini: &VendorTarget{Project: "acme-dev", ReleaseChannel: "nightly"}}, "releaseChannel", SeverityError},
		{"bad location", &VendorAdmin{Gemini: &VendorTarget{Project: "acme-dev", Location: "Mars"}}, "location", SeverityError},
		{"gemini fields elsewhere", &VendorAdmin{Codex: &VendorTarget{Project: "acme-dev"}}, "gemini only", SeverityError},
		{"unknown ring", &VendorAdmin{Ring: "nope", Claude: &VendorTarget{}}, "unknown ring", SeverityError},
		{"non-GA ring warns", &VendorAdmin{Ring: "ring1-canary", Claude: &VendorTarget{}}, "org-wide", SeverityWarning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := mustLoad(t)
			o.VendorAdmin = tc.va
			var hit *Issue
			for _, i := range o.Validate() {
				if strings.HasPrefix(i.Path, "vendorAdmin") {
					if tc.want == "" {
						t.Fatalf("unexpected issue %v", i)
					}
					if strings.Contains(i.String(), tc.want) {
						hit = &i
					}
				}
			}
			if tc.want != "" && (hit == nil || hit.Severity != tc.sev) {
				t.Fatalf("want %s %q, got %v", tc.sev, tc.want, hit)
			}
		})
	}
	if got := mustLoad(t).VendorAdminRing(); got != "ring3-ga" {
		t.Fatalf("default ring %q, want the highest order ring", got)
	}
}

// halos.yaml vendorAdmin decodes strictly: a credential-shaped key is an error.
func TestVendorAdminStrictDecode(t *testing.T) {
	dir := t.TempDir()
	b := "org: acme\nvendorAdmin:\n  copilot:\n    org: acme\n    token: ghp_x\n"
	if err := os.WriteFile(filepath.Join(dir, RootFile), []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRoot(dir); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("want strict decode error on token, got %v", err)
	}
}
