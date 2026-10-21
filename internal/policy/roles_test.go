package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// identity.roles decodes strictly: a misspelled role is a load error, never a
// silently empty grant. Unset roles leave the JSON form (snapshot digests) as before.
func TestIdentityRoles(t *testing.T) {
	for _, tc := range []struct {
		name, roles, err string
	}{
		{"all roles", "  roles:\n    viewer: [eng]\n    operator: [sre]\n    approver: [leads]\n    auditor: [sec]\n    admin: [plat]\n", ""},
		{"unknown role", "  roles:\n    superuser: [eng]\n", "superuser"},
		{"not a list", "  roles:\n    viewer: eng\n", "cannot unmarshal"},
		{"unset", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := "org: acme\nidentity:\n  issuer: https://idp.example\n  adminGroups: [ops]\n" + tc.roles
			if err := os.WriteFile(filepath.Join(dir, RootFile), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := ReadRoot(dir)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r := root.Identity.Roles
			b, _ := json.Marshal(root.Identity)
			if tc.roles == "" {
				if strings.Contains(string(b), "roles") {
					t.Fatalf("unset roles serialized: %s", b)
				}
				return
			}
			if !slices.Equal(r.Viewer, []string{"eng"}) || !slices.Equal(r.Operator, []string{"sre"}) || !slices.Equal(r.Approver, []string{"leads"}) ||
				!slices.Equal(r.Auditor, []string{"sec"}) || !slices.Equal(r.Admin, []string{"plat"}) {
				t.Fatalf("roles = %+v", r)
			}
		})
	}
}
