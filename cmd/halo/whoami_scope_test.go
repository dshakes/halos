package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWhoamiConsoleRoles: halo whoami shows the halo-server roles a user
// holds and over which scope (ADR-0037).
func TestWhoamiConsoleRoles(t *testing.T) {
	dir := copyDir(t, example)
	f := filepath.Join(dir, "halos.yaml")
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), "  roles:\n", "  roles:\n    viewer: [eng]\n", 1)
	s = strings.Replace(s, "\nselfService:\n", "\n  roleBindings:\n"+
		"    - role: operator\n      groups: [payments-sre]\n      scope: {rings: [ring1-canary], units: [payments]}\nselfService:\n", 1)
	if strings.Count(s, "viewer: [eng]")+strings.Count(s, "roleBindings:") != 2 {
		t.Fatal("example halos.yaml changed: no identity.roles or selfService")
	}
	if err := os.WriteFile(f, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := halo(t, "validate", "--policy-dir", dir); code != 0 {
		t.Fatalf("validate: %d %s %s", code, out, errOut)
	}
	code, out, _ := halo(t, "whoami", dir, "--user", "sam@acme.example", "--groups", "eng,payments-sre")
	if code != 0 || !strings.Contains(out, "console  viewer over global (identity.roles.viewer)") ||
		!strings.Contains(out, "console  operator over rings=ring1-canary units=payments (identity.roleBindings[0])") {
		t.Fatalf("%d\n%s", code, out)
	}
	_, out, _ = halo(t, "whoami", dir, "--user", "sam@acme.example", "--groups", "payments-sre", "--output", "json")
	var res struct {
		ConsoleRoles []struct {
			Role   string
			Scope  struct{ Rings, Units []string }
			Source string
		}
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.ConsoleRoles) != 1 || res.ConsoleRoles[0].Role != "operator" ||
		strings.Join(res.ConsoleRoles[0].Scope.Units, ",") != "payments" {
		t.Fatalf("%v %s", err, out)
	}
	if _, out, _ := halo(t, "whoami", dir, "--user", "nobody@acme.example"); !strings.Contains(out, "console  (no halo-server role)") {
		t.Fatalf("no role: %s", out)
	}
}
