package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func TestUnitsCodeowners(t *testing.T) {
	// the example lives in this git repository, so paths carry its prefix
	code, out, errs := halo(t, "units", "codeowners", "--policy-dir", example, "--owner", "@acme/ai-platform")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{
		"* @acme/ai-platform\n",
		"/examples/acme-corp/units/payments/ @acme/payments-platform\n",
		"/examples/acme-corp/units/payments/checkout/ @acme/checkout-team @acme/payments-platform\n",
		"/examples/acme-corp/units/payments/unit.yaml @acme/ai-platform\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("codeowners lacks %q:\n%s", want, out)
		}
	}
	// outside any git repository the paths are relative to the policy dir
	dir := copyDir(t, example)
	if code, out, errs = halo(t, "units", "codeowners", "--policy-dir", dir, "--owner", "@acme/ai-platform"); code != 0 || !strings.Contains(out, "\n/units/payments/checkout/ ") || !strings.Contains(out, "\n/units/payments/unit.yaml @acme/ai-platform\n") {
		t.Fatalf("%d %s\n%s", code, errs, out)
	}
	// top-level unit files need root owners
	if code, _, errs = halo(t, "units", "codeowners", "--policy-dir", dir); code == 0 || !strings.Contains(errs, "--owner") {
		t.Fatalf("no --owner: %d %s", code, errs)
	}
}

func TestExplainUser(t *testing.T) {
	explain := func(args ...string) explained {
		t.Helper()
		code, out, errs := halo(t, append([]string{"--output", "json", "explain", "--policy-dir", example}, args...)...)
		if code != 0 {
			t.Fatalf("%v: %d %s", args, code, errs)
		}
		var r explained
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return r
	}
	source := func(r explained, path, value string) string {
		i := slices.IndexFunc(r.Fields, func(f policy.FieldSource) bool { return f.Path == path && f.Value == value })
		if i < 0 {
			t.Fatalf("no %s=%s in %+v", path, value, r.Fields)
		}
		return r.Fields[i].Source
	}
	r := explain("--user", "carol", "--groups", "payments-eng, checkout-eng")
	if !slices.Equal(r.Units, []string{"payments", "checkout"}) || r.Ring == "" {
		t.Fatalf("carol: %+v", r)
	}
	if got := source(r, "permissions.mode", "plan"); got != "unit checkout" {
		t.Errorf("mode set by %q", got)
	}
	if got := source(r, "permissions.deny[]", "Bash(psql:*)"); got != "unit payments" {
		t.Errorf("deny set by %q", got)
	}
	r = explain("--user", "dave")
	if len(r.Units) != 0 || source(r, "permissions.mode", "default") != "profile base" {
		t.Fatalf("dave: %+v", r)
	}
	if code, _, errs := halo(t, "explain", "--policy-dir", example, "--user", "x", "--kind", "Unit"); code == 0 || !strings.Contains(errs, "exclusive") {
		t.Fatalf("--kind with --user: %d %s", code, errs)
	}
	if code, out, _ := halo(t, "explain", "--policy-dir", example, "--kind", "Unit"); code != 0 || !strings.Contains(out, "# source: units/payments/checkout/unit.yaml") {
		t.Fatalf("explain --kind Unit: %d\n%s", code, out)
	}
	if code, out, _ := halo(t, "explain", "--policy-dir", example, "--user", "carol", "--groups", "payments-eng"); code != 0 || !strings.Contains(out, "unit     payments\n") || !strings.Contains(out, "SET BY") {
		t.Fatalf("text: %d\n%s", code, out)
	}
}

func TestValidateRejectsUnitLoosening(t *testing.T) {
	dir := copyDir(t, example)
	p := filepath.Join(dir, "units", "payments", "checkout", "unit.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "    mode: plan\n", "    mode: plan\n    sandbox: \"off\"\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := halo(t, "validate", "--policy-dir", dir)
	if code != exitValidation || !strings.Contains(out, "units[checkout].overlay.permissions.sandbox") || !strings.Contains(out, `"off" is looser than "workspace-write"`) {
		t.Fatalf("%d\n%s", code, out)
	}
	if code, _, errs := halo(t, "release", "build", "--policy-dir", dir, "--ring", "ring3-ga", "--release-version", "1.0.0", "--out", t.TempDir()); code != exitValidation {
		t.Fatalf("release build of a loosening policy: %d %s", code, errs)
	}
}

// `halo release build` (and so publish) refuses a workload rule that pins no
// tenant, as `halo validate` does.
func TestReleaseBuildRefusesUnpinnedWorkload(t *testing.T) {
	dir := copyDir(t, "../../examples/ci-agents")
	p := filepath.Join(dir, "halos.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errs := halo(t, "release", "build", "--policy-dir", dir, "--ring", "ring3-ga", "--release-version", "1.0.0", "--no-artifacts", "--out", filepath.Join(t.TempDir(), "r.tar")); code != 0 {
		t.Fatalf("fixture: %d %s", code, errs)
	}
	bad := strings.Replace(string(b), "        namespace_id: \"4242\"\n        namespace_path: acme\n", "", 1)
	if bad == string(b) {
		t.Fatal("fixture changed")
	}
	if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := halo(t, "release", "build", "--policy-dir", dir, "--ring", "ring3-ga", "--release-version", "1.0.0", "--no-artifacts", "--out", filepath.Join(t.TempDir(), "r.tar"))
	if code != exitValidation || !strings.Contains(errs, "pins no tenant") {
		t.Fatalf("release build of an unpinned workload rule: %d %s", code, errs)
	}
}
