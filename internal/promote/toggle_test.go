package promote

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const toggleRepoRoot = "org: acme\n"

func toggleRepo(t *testing.T, toggle string) string {
	t.Helper()
	dir := t.TempDir()
	for f, c := range map[string]string{
		"halos.yaml": toggleRepoRoot,
		"profiles/base.yaml": `apiVersion: halos.dev/v1alpha1
kind: Profile
name: base
harnesses: {claude-code: {version: 2.1.0}}
telemetry: {enabled: true}
permissions: {disableBypass: true}
`,
		"rings/r1.yaml":  "apiVersion: halos.dev/v1alpha1\nkind: Ring\nname: r1\norder: 1\nprofile: base\nmembership: {percent: 10}\n",
		"rings/ga.yaml":  "apiVersion: halos.dev/v1alpha1\nkind: Ring\nname: ga\norder: 9\nprofile: base\nmembership: {default: true}\n",
		"toggles/t.yaml": toggle,
	} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const toggleDoc = `# my toggle
apiVersion: halos.dev/v1alpha1
kind: Toggle
name: t
owner: me
expires: "2999-01-01"
default: false
axis: client
rules:
  # first rule
  - name: canary
    rings: [r1]
    percent: 10
client:
  harnesses:
    claude-code:
      env: {MY_FLAG: "on"}
---
apiVersion: halos.dev/v1alpha1
kind: Toggle
name: other
owner: me
expires: "2999-01-01"
default: true
axis: client
client:
  harnesses:
    claude-code:
      env: {OTHER: "1"}
`

func TestPlanToggle(t *testing.T) {
	zero, fifty := 0.0, 50.0
	yes := true
	tests := []struct {
		name    string
		c       ToggleChange
		want    []string // substrings of the new file
		notWant []string
		wantErr string
	}{
		{"percent", ToggleChange{Rule: "canary", Percent: &fifty}, []string{"percent: 50", "# first rule", "# my toggle", "name: other", "OTHER"}, []string{"!!"}, ""},
		{"percent by index, ramp down to 0", ToggleChange{Rule: "0", Percent: &zero}, []string{"percent: 0\n"}, nil, ""},
		{"default and expiry", ToggleChange{Default: &yes, Expires: "2999-02-02"}, []string{"default: true", `expires: "2999-02-02"`}, nil, ""},
		{"add ring", ToggleChange{Rule: "canary", AddRings: []string{"ga"}}, []string{"rings: [r1, ga]"}, nil, ""},
		{"add group creates the list", ToggleChange{Rule: "canary", AddGroups: []string{"eng"}}, []string{"groups: [eng]"}, nil, ""},
		{"remove ring", ToggleChange{Rule: "canary", AddRings: []string{"ga"}, RemoveRings: []string{"r1"}}, []string{"rings: [ga]"}, []string{"r1]"}, ""},
		{"the other toggle in the file is untouched by default", ToggleChange{Default: &yes}, []string{"default: true", "default: true\naxis: client\nclient"}, nil, ""},

		{"unknown ring fails validation", ToggleChange{Rule: "canary", AddRings: []string{"ghost"}}, nil, nil, "unknown ring"},
		{"emptying a list would widen the rule", ToggleChange{Rule: "canary", RemoveRings: []string{"r1"}}, nil, nil, "widens"},
		{"remove a missing entry", ToggleChange{Rule: "canary", RemoveGroups: []string{"x"}}, nil, nil, "is not in the rule"},
		{"unknown rule", ToggleChange{Rule: "nope", Percent: &fifty}, nil, nil, "not found"},
		{"percent out of range", ToggleChange{Rule: "canary", Percent: ptr(101.0)}, nil, nil, "0-100"},
		{"nothing to change", ToggleChange{}, nil, nil, "nothing to change"},
		{"rule without an edit", ToggleChange{Rule: "canary", Default: &yes}, nil, nil, "nothing to change in it"},
		{"edit without a rule", ToggleChange{Percent: &fifty}, nil, nil, "rule (name or index) is required"},
		{"already has this change", ToggleChange{Rule: "canary", Percent: ptr(10.0)}, nil, nil, "already has"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := toggleRepo(t, toggleDoc)
			ch, err := PlanToggle(dir, "t", tc.c)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, ErrToggleChange) {
					t.Fatalf("err = %v, want %q wrapping ErrToggleChange", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := string(ch.Files["toggles/t.yaml"])
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("unexpected %q in:\n%s", w, got)
				}
			}
			if ch.Patch == "" || ch.Edit == nil {
				t.Fatal("no patch / edit")
			}
			if b, _ := os.ReadFile(filepath.Join(dir, "toggles/t.yaml")); string(b) != toggleDoc {
				t.Fatal("PlanToggle wrote to the repo")
			}
			// Edit re-applies to another version of the file
			re, err := ch.Edit(func(string) ([]byte, error) { return []byte(toggleDoc), nil })
			if err != nil || string(re["toggles/t.yaml"]) != got {
				t.Fatalf("Edit differs: %v", err)
			}
		})
	}
}

func ptr(f float64) *float64 { return &f }
