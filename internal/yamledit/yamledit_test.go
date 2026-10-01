package yamledit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

const src = "# head\nkind: Experiment\nname: e1   # keep\nstatus: draft # c\n\n# tail\nx: 1\n"

func find(t *testing.T, in string, kind policy.Kind, name string) *Doc {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Find(dir, kind, name)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSetField(t *testing.T) {
	const e = "kind: Experiment\nname: e1\n"
	tests := []struct{ name, in, key, val, want string }{
		{"replace", src, "status", "running", "# head\nkind: Experiment\nname: e1   # keep\nstatus: running # c\n\n# tail\nx: 1\n"},
		{"insert", "kind: Experiment\nname: e1\n# c\nx: 1\n", "status", "paused", "kind: Experiment\nname: e1\nstatus: paused\n# c\nx: 1\n"},
		{"double", e + "status: \"draft\"\n", "status", "running", e + "status: \"running\"\n"},
		{"double escaped", e + "status: \"dr\\\"a # ft\" # c\nx: 1\n", "status", "run\"ning", e + "status: \"run\\\"ning\" # c\nx: 1\n"},
		{"single", e + "status: 'it''s' # c\n", "status", "o'k", e + "status: 'o''k' # c\n"},
		{"plain needs quotes", e + "status: draft\n", "status", "true", e + "status: \"true\"\n"},
		{"plain with colon", e + "status: draft\n", "status", "a: b", e + "status: \"a: b\"\n"},
		{"plain hash", e + "status: draft\n", "status", "a #b", e + "status: \"a #b\"\n"},
		{"insert quoted", e, "status", "", e + "status: \"\"\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := find(t, tc.in, policy.KindExperiment, "e1")
			got, err := d.SetField(tc.key, tc.val)
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if d.Rel != "a.yaml" {
				t.Errorf("Rel = %q", d.Rel)
			}
			m, err := Parse(got, policy.KindExperiment, "e1")
			if err != nil || m == nil {
				t.Fatalf("reparse: %v", err)
			}
			if _, v := Scalar(m, tc.key); v == nil || v.Value != tc.val {
				t.Fatalf("value round trip: %+v", v)
			}
		})
	}
	if _, err := Find(t.TempDir(), policy.KindExperiment, "nope"); err == nil {
		t.Error("want not-found error")
	}
	if _, err := find(t, e+"status: |\n  x\n", policy.KindExperiment, "e1").SetField("status", "y"); err == nil {
		t.Error("block scalar: want error")
	}
}

const multi = `# doc one
kind: Ring
name: a # first
membership:
  users: [x]
---
kind: Ring
name: b
# comment in b
membership:
  percent: 5
---
kind: Ring
name: c
release: "sha256:c"
`

func TestMultiDoc(t *testing.T) {
	docs := strings.Split(multi, "---\n")
	check := func(t *testing.T, got []byte) {
		t.Helper()
		parts := strings.Split(string(got), "---\n")
		if len(parts) != 3 || parts[0] != docs[0] || parts[2] != docs[2] {
			t.Fatalf("other docs changed:\n%s", got)
		}
	}
	d := find(t, multi, policy.KindRing, "b")
	got, err := d.AppendSeq([]string{"membership", "users"}, "u@x")
	if err != nil {
		t.Fatal(err)
	}
	check(t, got)
	if !strings.Contains(string(got), "  percent: 5\n  users:\n    - u@x\n---") || !strings.Contains(string(got), "# comment in b") {
		t.Fatalf("append:\n%s", got)
	}
	got, err = d.SetField("release", "sha256:new")
	if err != nil {
		t.Fatal(err)
	}
	check(t, got)
	if !strings.Contains(string(got), "name: b\nrelease: sha256:new\n") {
		t.Fatalf("set:\n%s", got)
	}
	c := find(t, multi, policy.KindRing, "c")
	got, err = c.SetField("release", "sha256:z")
	if err != nil || !strings.HasSuffix(string(got), "release: \"sha256:z\"\n") || !strings.HasPrefix(string(got), docs[0]+"---\n"+docs[1]) {
		t.Fatalf("doc 3 set: %v\n%s", err, got)
	}
}

func TestAppendSeq(t *testing.T) {
	type srv struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
	}
	const r = "kind: Ring\nname: r\n"
	tests := []struct {
		name, in string
		path     []string
		item     any
		want     string
	}{
		{"block", r + "membership:\n  users:\n    - a # c\n  optIn: true\n", []string{"membership", "users"}, "b",
			r + "membership:\n  users:\n    - a # c\n    - b\n  optIn: true\n"},
		{"block same indent", r + "membership:\n  users:\n  - a\n\n# tail\n", []string{"membership", "users"}, "b",
			r + "membership:\n  users:\n  - a\n  - b\n\n# tail\n"},
		{"missing key", r + "membership:\n  percent: 5\n# tail\n", []string{"membership", "users"}, "b",
			r + "membership:\n  percent: 5\n  users:\n    - b\n# tail\n"},
		{"missing parent", r + "order: 1\n", []string{"membership", "users"}, "true",
			r + "order: 1\nmembership:\n  users:\n    - \"true\"\n"},
		{"null", r + "membership:\n  users: ~ # none\n", []string{"membership", "users"}, "b",
			r + "membership:\n  users: # none\n    - b\n"},
		{"null parent", r + "membership:\norder: 1\n", []string{"membership", "users"}, "b",
			r + "membership:\n  users:\n    - b\norder: 1\n"},
		{"flow", r + "membership:\n  users: [a, 'b c'] # c\n", []string{"membership", "users"}, "d",
			r + "membership:\n  users:\n    - a\n    - 'b c'\n    - d # c\n"},
		{"flow empty", r + "mcp:\n  servers: []\n", []string{"mcp", "servers"}, srv{"jira", "https://j"},
			r + "mcp:\n  servers:\n    - name: jira\n      url: https://j\n"},
		{"block mapping items", r + "mcp:\n  servers:\n    - name: a\n      url: https://a\n      headers:\n        X: y\n\n  other: 1\n", []string{"mcp", "servers"}, srv{"b", "https://b"},
			r + "mcp:\n  servers:\n    - name: a\n      url: https://a\n      headers:\n        X: y\n    - name: b\n      url: https://b\n\n  other: 1\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := find(t, tc.in, policy.KindRing, "r").AppendSeq(tc.path, tc.item)
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v\nwant %q", got, err, tc.want)
			}
		})
	}
	for name, in := range map[string]string{
		"not a list":    r + "membership:\n  users: a\n",
		"not a mapping": r + "membership: 3\n",
		"flow mapping":  r + "membership: {percent: 5}\n",
	} {
		if _, err := find(t, in, policy.KindRing, "r").AppendSeq([]string{"membership", "users"}, "b"); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestSave(t *testing.T) {
	d := find(t, src, policy.KindExperiment, "e1")
	if err := d.Save([]byte("x: 1\n")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(d.Path)
	st, _ := os.Stat(d.Path)
	if string(b) != "x: 1\n" || st.Mode().Perm() != 0o644 {
		t.Fatalf("%q %v", b, st.Mode())
	}
}
