package policytest

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const hdr = "apiVersion: halos.dev/v1\nkind: PolicyTest\nname: s\ncases:\n"

// goodSuite passes against the example policy.
const goodSuite = hdr + `  - name: ga
    identity: {user: dev0@acme.example}
    expect:
      ring: ring3-ga
      variants: {opus-5-5-canary: ""}
      settings:
        claude-code: {permissions.defaultMode: default, sandbox.enabled: true}
`

func casesRun(t *testing.T, files map[string]string) *Report {
	t.Helper()
	d := slim(t)
	for name, content := range files {
		write(t, d, "tests/"+name, content)
	}
	return run(t, Options{Dir: d, Ring: "ring3-ga"})
}

func TestCasesPass(t *testing.T) {
	rep := casesRun(t, map[string]string{"a.yaml": goodSuite})
	if r := find(t, rep, SuiteCases, "s/ga"); r.Status != Pass || !rep.OK {
		t.Fatalf("%+v", r)
	}
}

// Check 6: each wrong expectation fails its case with the reason, and only that case.
func TestCaseExpectationsFail(t *testing.T) {
	tests := []struct {
		name   string
		expect string // the expect: block body
		user   string
		groups string
		want   []string
	}{
		{"wrong ring", "ring: ring1-canary", "dev0@acme.example", "[]",
			[]string{`ring: want "ring1-canary", got "ring3-ga"`}},
		{"group lands in another ring", "ring: ring3-ga", "x@acme.example", "[ai-platform]",
			[]string{`ring: want "ring3-ga", got "ring0-harness-team"`}},
		{"expected no ring", `ring: ""`, "dev0@acme.example", "[]",
			[]string{`ring: want (none), got "ring3-ga"`}},
		{"wrong variant", "variants: {opus-5-5-canary: opus-5-5}", "dev5@acme.example", "[]",
			[]string{`variants.opus-5-5-canary: want "opus-5-5", got "control"`}},
		{"not enrolled", "variants: {opus-5-5-canary: control}", "dev0@acme.example", "[]",
			[]string{`variants.opus-5-5-canary: want "control", got (none)`}},
		{"unknown experiment", "variants: {nope: control}", "dev0@acme.example", "[]",
			[]string{"variants.nope: no running experiment of that name"}},
		{"wrong setting", "settings: {claude-code: {permissions.defaultMode: plan}}", "dev0@acme.example", "[]",
			[]string{`settings.claude-code.permissions.defaultMode (linux): want "plan", got "default"`}},
		{"wrong type", "settings: {claude-code: {sandbox.enabled: \"true\"}}", "dev0@acme.example", "[]",
			[]string{`want "true", got true`}},
		{"missing key", "settings: {claude-code: {sandbox.nope: 1}}", "dev0@acme.example", "[]",
			[]string{"settings.claude-code.sandbox.nope (linux): want 1, but the key is absent"}},
		{"key that must be absent is there", "settings: {claude-code: {sandbox.enabled: null}}", "dev0@acme.example", "[]",
			[]string{"want absent, got true"}},
		{"harness not in the profile", "settings: {cursor-agent: {a: 1}}", "dev0@acme.example", "[]",
			[]string{"settings.cursor-agent: harness is not enabled in profile engineering"}},
		{"several at once", "ring: ring1-canary\n      settings: {claude-code: {sandbox.enabled: false}}", "dev0@acme.example", "[]",
			[]string{"ring: want", "sandbox.enabled"}},
	}
	// One run for all of them: every case is independent, and a run builds releases.
	var suite strings.Builder
	suite.WriteString(hdr)
	for _, tt := range tests {
		suite.WriteString("  - name: " + tt.name + "\n    identity: {user: " + tt.user + ", groups: " + tt.groups + "}\n    expect:\n      " + tt.expect + "\n")
	}
	suite.WriteString("  - name: ok\n    identity: {user: dev0@acme.example}\n    expect: {ring: ring3-ga}\n")
	rep := casesRun(t, map[string]string{"a.yaml": suite.String()})
	if ok := find(t, rep, SuiteCases, "s/ok"); ok.Status != Pass {
		t.Errorf("a passing case failed with the others: %+v", ok)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := wantFail(t, rep, SuiteCases, "s/"+tt.name, tt.want[0])
			for _, w := range tt.want[1:] {
				if !strings.Contains(strings.Join(r.Details, "\n"), w) {
					t.Errorf("details lack %q: %v", w, r.Details)
				}
			}
		})
	}
}

// Check 6: a test file that is not a valid PolicyTest document fails by file name.
func TestInvalidTestFiles(t *testing.T) {
	tests := []struct {
		name, file, content, want string
		schema                    bool // the JSON schema rejects it too (the rest is checked in Go only)
	}{
		{"unknown field", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expct: {ring: r}\n    expect: {ring: r}\n", "field expct not found", true},
		{"unknown expect field", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {rings: r}\n", "field rings not found", true},
		{"missing identity user", "a.yaml", hdr + "  - name: c\n    identity: {groups: [g]}\n    expect: {ring: r}\n", "identity.user is required", true},
		{"asserts nothing", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {}\n", "asserts nothing", true},
		{"bad os", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    os: plan9\n    expect: {ring: r}\n", "os must be one of", true},
		{"wrong kind", "a.yaml", "apiVersion: halos.dev/v1\nkind: Ring\nname: s\ncases: []\n", `kind must be "PolicyTest"`, true},
		{"wrong apiVersion", "a.yaml", "apiVersion: v2\nkind: PolicyTest\nname: s\ncases: [{name: c, identity: {user: u}, expect: {ring: r}}]\n", "apiVersion must be", true},
		{"no cases", "a.yaml", "apiVersion: halos.dev/v1\nkind: PolicyTest\nname: s\ncases: []\n", "at least one case", true},
		{"no name", "a.yaml", "apiVersion: halos.dev/v1\nkind: PolicyTest\ncases: [{name: c, identity: {user: u}, expect: {ring: r}}]\n", "name is required", true},
		{"unknown harness", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {settings: {vim: {a: 1}}}\n", `unknown harness "vim"`, false},
		{"duplicate case name", "a.yaml", hdr + "  - {name: c, identity: {user: u}, expect: {ring: r}}\n  - {name: c, identity: {user: u}, expect: {ring: r}}\n", "duplicate case name", false},
		{"no key paths", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {settings: {codex: {}}}\n", "no key paths", true},
		{"malformed key path", "a.yaml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {settings: {codex: {\"a..b\": 1}}}\n", "malformed key path", false},
		{"empty file", "a.yaml", "# nothing\n", "no document", false},
		{"not yaml", "a.yaml", "cases: [\n", "yaml", false},
		{"nested dir, .yml", "sub/b.yml", hdr + "  - name: c\n    identity: {user: u}\n    expect: {ring: r, bogus: 1}\n", "field bogus not found", true},
	}
	schema := compileSchema(t)
	files := map[string]string{"good.yaml": goodSuite}
	for i, tt := range tests {
		tests[i].file = fmt.Sprintf("%02d/%s", i, filepath.Base(tt.file)) // one file each, so each failure is attributable
		files[tests[i].file] = tt.content
	}
	rep := casesRun(t, files)
	if good := find(t, rep, SuiteCases, "s/ga"); good.Status != Pass {
		t.Errorf("the valid file next to the invalid ones did not run: %+v", good)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := wantFail(t, rep, SuiteCases, "tests/"+tt.file, tt.want)
			if r.Message != "invalid test file" {
				t.Errorf("message = %q", r.Message)
			}
			// The JSON schema agrees with the Go check wherever it can express it.
			var doc any
			if err := yaml.Unmarshal([]byte(tt.content), &doc); err == nil && doc != nil {
				if err := schema.Validate(toJSON(t, doc)); (err != nil) != tt.schema {
					t.Errorf("schema rejects = %v, want %v (%v)", err != nil, tt.schema, err)
				}
			}
		})
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	s, err := jsonschema.NewCompiler().Compile("../../schemas/policytest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func toJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The example tests and a good suite satisfy the schema, and the loader reads them.
func TestExampleSuitesMatchSchema(t *testing.T) {
	schema := compileSchema(t)
	suites, bad, err := LoadSuites(exampleDir)
	if err != nil || len(bad) != 0 || len(suites) < 2 {
		t.Fatalf("suites=%d bad=%v err=%v", len(suites), bad, err)
	}
	for _, s := range suites {
		b, err := yamlFile(filepath.Join(exampleDir, s.File))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(toJSON(t, b)); err != nil {
			t.Errorf("%s: %v", s.File, err)
		}
	}
	var doc any
	if err := yaml.Unmarshal([]byte(goodSuite), &doc); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(toJSON(t, doc)); err != nil {
		t.Errorf("good suite: %v", err)
	}
}

func yamlFile(p string) (any, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var v any
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&v); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return v, nil
}

func TestLoadSuitesWithoutTestsDir(t *testing.T) {
	suites, bad, err := LoadSuites(t.TempDir())
	if err != nil || len(suites) != 0 || len(bad) != 0 {
		t.Fatalf("%v %v %v", suites, bad, err)
	}
	d := slim(t) // no tests/ at all: no cases, and the next_steps say how to add some
	rep := run(t, Options{Dir: d, Ring: "ring3-ga"})
	if !rep.OK || !strings.Contains(strings.Join(rep.NextSteps, "\n"), "no policy tests found") {
		t.Fatalf("ok=%v next=%v", rep.OK, rep.NextSteps)
	}
}

func TestLookup(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{"a":{"b":[{"c":1},{"c":2}]},"x.y":{"z":true},"x":{"y":"short"},"n":null,"s":"v"}`), &doc); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want any
		ok   bool
	}{
		{"s", "v", true},
		{"a.b.1.c", float64(2), true},
		{"a.b.0", map[string]any{"c": float64(1)}, true},
		{"x.y.z", true, true},                    // a key that contains a dot
		{"x.y", map[string]any{"z": true}, true}, // the longest key wins
		{"n", nil, true},
		{"a.b.2.c", nil, false},
		{"a.b.-1.c", nil, false},
		{"a.b.01.c", nil, false},
		{"a.b.c", nil, false},
		{"a.nope", nil, false},
		{"s.deeper", nil, false},
		{"", nil, false},
	}
	for _, tt := range tests {
		got, ok := Lookup(doc, tt.path)
		if ok != tt.ok || (ok && !jsonEq(got, tt.want)) {
			t.Errorf("Lookup(%q) = %v, %v; want %v, %v", tt.path, got, ok, tt.want, tt.ok)
		}
	}
}

func jsonEq(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// TOML numbers and YAML ints compare with JSON numbers.
func TestNormalizeComparesAcrossFormats(t *testing.T) {
	a, err := normalize(int64(3))
	if err != nil {
		t.Fatal(err)
	}
	b, err := normalize(3)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEq(a, b) {
		t.Fatalf("%v != %v", a, b)
	}
	if _, err := normalize(map[any]any{1: 2}); err == nil {
		t.Fatal("a non-string-keyed map should not normalize")
	}
}

func TestOutputFormats(t *testing.T) {
	rep := casesRun(t, map[string]string{"good.yaml": goodSuite, "bad.yaml": hdr + "  - name: c\n    identity: {user: dev0@acme.example}\n    expect: {ring: ring1-canary}\n"})
	var txt bytes.Buffer
	rep.Text(&txt, Painter{})
	for _, want := range []string{"PASS  validate", "FAIL  cases      s/c", `ring: want "ring1-canary"`, "passed", "failed", "next steps:", "`halo whoami"} {
		if !strings.Contains(txt.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, txt.String())
		}
	}
	var js bytes.Buffer
	if err := json.NewEncoder(&js).Encode(rep); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back["ok"] != false || len(back["next_steps"].([]any)) == 0 {
		t.Fatalf("json: %v %s", err, js.String())
	}
	var x bytes.Buffer
	if err := rep.JUnit(&x); err != nil {
		t.Fatal(err)
	}
	var ju junitSuites
	if err := xml.Unmarshal(x.Bytes(), &ju); err != nil {
		t.Fatalf("junit is not XML: %v\n%s", err, x.String())
	}
	if ju.Tests != len(rep.Results) || ju.Failures != rep.Failed || ju.Failures != 1 {
		t.Fatalf("junit totals %d/%d vs report %d/%d", ju.Tests, ju.Failures, len(rep.Results), rep.Failed)
	}
	var failed *junitCase
	for _, s := range ju.Suites {
		for i, c := range s.Cases {
			if c.Failure != nil {
				failed = &s.Cases[i]
			}
		}
	}
	if failed == nil || failed.Name != "s/c" || failed.ClassName != "halo.test.cases" || !strings.Contains(failed.Failure.Body, "ring1-canary") {
		t.Fatalf("junit failure: %+v", failed)
	}
}
