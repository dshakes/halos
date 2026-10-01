package yamledit

import (
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

func TestSetPath(t *testing.T) {
	src := `# keep me
apiVersion: halos.dev/v1alpha1
kind: Experiment
name: e # trailing
status: draft
variants:
  - name: control
    weight: 95 # control share
    control: true
  - name: "t"
    weight: 5
  - {name: f, weight: 7, control: false}
gateway:
  models:
    opus: {upstream: a, model: "m1"}
`
	tests := []struct {
		name string
		path []string
		raw  string
		want string // substring of the result
		err  string
	}{
		{name: "number in a sequence item by name", path: []string{"variants", "name=t", "weight"}, raw: "25", want: "  - name: \"t\"\n    weight: 25\n"},
		{name: "keeps trailing comment", path: []string{"variants", "name=control", "weight"}, raw: "75", want: "weight: 75 # control share"},
		{name: "plain scalar in a flow mapping", path: []string{"variants", "name=f", "weight"}, raw: "70", want: "{name: f, weight: 70, control: false}"},
		{name: "flow mapping, quoted", path: []string{"gateway", "models", "opus", "model"}, raw: Quote("m2", 0), want: `{upstream: a, model: m2}`},
		{name: "insert missing top-level key", path: []string{"sampleRate"}, raw: "0.1", want: "name: e # trailing\nsampleRate: 0.1\nstatus"},
		{name: "replace top-level", path: []string{"status"}, raw: "running", want: "status: running\n"},
		{name: "missing nested key", path: []string{"variants", "name=nope", "weight"}, raw: "1", err: "not found"},
		{name: "not a scalar", path: []string{"variants"}, raw: "1", err: "not an inline scalar"},
		{name: "raw must be a scalar", path: []string{"status"}, raw: "a: b", err: "not an inline scalar"},
		{name: "raw single line", path: []string{"status"}, raw: "a\nb", err: "not an inline scalar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte(src), policy.KindExperiment, "e")
			if err != nil || m == nil {
				t.Fatalf("parse: %v", err)
			}
			out, err := (&Doc{Path: "x.yaml", Data: []byte(src), Mapping: m}).SetPath(tc.path, tc.raw)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), tc.want) || !strings.HasPrefix(string(out), "# keep me\n") {
				t.Fatalf("got:\n%s\nwant substring %q", out, tc.want)
			}
		})
	}
}
