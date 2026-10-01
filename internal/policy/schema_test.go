package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const schemaDir = "../../schemas"

var kindSchema = map[string]string{
	"Profile": "profile.schema.json", "Ring": "ring.schema.json", "Experiment": "experiment.schema.json",
	"Gateway": "gateway.schema.json", "Halos": "halos.schema.json",
}

func compileSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	out := map[string]*jsonschema.Schema{}
	for _, f := range kindSchema {
		s, err := c.Compile(filepath.Join(schemaDir, f))
		if err != nil {
			t.Fatalf("compile %s: %v", f, err)
		}
		out[f] = s
	}
	return out
}

// yamlDocs decodes every document of a YAML file into JSON-compatible values.
func yamlDocs(t *testing.T, b []byte) []any {
	t.Helper()
	var docs []any
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var v any
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			return docs
		} else if err != nil {
			t.Fatal(err)
		}
		if v == nil {
			continue
		}
		j, err := json.Marshal(v) // normalise ints/maps to JSON types
		if err != nil {
			t.Fatal(err)
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(j))
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, inst)
	}
}

func TestExamplesMatchSchemas(t *testing.T) {
	schemas := compileSchemas(t)
	n := 0
	err := filepath.WalkDir(exampleDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".yml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, doc := range yamlDocs(t, b) {
			kind, _ := doc.(map[string]any)["kind"].(string)
			sf, ok := kindSchema[kind]
			if !ok {
				t.Errorf("%s doc %d: no schema for kind %q", p, i, kind)
				continue
			}
			if err := schemas[sf].Validate(doc); err != nil {
				t.Errorf("%s doc %d: %v", p, i, err)
			}
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("only %d documents validated", n)
	}
}

func TestSchemasRejectBadDocs(t *testing.T) {
	schemas := compileSchemas(t)
	tests := []struct{ name, kind, yaml string }{
		{"unknown field", "Ring", hdr + "kind: Ring\nname: r\norder: 0\nprofile: p\nmembership: {}\nbogus: 1\n"},
		{"ring missing profile", "Ring", hdr + "kind: Ring\nname: r\norder: 0\nmembership: {}\n"},
		{"percent over 100", "Ring", hdr + "kind: Ring\nname: r\norder: 0\nprofile: p\nmembership: {percent: 101}\n"},
		{"bad permission mode", "Profile", hdr + "kind: Profile\nname: p\npermissions: {mode: yolo}\n"},
		{"bad api version", "Profile", "apiVersion: v2\nkind: Profile\nname: p\n"},
		{"experiment bad type", "Experiment", hdr + "kind: Experiment\nname: e\ntype: zzz\naxis: client\nrings: [a]\nvariants: [{name: a, weight: 1}]\nmetrics: {primary: {metric: halo.task.success, direction: increase}}\nstopping: {method: msprt}\n"},
		{"zero weight", "Experiment", hdr + "kind: Experiment\nname: e\ntype: ab\naxis: client\nrings: [a]\nvariants: [{name: a, weight: 0}]\nmetrics: {primary: {metric: halo.task.success, direction: increase}}\nstopping: {method: msprt}\n"},
		{"root missing org", "Halos", "kind: Halos\n"},
		{"gateway missing upstreams", "Gateway", hdr + "kind: Gateway\nname: g\nbaseURL: https://x.example\nauth: {}\nmodels: {}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := yamlDocs(t, []byte(tt.yaml))
			if len(docs) != 1 {
				t.Fatalf("got %d docs", len(docs))
			}
			if err := schemas[kindSchema[tt.kind]].Validate(docs[0]); err == nil {
				t.Fatal("expected schema violation")
			} else if !strings.Contains(err.Error(), "jsonschema") {
				t.Fatalf("unexpected error type: %v", err)
			}
		})
	}
}
