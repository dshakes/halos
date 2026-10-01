package adapters

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite deploy/integrations from the templates")

const integrations = "../../../deploy/integrations"

func TestStaticFilesMatchTemplates(t *testing.T) {
	for name, rel := range Outputs {
		got, err := Render(name, Params{})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(integrations, rel)
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run: go test ./internal/gateway/adapters -update)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run: go test ./internal/gateway/adapters -update", rel)
		}
	}
}

func TestRenderedYAMLParsesAndParamsApply(t *testing.T) {
	p := Params{Host: "halo.internal", Port: 9000, TimeoutSeconds: 120}
	for _, name := range []string{"kong", "envoy", "apigw"} {
		b, err := Render(name, p)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := yaml.Unmarshal(b, &v); err != nil {
			t.Errorf("%s: invalid YAML: %v", name, err)
		}
	}
	b, _ := Render("nginx", p)
	if !strings.Contains(string(b), "server halo.internal:9000;") || !strings.Contains(string(b), "proxy_read_timeout 120s;") {
		t.Errorf("nginx params not applied:\n%s", b)
	}
	if _, err := Render("nope", p); err == nil {
		t.Error("unknown adapter must error")
	}
}
