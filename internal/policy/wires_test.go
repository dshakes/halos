package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wireIssues(t *testing.T, files map[string]string) []Issue {
	t.Helper()
	org, err := Load(writeRepo(t, files))
	if err != nil {
		t.Fatal(err)
	}
	var out []Issue
	for _, i := range org.Validate() {
		if strings.Contains(i.Message, " speaks ") || strings.Contains(i.Path, ".serves") {
			out = append(out, i)
		}
	}
	return out
}

func TestGuardHarnessWire(t *testing.T) {
	simple := func(tools, models string) map[string]string {
		return map[string]string{RootFile: hdr + "kind: Halos\norg: acme\ngateway: https://ai.acme.example\nprovider: anthropic\n" +
			"tools: " + tools + "\nmodels: " + models + "\n"}
	}
	full := func(upstream, route string) map[string]string {
		return map[string]string{
			RootFile: hdr + "kind: Halos\norg: acme\n",
			"gateway.yaml": hdr + "kind: Gateway\nname: g\nbaseURL: https://ai.acme.example\nprotocols: {claude-code: anthropic-messages}\nauth: {}\n" +
				"upstreams:\n  orch: " + upstream + "\n  direct: {url: https://api.anthropic.com, kind: anthropic}\n  oai: {url: https://api.openai.com, kind: openai}\n" +
				"models:\n  sonnet: " + route + "\n",
			"profile.yaml": hdr + "kind: Profile\nname: p\nharnesses: {claude-code: {version: 2.1.280}}\nmodels: {default: sonnet}\ntelemetry: {enabled: true}\npermissions: {disableBypass: true}\n",
			"ring.yaml":    hdr + "kind: Ring\nname: ga\norder: 0\nprofile: p\nmembership: {default: true}\n",
		}
	}
	tests := []struct {
		name  string
		files map[string]string
		sev   Severity // "" = no wire issue
		want  []string
	}{
		{"codex on anthropic only", simple("{codex: 0.99.0}", "{default: claude-sonnet-4-5}"), SeverityError,
			[]string{"codex speaks openai-responses", `model "default" routes only to anthropic (anthropic)`,
				"tools: {codex: {version: 0.99.0, model: codex}} and models: {codex: openai/gpt-5-codex}", "harnesses.codex.model: codex"}},
		{"codex on its own openai model", simple("{codex: {version: 0.99.0, model: codex}}", "{default: claude-sonnet-4-5, codex: openai/gpt-5-codex}"), "", nil},
		{"gemini on anthropic only", simple("{gemini-cli: 0.34.0}", "{default: claude-sonnet-4-5}"), SeverityError,
			[]string{"gemini-cli speaks gemini", "models: {gemini-cli: gemini/gemini-2.5-pro}"}},
		{"failover reaching one capable target", simple("{codex: 0.99.0}", "{default: [claude-sonnet-4-5, openai/gpt-5]}"), "", nil},
		{"undeclared orchestrator warns", full("{url: https://orch.acme.example, kind: orchestrator}", "{upstream: orch, model: m}"), SeverityWarning,
			[]string{"cannot prove", "serves: [anthropic-messages]"}},
		{"declared orchestrator", full("{url: https://orch.acme.example, kind: orchestrator, serves: [anthropic-messages]}", "{upstream: orch, model: m}"), "", nil},
		{"orchestrator declaring another wire still warns", full("{url: https://orch.acme.example, kind: orchestrator, serves: [openai-responses]}", "{upstream: orch, model: m}"), SeverityWarning, nil},
		{"claude on openai only", full("{url: https://orch.acme.example, kind: orchestrator}", "{upstream: oai, model: gpt-5}"), SeverityError,
			[]string{"claude-code speaks anthropic-messages", "anthropic/claude-sonnet-4-5"}},
		{"serves on a known kind", full("{url: https://orch.acme.example, kind: anthropic, serves: [anthropic-messages]}", "{upstream: orch, model: m}"), SeverityError,
			[]string{"serves is only for kind orchestrator"}},
		{"unknown wire in serves", full("{url: https://orch.acme.example, kind: orchestrator, serves: [smoke-signals]}", "{upstream: orch, model: m}"), SeverityError,
			[]string{`"smoke-signals"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wireIssues(t, tt.files)
			if tt.sev == "" {
				if len(got) != 0 {
					t.Fatalf("want no wire issue, got %v", got)
				}
				return
			}
			if len(got) == 0 || got[0].Severity != tt.sev {
				t.Fatalf("want a %s, got %v", tt.sev, got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got[0].Message, w) {
					t.Errorf("message lacks %q:\n%s", w, got[0].Message)
				}
			}
		})
	}
}

// TestExamplesValidateClean: every shipped example has no errors and no warnings.
func TestExamplesValidateClean(t *testing.T) {
	dirs, err := filepath.Glob("../../examples/*/" + RootFile)
	if err != nil || len(dirs) < 2 {
		t.Fatalf("examples: %v %v", dirs, err)
	}
	for _, f := range dirs {
		dir := filepath.Dir(f)
		org, err := Load(dir)
		if err != nil {
			t.Errorf("%s: %v", dir, err)
			continue
		}
		if issues := org.Validate(); len(issues) != 0 {
			t.Errorf("%s: %v", dir, issues)
		}
	}
	if _, err := os.Stat("../../examples/simple"); err != nil {
		t.Fatal(err)
	}
}
