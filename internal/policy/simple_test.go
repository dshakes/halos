package policy

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var updateSimple = flag.Bool("update-simple", false, "rewrite testdata/simple/*.golden.yaml")

const simpleExample = "../../examples/simple"

func errorsOf(issues []Issue) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Severity == SeverityError {
			out = append(out, i)
		}
	}
	return out
}

// TestSimpleExpandGolden pins what each preset expands to, and checks every
// expansion loads and validates with no errors.
func TestSimpleExpandGolden(t *testing.T) {
	cases := map[string]string{
		"standard": "", // examples/simple/halos.yaml
		"strict-careful-bedrock": hdr + "kind: Halos\norg: bank\ntools: {claude-code: 2.1.280}\n" +
			"provider: {name: bedrock, region: eu-west-1}\n" +
			"models:\n  default: [eu.anthropic.claude-sonnet-4-5-20250929-v1:0, anthropic/claude-sonnet-4-5]\n  strong: eu.anthropic.claude-opus-4-1-20250805-v1:0\n" +
			"gateway: https://ai.bank.example\ntelemetry: https://otel.bank.example:4318\nteam: [ai-platform, alice@bank.example]\n" +
			"safety: strict\nrollout: careful\n",
		"relaxed-fast-multi": hdr + "kind: Halos\norg: startup\ntools: {claude-code: 2.1.280, codex: {version: 0.58.0, model: codex}, gemini-cli: {version: 0.12.0, model: gemini}}\n" +
			"provider: multi\nmodels: {default: anthropic/claude-sonnet-4-5, codex: openai/gpt-5-codex, gemini: gemini/gemini-2.5-pro}\n" +
			"gateway: https://ai.startup.example\nsafety: relaxed\nrollout: fast\n",
		"vertex": hdr + "kind: Halos\norg: gco\ntools: {claude-code: 2.1.280}\n" +
			"provider: {name: vertex, project: gco-ai, region: us-east5}\nmodels: {default: claude-sonnet-4-5@20250929}\ngateway: https://ai.gco.example\n",
		// A company's own API gateway (Kong -> auth -> orchestrator -> Bedrock) that Halos does not run.
		"external-bedrock": hdr + "kind: Halos\norg: corp\ntools: {claude-code: 2.1.280}\n" +
			"provider: {name: bedrock, region: us-east-1}\nmodels: {default: us.anthropic.claude-sonnet-4-5-20250929-v1:0}\n" +
			"gateway: https://ai-gw.corp.example\ngatewayEngine: external\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := simpleExample
			if src != "" {
				dir = writeRepo(t, map[string]string{RootFile: src})
			}
			root, err := ReadRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			gen, err := root.Expand()
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			enc := yaml.NewEncoder(&b)
			enc.SetIndent(2)
			for _, v := range []any{gen.Gateway, gen.Profiles[SimpleProfile]} {
				if err := enc.Encode(v); err != nil {
					t.Fatal(err)
				}
			}
			for _, r := range gen.Rings {
				if err := enc.Encode(r); err != nil {
					t.Fatal(err)
				}
			}
			_ = enc.Close()
			golden := filepath.Join("testdata", "simple", name+".golden.yaml")
			if *updateSimple {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/policy -run TestSimpleExpandGolden -update-simple)", err)
			}
			if got := b.String(); got != string(want) {
				t.Errorf("expansion changed (rerun with -update-simple if intended):\n%s", got)
			}
			again, _ := root.Expand() // deterministic
			var b2 bytes.Buffer
			enc2 := yaml.NewEncoder(&b2)
			enc2.SetIndent(2)
			_ = enc2.Encode(again.Gateway)
			if !strings.HasPrefix(b.String(), b2.String()) {
				t.Error("Expand is not deterministic")
			}
			org, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if errs := errorsOf(org.Validate()); len(errs) > 0 {
				t.Fatalf("expansion does not validate: %v", errs)
			}
		})
	}
}

// TestSimpleSafetyNeverBypasses: every preset disables bypass, and the
// guardrails still reject an overlay or override that tries to bypass.
func TestSimpleSafetyNeverBypasses(t *testing.T) {
	for _, s := range []string{"", SafetyStrict, SafetyStandard, SafetyRelaxed} {
		p, _, err := SafetyPreset(s)
		if err != nil {
			t.Fatal(err)
		}
		if !p.DisableBypass || p.Mode == "bypassPermissions" || len(p.Deny) == 0 {
			t.Errorf("safety %q: %+v", s, p)
		}
	}
	root := hdr + "kind: Halos\norg: x\ntools: {claude-code: 2.1.280}\nprovider: anthropic\nmodels: {default: claude-sonnet-4-5}\ngateway: https://ai.x.example\nsafety: relaxed\n"
	for name, overlay := range map[string]string{
		"mode":     hdr + "kind: Profile\nname: default\npermissions: {mode: bypassPermissions}\n",
		"override": hdr + "kind: Profile\nname: default\nharnesses:\n  claude-code:\n    version: 2.1.280\n    overrides:\n      permissions: {defaultMode: bypassPermissions}\n",
	} {
		t.Run(name, func(t *testing.T) {
			org, err := Load(writeRepo(t, map[string]string{RootFile: root, "profiles/default.yaml": overlay}))
			if err != nil {
				t.Fatal(err)
			}
			if len(errorsOf(org.Validate())) == 0 {
				t.Fatal("bypassPermissions through a simple-mode overlay validated")
			}
		})
	}
}

func TestSimpleLoadErrors(t *testing.T) {
	base := "kind: Halos\norg: x\ntools: {claude-code: 2.1.280}\ngateway: https://ai.x.example\n"
	tests := []struct{ name, extra, want string }{
		{"unknown safety", "provider: anthropic\nmodels: {default: m}\nsafety: yolo\n", `safety "yolo"`},
		{"unknown rollout", "provider: anthropic\nmodels: {default: m}\nrollout: yolo\n", `rollout "yolo"`},
		{"unknown provider", "provider: azure\nmodels: {default: m}\n", `provider "azure"`},
		{"vertex without project", "provider: vertex\nmodels: {default: m}\n", "needs a project"},
		{"no default alias", "provider: anthropic\nmodels: {strong: m}\n", `"default" alias is required`},
		{"multi needs prefix", "provider: multi\nmodels: {default: m}\n", "names no provider"},
		{"no provider", "models: {default: m}\n", "names no provider"},
		{"strict provider keys", "provider: {name: anthropic, regoin: x}\nmodels: {default: m}\n", "regoin"},
		{"strict root keys", "provider: anthropic\nmodels: {default: m}\nsaftey: strict\n", "saftey"}, //nolint:misspell // intentional typo: testing schema rejects it
		{"bad model shape", "provider: anthropic\nmodels: {default: {id: m}}\n", "list of ids"},
		{"tool model not an alias", "provider: anthropic\nmodels: {default: m}\ntools: {codex: {version: 0.99.0, model: gpt}}\n", `tools.codex.model: "gpt"`},
		{"strict tool keys", "provider: anthropic\nmodels: {default: m}\ntools: {codex: {version: 0.99.0, modle: m}}\n", "modle"}, //nolint:misspell // intentional typo: testing schema rejects it
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := base
			if strings.Contains(tt.extra, "tools:") {
				b = strings.Replace(b, "tools: {claude-code: 2.1.280}\n", "", 1)
			}
			_, err := Load(writeRepo(t, map[string]string{RootFile: hdr + b + tt.extra}))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestSimpleOverlay: explicit documents with generated names merge over the
// expansion; deny lists only grow; other documents add alongside.
func TestSimpleOverlay(t *testing.T) {
	root := hdr + "kind: Halos\norg: x\ntools: {claude-code: 2.1.280}\nprovider: anthropic\n" +
		"models: {default: claude-sonnet-4-5, strong: claude-opus-4-1}\ngateway: https://ai.x.example\n"
	org, err := Load(writeRepo(t, map[string]string{
		RootFile: root,
		"profiles/default.yaml": hdr + "kind: Profile\nname: default\npermissions:\n  mode: plan\n  deny: [Read(./private/**)]\n" +
			"mcp:\n  servers: [{name: docs, url: https://docs.x.example/mcp}]\n",
		"rings/ring3-ga.yaml": hdr + "kind: Ring\nname: ring3-ga\nrelease: sha256:" + strings.Repeat("a", 64) + "\n",
		"rings/extra.yaml":    hdr + "kind: Ring\nname: ring9-lab\norder: 9\nprofile: default\nmembership: {groups: [lab]}\n",
		"gateway.yaml": hdr + "kind: Gateway\nname: x-gateway\nmodels:\n  strong: {upstream: internal, model: opus-internal}\n" +
			"upstreams:\n  internal: {url: https://llm.x.example, kind: orchestrator}\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := errorsOf(org.Validate()); len(errs) > 0 {
		t.Fatalf("overlay does not validate: %v", errs)
	}
	p := org.Profiles[SimpleProfile]
	if p.Permissions.Mode != "plan" || !p.Permissions.DisableBypass || p.Harnesses["claude-code"].Version != "2.1.280" {
		t.Errorf("profile overlay: %+v", p.Permissions)
	}
	if d := p.Permissions.Deny; len(d) != len(secretDenies)+1 || d[0] != secretDenies[0] || d[len(d)-1] != "Read(./private/**)" {
		t.Errorf("deny must keep the preset and add the overlay: %v", d)
	}
	if len(p.MCP.Servers) != 1 || !p.MCP.ManagedOnly {
		t.Errorf("mcp overlay: %+v", p.MCP)
	}
	ga, err := findRingT(org, "ring3-ga")
	if err != nil {
		t.Fatal(err)
	}
	if !ga.Membership.Default || ga.Profile != SimpleProfile || ga.Order != 3 || !strings.HasPrefix(ga.Release, "sha256:") {
		t.Errorf("ring stub overlay: %+v", ga)
	}
	if len(org.Rings) != 5 || org.Rings[4].Name != "ring9-lab" {
		t.Errorf("rings: %v", ringNamesT(org))
	}
	g := org.Gateway
	if g.BaseURL != "https://ai.x.example" || g.Models["strong"].Upstream != "internal" || g.Models["default"].Upstream != "anthropic" || len(g.Upstreams) != 2 {
		t.Errorf("gateway overlay: %+v", g)
	}
}

func findRingT(org *Org, name string) (*Ring, error) {
	for _, r := range org.Rings {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, os.ErrNotExist
}

func ringNamesT(org *Org) []string {
	var n []string
	for _, r := range org.Rings {
		n = append(n, r.Name)
	}
	return n
}

// TestFullModeUnaffected: a halos.yaml without simple keys expands nothing.
func TestFullModeUnaffected(t *testing.T) {
	root, err := ReadRoot(exampleDir)
	if err != nil {
		t.Fatal(err)
	}
	if root.Enabled() {
		t.Fatal("acme-corp has no simple-mode keys")
	}
}

func TestSimpleSchema(t *testing.T) {
	s := compileSchemas(t)["halos.schema.json"]
	b, err := os.ReadFile(filepath.Join(simpleExample, RootFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(yamlDocs(t, b)[0]); err != nil {
		t.Fatalf("examples/simple: %v", err)
	}
	for name, doc := range map[string]string{
		"bad safety":    "kind: Halos\norg: x\nsafety: yolo\n",
		"no default":    "kind: Halos\norg: x\nmodels: {strong: m}\n",
		"range pin":     "kind: Halos\norg: x\ntools: {claude-code: ^2.1.0}\n",
		"provider keys": "kind: Halos\norg: x\nprovider: {name: bedrock, regoin: x}\n",
		"tool keys":     "kind: Halos\norg: x\ntools: {codex: {version: 0.99.0, modle: m}}\n", //nolint:misspell // intentional typo: testing schema rejects it
		"tool no pin":   "kind: Halos\norg: x\ntools: {codex: {model: m}}\n",
	} {
		if err := s.Validate(yamlDocs(t, []byte(doc))[0]); err == nil {
			t.Errorf("%s: schema accepted it", name)
		}
	}
}

// A full policy behind an external gateway validates end to end (not just the
// gateway section): routes with no Halos upstream pass the harness-wire guard,
// and a profile may set ANTHROPIC_CUSTOM_HEADERS, which the renderer merges.
func TestExternalGatewayFullValidate(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		RootFile: hdr + "kind: Halos\norg: corp\ntools: {claude-code: 2.1.280}\nprovider: anthropic\nmodels: {default: claude-sonnet-4-5}\n" +
			"gateway: https://ai-gw.corp.example\ngatewayEngine: external\n",
		"gateway.yaml": hdr + "kind: Gateway\nname: corp-gateway\nbaseURL: https://ai-gw.corp.example\nengine: external\n" +
			"models: {default: {model: corp-sonnet}}\n",
		"profiles/default.yaml": hdr + "kind: Profile\nname: default\nenv: {ANTHROPIC_CUSTOM_HEADERS: \"x-tenant: corp\"}\n",
	})
	org, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if errs := errorsOf(org.Validate()); len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if m := org.Gateway.Models["default"]; m.Upstream != "" || m.Model != "corp-sonnet" {
		t.Fatalf("route = %+v", m)
	}
}

// Simple mode behind an external gateway: the company gateway translates, so a
// tool whose wire the provider does not speak still validates; and bad
// ANTHROPIC_CUSTOM_HEADERS are caught by validate, not only at render.
func TestExternalSimpleWireAndHeaders(t *testing.T) {
	root := hdr + "kind: Halos\norg: corp\ntools: {claude-code: 2.1.280, codex: 0.58.0}\nprovider: bedrock\n" +
		"models: {default: us.anthropic.claude-sonnet-4-5-20250929-v1:0, codex: corp-gpt}\n" +
		"gateway: https://ai-gw.corp.example\ngatewayEngine: external\n"
	org, err := Load(writeRepo(t, map[string]string{RootFile: root}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := errorsOf(org.Validate()); len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// Only the exact name is merged by the renderer, so another case is reserved.
	if org, err := Load(writeRepo(t, map[string]string{RootFile: root,
		"profiles/default.yaml": hdr + "kind: Profile\nname: default\nenv: {Anthropic_Custom_Headers: \"x-tenant: a\"}\n"})); err != nil {
		t.Fatal(err)
	} else if len(errorsOf(org.Validate())) == 0 {
		t.Error("mixed-case ANTHROPIC_CUSTOM_HEADERS validated")
	}
	for _, h := range []string{"X-Halo-Ring: ga", "x-ok: 1\rx-evil: 2"} {
		org, err := Load(writeRepo(t, map[string]string{RootFile: root,
			"profiles/default.yaml": hdr + "kind: Profile\nname: default\nenv: {ANTHROPIC_CUSTOM_HEADERS: " + strconv.Quote(h) + "}\n"}))
		if err != nil {
			t.Fatal(err)
		}
		if len(errorsOf(org.Validate())) == 0 {
			t.Errorf("header %q validated", h)
		}
	}
}

// Behind an external gateway Halos runs no upstream, so a provider's Halos-side
// requirements (a Vertex project) do not apply.
func TestExternalSimpleVertexNeedsNoProject(t *testing.T) {
	org, err := Load(writeRepo(t, map[string]string{RootFile: hdr + "kind: Halos\norg: corp\ntools: {claude-code: 2.1.280}\nprovider: vertex\n" +
		"models: {default: claude-sonnet-4-5@20250929}\ngateway: https://ai-gw.corp.example\ngatewayEngine: external\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if errs := errorsOf(org.Validate()); len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(org.Gateway.Upstreams) != 0 || org.Gateway.Models["default"].Model != "claude-sonnet-4-5@20250929" {
		t.Fatalf("gateway = %+v", org.Gateway)
	}
}
