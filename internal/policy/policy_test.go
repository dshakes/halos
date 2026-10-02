package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const exampleDir = "../../examples/acme-corp"

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const hdr = "apiVersion: halos.dev/v1\n"

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"no root", map[string]string{}, "halos.yaml"},
		{"root without org", map[string]string{"halos.yaml": "kind: Halos\n"}, "org is required"},
		{"root unknown field", map[string]string{"halos.yaml": "org: a\nbogus: 1\n"}, "line 2"},
		{"unknown field with line", map[string]string{
			"halos.yaml": "org: a\n",
			"p.yaml":     hdr + "kind: Profile\nname: p\nmodels:\n  default: x\n  bogus: 1\n",
		}, "line 6"},
		{"unknown kind", map[string]string{"halos.yaml": "org: a\n", "p.yaml": hdr + "kind: Widget\nname: w\n"}, `unknown kind "Widget"`},
		{"missing kind", map[string]string{"halos.yaml": "org: a\n", "p.yaml": hdr + "name: w\n"}, "no kind"},
		{"bad apiVersion", map[string]string{"halos.yaml": "org: a\n", "p.yaml": "apiVersion: v9\nkind: Profile\nname: p\n"}, "apiVersion"},
		{"missing name", map[string]string{"halos.yaml": "org: a\n", "p.yaml": hdr + "kind: Profile\n"}, "name is required"},
		{"duplicate profile across files", map[string]string{
			"halos.yaml": "org: a\n",
			"a.yaml":     hdr + "kind: Profile\nname: p\n",
			"b.yml":      hdr + "kind: Profile\nname: p\n",
		}, "duplicate profile"},
		{"two gateways in one multi-doc file", map[string]string{
			"halos.yaml": "org: a\n",
			"g.yaml":     hdr + "kind: Gateway\nname: g1\n---\n" + hdr + "kind: Gateway\nname: g2\n",
		}, "multiple Gateway"},
		{"malformed yaml", map[string]string{"halos.yaml": "org: a\n", "p.yaml": "kind: [\n"}, "p.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeRepo(t, tt.files))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadMultiDocAndOrdering(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		"halos.yaml": "org: acme\n",
		"rings/all.yaml": hdr + "kind: Ring\nname: b\norder: 2\nprofile: p\n---\n" +
			hdr + "kind: Ring\nname: a\norder: 1\nprofile: p\n---\n---\n",
		".hidden/x.yaml": "garbage: [",
		"notes.txt":      "ignored",
	})
	o, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "acme" || len(o.Rings) != 2 || o.Rings[0].Name != "a" || o.Rings[1].Name != "b" {
		t.Fatalf("unexpected org: %+v rings=%v", o, o.Rings)
	}
}

func orgWithProfiles(ps ...*Profile) *Org {
	o := &Org{Profiles: map[string]*Profile{}}
	for _, p := range ps {
		o.Profiles[p.Name] = p
	}
	return o
}

func TestResolveProfileMerge(t *testing.T) {
	base := &Profile{
		Meta:        Meta{Name: "base", Labels: map[string]string{"a": "1"}},
		Harnesses:   map[string]HarnessSpec{"claude-code": {Version: "1.0.0", Overrides: map[string]any{"x": 1, "y": 2}}},
		Models:      Models{Default: "sonnet", Allowed: []string{"sonnet", "opus"}, Enforce: true},
		Permissions: Permissions{Mode: "default", Deny: []string{"Read(.env)"}},
		Telemetry:   Telemetry{Enabled: true, Attributes: map[string]string{"k": "v"}},
		Env:         map[string]string{"A": "1"},
	}
	mid := &Profile{
		Meta: Meta{Name: "mid", Labels: map[string]string{"b": "2"}}, Extends: "base",
		Harnesses:   map[string]HarnessSpec{"claude-code": {Version: "2.0.0", Overrides: map[string]any{"y": 3}}, "codex": {Version: "0.1.0"}},
		Permissions: Permissions{Deny: []string{"Read(secrets)"}},
		Env:         map[string]string{"B": "2"},
	}
	leaf := &Profile{
		Meta: Meta{Name: "leaf"}, Extends: "mid",
		Models:    Models{Default: "opus"},
		Harnesses: map[string]HarnessSpec{"codex": {Version: "0.2.0"}},
	}
	o := orgWithProfiles(base, mid, leaf)
	got, err := o.ResolveProfile("leaf")
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		what      string
		got, want any
	}{
		{"name", got.Name, "leaf"},
		{"extends cleared", got.Extends, ""},
		{"scalar child wins", got.Models.Default, "opus"},
		{"scalar inherited", got.Permissions.Mode, "default"},
		{"bool inherited", got.Models.Enforce, true},
		{"slice inherited", strings.Join(got.Models.Allowed, ","), "sonnet,opus"},
		{"deny list unions down the chain", strings.Join(got.Permissions.Deny, ","), "Read(.env),Read(secrets)"},
		{"harness version child wins", got.Harnesses["claude-code"].Version, "2.0.0"},
		{"harness overrides merged x", got.Harnesses["claude-code"].Overrides["x"], 1},
		{"harness overrides child wins y", got.Harnesses["claude-code"].Overrides["y"], 3},
		{"harness added by mid, overridden by leaf", got.Harnesses["codex"].Version, "0.2.0"},
		{"map merge env", got.Env["A"] + got.Env["B"], "12"},
		{"labels merged", got.Labels["a"] + got.Labels["b"], "12"},
		{"nested map merge", got.Telemetry.Attributes["k"], "v"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.what, c.got, c.want)
		}
	}
	// mutating the result must not touch the source
	got.Env["A"] = "changed"
	got.Models.Allowed[0] = "changed"
	if base.Env["A"] != "1" || base.Models.Allowed[0] != "sonnet" {
		t.Error("ResolveProfile aliased source data")
	}
}

func TestResolveProfileErrors(t *testing.T) {
	tests := []struct {
		name string
		org  *Org
		ask  string
		want string
	}{
		{"not found", orgWithProfiles(), "nope", "not found"},
		{"missing parent", orgWithProfiles(&Profile{Meta: Meta{Name: "a"}, Extends: "zzz"}), "a", `unknown profile "zzz"`},
		{"self cycle", orgWithProfiles(&Profile{Meta: Meta{Name: "a"}, Extends: "a"}), "a", "cycle"},
		{"three cycle", orgWithProfiles(
			&Profile{Meta: Meta{Name: "a"}, Extends: "b"},
			&Profile{Meta: Meta{Name: "b"}, Extends: "c"},
			&Profile{Meta: Meta{Name: "c"}, Extends: "a"}), "a", "a -> b -> c -> a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.org.ResolveProfile(tt.ask)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestExampleAcmeCorp(t *testing.T) {
	o, err := Load(exampleDir)
	if err != nil {
		t.Fatal(err)
	}
	if issues := o.Validate(); len(issues) != 0 {
		t.Fatalf("example should be issue-free, got: %v", issues)
	}
	if o.Name != "acme-corp" || len(o.Rings) != 4 || len(o.Experiments) != 3 || len(o.Profiles) != 3 {
		t.Fatalf("unexpected shape: name=%s rings=%d exps=%d profiles=%d", o.Name, len(o.Rings), len(o.Experiments), len(o.Profiles))
	}
	p, err := o.ResolveProfile("engineering-next")
	if err != nil {
		t.Fatal(err)
	}
	if p.Harnesses["claude-code"].Version != "2.1.312" || !p.Telemetry.Enabled || !p.Permissions.DisableBypass {
		t.Fatalf("bad resolved profile: %+v", p)
	}
	if r := o.ResolveRing(Subject{ID: "x", Groups: []string{"ai-platform"}}); r.Name != "ring0-harness-team" {
		t.Fatalf("group ring = %s", r.Name)
	}
}

// validOrg builds a minimal org that validates cleanly; tests mutate it.
func validOrg() *Org {
	return &Org{
		Name: "t",
		Gateway: &Gateway{
			BaseURL:   "https://gw.example.com",
			Upstreams: map[string]Upstream{"up": {URL: "https://up.example.com", Kind: "orchestrator", Serves: []string{"anthropic-messages", "openai-responses", "gemini"}}},
			Models:    map[string]ModelRoute{"sonnet": {Upstream: "up", Model: "m1"}},
		},
		Profiles: map[string]*Profile{
			"base": {
				Meta:        Meta{Name: "base"},
				Harnesses:   map[string]HarnessSpec{"claude-code": {Version: "2.1.280"}},
				Models:      Models{Default: "sonnet", Allowed: []string{"sonnet"}, Enforce: true},
				Permissions: Permissions{DisableBypass: true},
				Telemetry:   Telemetry{Enabled: true},
			},
			"next": {Meta: Meta{Name: "next"}, Extends: "base", Harnesses: map[string]HarnessSpec{"claude-code": {Version: "2.1.300"}}},
		},
		Rings: []*Ring{
			{Meta: Meta{Name: "r0"}, Order: 0, Profile: "next", Membership: Membership{Percent: 10}},
			{Meta: Meta{Name: "r1"}, Order: 1, Profile: "base", Membership: Membership{Default: true}},
		},
		Experiments: []*Experiment{{
			Meta: Meta{Name: "e"}, Type: ExperimentCanary, Axis: AxisTraffic, Status: "running", Rings: []string{"r0"},
			Variants: []Variant{
				{Name: "c", Weight: 9, Control: true},
				{Name: "t", Weight: 1, Routes: map[string]ModelRoute{"sonnet": {Upstream: "up", Model: "m2"}}},
			},
			Metrics:  Metrics{Primary: MetricGoal{Metric: "halo.api.error_rate", Direction: "decrease"}},
			Stopping: Stopping{Method: "msprt", Alpha: 0.05},
		}},
	}
}

func TestValidateBaseline(t *testing.T) {
	if issues := validOrg().Validate(); len(issues) != 0 {
		t.Fatalf("baseline should be clean: %v", issues)
	}
}

func TestValidate(t *testing.T) {
	shadow := func(o *Org) *Experiment {
		e := o.Experiments[0]
		e.Type, e.SampleRate = ExperimentShadow, 0.1
		return e
	}
	tests := []struct {
		name     string
		mutate   func(*Org)
		wantPath string // substring of Path
		wantMsg  string // substring of Message
		wantSev  Severity
	}{
		{"no gateway", func(o *Org) { o.Gateway = nil }, "gateway", "no Gateway", SeverityError},
		{"harness model not a gateway alias", func(o *Org) {
			o.Profiles["base"].Models.Enforce = false
			o.Profiles["base"].Harnesses["codex"] = HarnessSpec{Version: "0.99.0", Model: "codex-default"}
		}, "harnesses.codex.model", "not a gateway.models alias", SeverityError},
		{"harness model outside enforced allowlist", func(o *Org) {
			o.Gateway.Models["codex-default"] = ModelRoute{Upstream: "up", Model: "m3"}
			o.Profiles["base"].Harnesses["codex"] = HarnessSpec{Version: "0.99.0", Model: "codex-default"}
		}, "harnesses.codex.model", "must be in models.allowed", SeverityError},
		{"gateway bad url", func(o *Org) { o.Gateway.BaseURL = "nope" }, "gateway.baseURL", "absolute", SeverityError},
		{"model route unknown upstream", func(o *Org) { o.Gateway.Models["sonnet"] = ModelRoute{Upstream: "zz", Model: "m"} }, "gateway.models.sonnet.upstream", "not defined", SeverityError},
		{"upstream bad kind", func(o *Org) { o.Gateway.Upstreams["up"] = Upstream{URL: "https://x.example", Kind: "wat"} }, "upstreams.up.kind", "invalid", SeverityError},
		{"duplicate ring name", func(o *Org) { o.Rings[1].Name = "r0" }, "rings[r0]", "duplicate ring", SeverityError},
		{"user in two rings", func(o *Org) {
			o.Rings[0].Membership.Users = []string{"a@x"}
			o.Rings[1].Membership.Users = []string{"a@x"}
		}, "membership.users", "already listed", SeverityError},
		{"duplicate ring order", func(o *Org) { o.Rings[1].Order = 0 }, ".order", "already used", SeverityError},
		{"no default ring", func(o *Org) { o.Rings[1].Membership.Default = false }, "rings", "exactly one", SeverityError},
		{"two default rings", func(o *Org) { o.Rings[0].Membership.Default = true; o.Rings[0].Membership.Percent = 0 }, "rings", "exactly one", SeverityError},
		{"percent over 100 cumulative", func(o *Org) {
			o.Rings[0].Membership.Percent = 60
			o.Rings = append(o.Rings, &Ring{Meta: Meta{Name: "r2"}, Order: 2, Profile: "base", Membership: Membership{Percent: 50}})
		}, "rings", "exceeds 100", SeverityError},
		{"percent negative", func(o *Org) { o.Rings[0].Membership.Percent = -1 }, "membership.percent", "out of range", SeverityError},
		{"default ring with percent", func(o *Org) { o.Rings[1].Membership.Percent = 5 }, "membership.percent", "remainder", SeverityError},
		{"ring profile missing", func(o *Org) { o.Rings[0].Profile = "ghost" }, "rings[r0].profile", "not found", SeverityError},
		{"ring profile no harnesses", func(o *Org) {
			o.Profiles["base"].Harnesses = nil
			delete(o.Profiles, "next")
			o.Rings[0].Profile = "base"
		}, "rings[r0].profile", "no harnesses", SeverityError},
		{"version range", func(o *Org) { o.Profiles["next"].Harnesses["claude-code"] = HarnessSpec{Version: "^2.1.0"} }, "version", "exact semver", SeverityError},
		{"version latest", func(o *Org) { o.Profiles["next"].Harnesses["claude-code"] = HarnessSpec{Version: "latest"} }, "version", "exact semver", SeverityError},
		{"version v prefix", func(o *Org) { o.Profiles["next"].Harnesses["claude-code"] = HarnessSpec{Version: "v2.1.0"} }, "version", "exact semver", SeverityError},
		{"version empty", func(o *Org) {
			o.Profiles["base"].Harnesses["claude-code"] = HarnessSpec{}
			o.Profiles["next"].Harnesses = nil
		}, "version", "exact semver", SeverityError},
		{"unknown harness", func(o *Org) { o.Profiles["base"].Harnesses["vim"] = HarnessSpec{Version: "1.0.0"} }, "harnesses.vim", "unknown harness", SeverityError},
		{"enforce default not allowed", func(o *Org) { o.Profiles["base"].Models.Allowed = []string{"other"} }, "models.default", "models.allowed", SeverityError},
		{"model not a gateway alias", func(o *Org) {
			o.Profiles["base"].Models.Default = "gpt"
			o.Profiles["base"].Models.Allowed = []string{"gpt"}
		}, "models", "not a gateway.models alias", SeverityError},
		{"bad permission mode", func(o *Org) { o.Profiles["base"].Permissions.Mode = "yolo" }, "permissions.mode", "invalid", SeverityError},
		{"sandboxRequired with sandbox off", func(o *Org) {
			o.Profiles["base"].Permissions.Sandbox, o.Profiles["base"].Permissions.SandboxRequired = "off", true
		}, "permissions.sandboxRequired", "contradicts", SeverityError},
		{"bad sandbox", func(o *Org) { o.Profiles["base"].Permissions.Sandbox = "x" }, "permissions.sandbox", "invalid", SeverityError},
		{"bad posture", func(o *Org) { o.Rings[0].Posture = "block" }, "posture", "invalid", SeverityError},
		{"bad versionGate", func(o *Org) { o.Rings[0].VersionGate = "on" }, "versionGate", "invalid", SeverityError},
		{"bad hook event", func(o *Org) { o.Profiles["base"].Hooks.Hooks = []Hook{{Event: "Nope", Command: "c"}} }, "hooks.items[0].event", "invalid", SeverityError},
		{"bad telemetry protocol", func(o *Org) { o.Profiles["base"].Telemetry.Protocol = "smtp" }, "telemetry.protocol", "invalid", SeverityError},
		{"extends cycle", func(o *Org) { o.Profiles["base"].Extends = "next" }, "extends", "cycle", SeverityError},
		{"duplicate experiment", func(o *Org) { o.Experiments = append(o.Experiments, o.Experiments[0]) }, "experiments[e]", "duplicate experiment", SeverityError},
		{"experiment bad type", func(o *Org) { o.Experiments[0].Type = "x" }, ".type", "invalid", SeverityError},
		{"experiment bad status", func(o *Org) { o.Experiments[0].Status = "x" }, ".status", "invalid", SeverityError},
		{"experiment unknown ring", func(o *Org) { o.Experiments[0].Rings = []string{"zz"} }, ".rings", "not defined", SeverityError},
		{"experiment no rings", func(o *Org) { o.Experiments[0].Rings = nil }, ".rings", "at least one", SeverityError},
		{"variant weight zero", func(o *Org) { o.Experiments[0].Variants[1].Weight = 0 }, "weight", "> 0", SeverityError},
		{"variant weight negative", func(o *Org) { o.Experiments[0].Variants[1].Weight = -1 }, "weight", "> 0", SeverityError},
		{"variant dup name", func(o *Org) { o.Experiments[0].Variants[1].Name = "c" }, ".name", "duplicate", SeverityError},
		{"no control", func(o *Org) { o.Experiments[0].Variants[0].Control = false }, ".variants", "exactly one control", SeverityError},
		{"two controls", func(o *Org) { o.Experiments[0].Variants[1].Control = true }, ".variants", "exactly one control", SeverityError},
		{"one variant", func(o *Org) { o.Experiments[0].Variants = o.Experiments[0].Variants[:1] }, ".variants", "at least 2", SeverityError},
		{"traffic route alias unknown", func(o *Org) {
			o.Experiments[0].Variants[1].Routes = map[string]ModelRoute{"opus": {Upstream: "up", Model: "m"}}
		}, "routes.opus", "not defined in gateway.models", SeverityError},
		{"traffic route upstream unknown", func(o *Org) { o.Experiments[0].Variants[1].Routes["sonnet"] = ModelRoute{Upstream: "zz", Model: "m"} }, "routes.sonnet.upstream", "not defined", SeverityError},
		{"traffic without routes", func(o *Org) { o.Experiments[0].Variants[1].Routes = nil }, ".variants", "with routes", SeverityError},
		{"traffic variant with profile", func(o *Org) { o.Experiments[0].Variants[1].Profile = "base" }, ".profile", "not profiles", SeverityError},
		{"client variant unknown profile", func(o *Org) {
			o.Experiments[0].Axis = AxisClient
			o.Experiments[0].Variants[1].Routes = nil
			o.Experiments[0].Variants[1].Profile = "zz"
			o.Experiments[0].Variants[0].Profile = "base"
		}, ".profile", "not defined", SeverityError},
		{"client variant with routes", func(o *Org) {
			o.Experiments[0].Axis = AxisClient
			o.Experiments[0].Variants[0].Profile = "base"
			o.Experiments[0].Variants[1].Profile = "next"
		}, ".routes", "not routes", SeverityError},
		{"shadow on client axis", func(o *Org) { e := shadow(o); e.Axis = AxisClient }, ".axis", "traffic axis", SeverityError},
		{"shadow rate zero", func(o *Org) { shadow(o).SampleRate = 0 }, "sampleRate", "(0,1]", SeverityError},
		{"shadow rate above one", func(o *Org) { shadow(o).SampleRate = 1.5 }, "sampleRate", "(0,1]", SeverityError},
		{"unknown metric", func(o *Org) { o.Experiments[0].Metrics.Primary.Metric = "halo.bogus" }, "metrics.primary.metric", "unknown metric", SeverityError},
		{"bad direction", func(o *Org) { o.Experiments[0].Metrics.Primary.Direction = "up" }, "direction", "invalid", SeverityError},
		{"guardrail negative regression", func(o *Org) {
			o.Experiments[0].Metrics.Guardrails = []MetricGoal{{Metric: "halo.api.error_rate", Direction: "decrease", MaxRegression: -1}}
		}, "maxRegression", ">= 0", SeverityError},
		{"bad stopping method", func(o *Org) { o.Experiments[0].Stopping.Method = "peek" }, "stopping.method", "invalid", SeverityError},
		{"bad alpha", func(o *Org) { o.Experiments[0].Stopping.Alpha = 1 }, "stopping.alpha", "(0,1)", SeverityError},

		// guardrails
		{"bypass mode", func(o *Org) { o.Profiles["base"].Permissions.Mode = "bypassPermissions" }, "permissions.mode", "bypassPermissions", SeverityError},
		{"auto on default ring warns", func(o *Org) { o.Profiles["base"].Permissions.Mode = "auto" }, "rings[r1]", "auto", SeverityWarning},
		{"telemetry off", func(o *Org) { o.Profiles["base"].Telemetry.Enabled = false }, "rings[r1].profile", "telemetry must be enabled", SeverityError},
		{"mcp http url", func(o *Org) { o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "s", URL: "http://x.example"}} }, "mcp.servers[0].url", "https", SeverityError},
		{"mcp both url and command", func(o *Org) {
			o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "s", URL: "https://x.example", Command: []string{"c"}}}
		}, "mcp.servers[0]", "exactly one", SeverityError},
		{"mcp neither", func(o *Org) { o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "s"}} }, "mcp.servers[0]", "exactly one", SeverityError},
		{"egress lacks gateway", func(o *Org) { o.Profiles["base"].Egress.AllowedDomains = []string{"github.com"} }, "egress.allowedDomains", "gw.example.com", SeverityError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validOrg()
			tt.mutate(o)
			issues := o.Validate()
			for _, is := range issues {
				if strings.Contains(is.Path, tt.wantPath) && strings.Contains(is.Message, tt.wantMsg) && is.Severity == tt.wantSev {
					return
				}
			}
			t.Fatalf("no %s issue with path~%q msg~%q in: %v", tt.wantSev, tt.wantPath, tt.wantMsg, issues)
		})
	}
}

func TestValidateGuardrailAllowances(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Org)
	}{
		{"mcp stdio command ok", func(o *Org) {
			o.Profiles["base"].MCP.Servers = []MCPServer{{Name: "s", Command: []string{"npx", "srv"}}}
		}},
		{"egress wildcard covers gateway", func(o *Org) { o.Profiles["base"].Egress.AllowedDomains = []string{"*.example.com"} }},
		{"egress with gateway host", func(o *Org) { o.Profiles["base"].Egress.AllowedDomains = []string{"gw.example.com", "github.com"} }},
		{"auto on non-default ring ok", func(o *Org) { o.Profiles["next"].Permissions.Mode = "auto" }},
		{"plan and acceptEdits ok", func(o *Org) {
			o.Profiles["base"].Permissions.Mode = "plan"
			o.Profiles["next"].Permissions.Mode = "acceptEdits"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validOrg()
			tt.mutate(o)
			if is := o.Validate(); len(is) != 0 {
				t.Fatalf("unexpected issues: %v", is)
			}
		})
	}
}

func TestHasErrorsAndRegistry(t *testing.T) {
	if HasErrors([]Issue{{Severity: SeverityWarning}}) || !HasErrors([]Issue{{Severity: SeverityError}}) {
		t.Fatal("HasErrors wrong")
	}
	for _, m := range []string{"halo.task.success", "halo.cost.usd_per_session", "halo.api.error_rate", "halo.edit.accept_rate", "halo.latency.p95_ms"} {
		if !KnownMetric(m) {
			t.Errorf("%s not registered", m)
		}
	}
	if KnownMetric("halo.nope") {
		t.Error("unknown metric accepted")
	}
}

func TestResolveProfileDenyListsAccumulate(t *testing.T) {
	o := &Org{Profiles: map[string]*Profile{
		"base":  {Meta: Meta{Name: "base"}, Permissions: Permissions{Deny: []string{"Read(.env)"}}, MCP: MCP{Denied: []string{"evil"}}},
		"child": {Meta: Meta{Name: "child"}, Extends: "base", Permissions: Permissions{Deny: []string{"Bash(rm:*)"}}},
	}}
	p, err := o.ResolveProfile("child")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Permissions.Deny, []string{"Read(.env)", "Bash(rm:*)"}) {
		t.Fatalf("deny = %v, want parent+child", p.Permissions.Deny)
	}
	if !slices.Equal(p.MCP.Denied, []string{"evil"}) {
		t.Fatalf("mcp denied = %v", p.MCP.Denied)
	}
}

// A per-harness model (harnesses.<h>.model) validates and survives extends.
func TestHarnessModelValidAndInherited(t *testing.T) {
	o := validOrg()
	o.Gateway.Models["codex-default"] = ModelRoute{Upstream: "up", Model: "m3"}
	b := o.Profiles["base"]
	b.Models.Allowed = append(b.Models.Allowed, "codex-default")
	b.Harnesses["codex"] = HarnessSpec{Version: "0.99.0", Model: "codex-default"}
	o.Profiles["next"].Harnesses["codex"] = HarnessSpec{Version: "0.100.0"}
	if is := o.Validate(); len(is) != 0 {
		t.Fatalf("issues: %v", is)
	}
	p, err := o.ResolveProfile("next")
	if err != nil {
		t.Fatal(err)
	}
	if h := p.Harnesses["codex"]; h.Model != "codex-default" || h.Version != "0.100.0" {
		t.Fatalf("resolved codex = %+v", h)
	}
}
