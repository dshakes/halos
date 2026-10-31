package mcpserver

import (
	"runtime"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/onboard"
)

// extraRequired are fields a tool needs that its Go input type leaves
// optional (so the shared embedded struct stays reusable): onboard_company
// needs only an org; everything else has a documented default.
var extraRequired = map[string][]string{"onboard_company": {"org"}}

// argExamples are complete, valid argument sets for tools whose required
// fields have no value derivable from the policy. They are shown in argument
// errors and as next-step args.
var argExamples = map[string]map[string]any{
	"onboard_company": {"org": "acme"},
	"init_policy":     {"org": "acme"},
	"verify_harness":  {"harness": "claude-code"},
	"whoami":          {"user": "alice@example.com"},
	"render_preview":  {"os": "linux"},
}

// fieldExamples are example values by field name, used where a tool-specific
// one is not known.
var fieldExamples = map[string]any{
	"org": "acme", "user": "alice@example.com", "os": "linux", "harness": "claude-code", "reason": "why this change, one sentence",
	"provider": "anthropic", "safety": "standard", "rollout": "standard", "dry_run": true, "gateway_kind": "halo-proxy",
	"issuer": "https://login.acme.example.com", "gateway": "https://ai.acme.example.com", "portal_url": "https://halos.acme.example.com",
	"registry": "ghcr.io/acme/halos-releases", "policy_repo": "https://github.com/acme/halos-policy.git",
	"tools": map[string]any{"claude-code": "2.1.280"}, "delivery": []any{"halod"}, "admin_groups": []any{"ai-platform"},
	"models": map[string]any{"default": "claude-sonnet-4-5"}, "client_id": "halos",
}

// fieldDefaults are documented defaults surfaced as JSON-schema `default`.
var fieldDefaults = map[string]map[string]any{
	"onboard_company": {"gateway_kind": "halo-proxy", "delivery": []any{"halod"}, "client_id": "halos", "provider": "anthropic",
		"safety": "standard", "rollout": "standard", "dry_run": true},
	"init_policy": {"org": "local", "safety": "standard", "rollout": "standard", "dry_run": true},
}

func fieldDefault(tool, field string) (any, bool) {
	if d, ok := fieldDefaults[tool][field]; ok {
		return d, true
	}
	if field == "dry_run" {
		return true, true
	}
	return nil, false
}

func fallbackVersion(name string) string { return onboard.FallbackTools[name] }

// names returns the policy's ring and experiment names (empty when the policy
// does not load).
func (s *srv) names() (rings, exps []string) {
	org, err := s.load()
	if err != nil {
		return nil, nil
	}
	for _, r := range org.Rings {
		rings = append(rings, r.Name)
	}
	for _, e := range org.Experiments {
		exps = append(exps, e.Name)
	}
	return rings, exps
}

func (s *srv) fieldExample(tool, field string, p *jsonschema.Schema) any {
	rings, exps := s.names()
	return s.fieldExampleWith(tool, field, p, rings, exps)
}

func (s *srv) fieldExampleWith(tool, field string, p *jsonschema.Schema, rings, exps []string) any {
	if v, ok := argExamples[tool][field]; ok {
		return v
	}
	switch {
	case field == "ring" && len(rings) > 0:
		return rings[0]
	case (field == "experiment" || field == "name" && strings.Contains(tool, "experiment")) && len(exps) > 0:
		return exps[0]
	case field == "os":
		return runtime.GOOS
	}
	if p != nil && len(p.Examples) > 0 {
		return p.Examples[0]
	}
	if v, ok := fieldExamples[field]; ok {
		return v
	}
	if field == "ring" {
		return "ring1-canary"
	}
	if p == nil {
		return nil
	}
	switch {
	case schemaIs(p, "boolean"):
		return true
	case schemaIs(p, "array"):
		return []any{}
	case schemaIs(p, "object"):
		return map[string]any{}
	case schemaIs(p, "integer"), schemaIs(p, "number"):
		return 1
	case schemaIs(p, "string"):
		return "<" + field + ">"
	}
	return nil
}

// allowed lists the values of an enum-like field: the policy's rings and
// experiments, the OSes, the harness names, or the `a | b | c` list in the
// field's description.
func (s *srv) allowed(tool, field string, p *jsonschema.Schema) []string {
	if p != nil && len(p.Enum) > 0 {
		var out []string
		for _, e := range p.Enum {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	rings, exps := s.names()
	switch {
	case field == "ring":
		return rings
	case field == "experiment" || field == "name" && strings.Contains(tool, "experiment"):
		return exps
	case field == "os":
		return []string{"darwin", "linux", "windows"}
	case field == "harness" && tool != "verify_harness":
		return harness.Names()
	}
	if p == nil {
		return nil
	}
	d, _, _ := strings.Cut(p.Description, "(")
	if !strings.Contains(d, " | ") {
		return nil
	}
	var out []string
	for _, tok := range strings.Split(d, " | ") {
		if tok = strings.TrimSpace(tok); tok != "" && !strings.ContainsAny(tok, " ,") {
			out = append(out, tok)
		}
	}
	return out
}

// exampleArgs is a complete valid argument set for tool: the required fields
// (and dry_run: true for write-capable tools) with example values.
func (s *srv) exampleArgs(tool string, sch *jsonschema.Schema) map[string]any {
	out := map[string]any{}
	if sch == nil {
		sch = s.cachedSchema(tool)
	}
	req := append([]string(nil), extraRequired[tool]...)
	if sch != nil {
		req = append(req, sch.Required...)
	}
	for _, f := range req {
		var p *jsonschema.Schema
		if sch != nil {
			p = sch.Properties[f]
		}
		if v := s.fieldExample(tool, f, p); v != nil {
			out[f] = v
		}
	}
	for f, v := range argExamples[tool] {
		out[f] = v
	}
	if sch != nil && sch.Properties["dry_run"] != nil {
		out["dry_run"] = true
	}
	return out
}

func (s *srv) cachedSchema(tool string) *jsonschema.Schema {
	s.mw.mu.Lock()
	defer s.mw.mu.Unlock()
	if t := s.mw.schemas[tool]; t != nil {
		return asSchema(t.InputSchema)
	}
	return nil
}

// firstRing is the ring the examples use.
func (s *srv) firstRing() string {
	if rings, _ := s.names(); len(rings) > 0 {
		return rings[0]
	}
	return "ring1-canary"
}

func isDryArgs(args map[string]any) bool {
	b, ok := args["dry_run"].(bool)
	return !ok || b
}

func asBool(v any) bool { b, _ := v.(bool); return b }

// flow is the standard next step list after tool succeeded: the onboarding
// chain (doctor -> detect_harnesses -> init_policy | onboard_company ->
// validate -> plan -> install) and, for every other tool, a way back to the
// state view. Handler-specific steps come first and are kept by the caller.
func (s *srv) flow(tool string, args, out map[string]any) []step {
	ring := s.firstRing()
	org, _ := args["org"].(string)
	if org == "" {
		org = "acme"
	}
	dry := isDryArgs(args)
	machine := step{Tool: "init_policy", Why: "my-machine path: preview the halos.yaml for this machine (writes nothing)", Args: map[string]any{"org": org, "dry_run": true}}
	company := step{Tool: "onboard_company", Why: "my-company path: preview the whole policy repo; only org is required, every other answer has a default echoed in `assumed`", Args: map[string]any{"org": org, "dry_run": true}}
	validate := step{Tool: "validate", Why: "check the policy in the policy dir"}
	plan := step{Tool: "plan", Why: "diff the release a ring would get; with no baseline everything shows as added", Args: map[string]any{"ring": ring}}
	switch tool {
	case "doctor":
		return []step{{Tool: "detect_harnesses", Why: "which AI CLIs are installed, which credential variables are set (never values)"}, machine}
	case "detect_harnesses":
		return []step{machine, company}
	case "init_policy":
		if dry {
			w := step{Tool: "init_policy", Why: "after the human says yes: write halos.yaml (needs a server started with --allow-writes)", Args: map[string]any{"org": org, "dry_run": false}}
			return []step{w, company, validate}
		}
		return []step{validate, plan, {Tool: "local_install", Why: "preview the managed config files for this machine", Args: map[string]any{"dry_run": true}}}
	case "onboard_company":
		st := []step{validate, plan}
		if dry {
			st = append([]step{{Tool: "onboard_company", Why: "after the human confirms the assumed values (replace the example.com placeholders): write the policy repo (needs --allow-writes)",
				Args: map[string]any{"org": org, "dry_run": false}}}, st...)
		}
		return st
	case "validate":
		if !asBool(out["ok"]) {
			return []step{{Tool: "validate", Why: "fix every severity=error issue in the named file, then run validate again"}, {Tool: "init_policy", Why: "or start from a generated halos.yaml", Args: map[string]any{"org": org, "dry_run": true}}}
		}
		return []step{plan, {Tool: "list_rings", Why: "the rings this policy defines"}}
	case "plan":
		return []step{{Tool: "render_preview", Why: "the exact config files the ring renders, per OS", Args: map[string]any{"ring": ring, "os": runtime.GOOS}},
			{Tool: "local_install", Why: "my-machine path: preview where the managed config lands (dry run)", Args: map[string]any{"dry_run": true}},
			{Tool: "status", Why: "overall state and the lifecycle's next gate"}}
	case "render_preview":
		return []step{{Tool: "harness_matrix", Why: "which settings each harness can honour"}, plan}
	case "list_rings":
		return []step{plan, {Tool: "list_experiments", Why: "experiments targeting these rings"}}
	case "whoami":
		return []step{{Tool: "list_rings", Why: "the rings this policy defines"}, plan}
	case "local_install":
		return []step{{Tool: "local_proxy", Why: "write a loopback halo-proxy config (dry run first) and get its start command", Args: map[string]any{"dry_run": true}}, {Tool: "verify_harness", Why: "prove one CLI works end to end (dry run shows the command)", Args: map[string]any{"harness": "claude-code", "dry_run": true}}}
	case "local_proxy":
		return []step{{Tool: "verify_harness", Why: "prove one CLI works through the proxy (dry run shows the command)", Args: map[string]any{"harness": "claude-code", "dry_run": true}}}
	case "status":
		return []step{{Tool: "doctor", Why: "check the machine and the policy repo; each problem carries its fix"}, validate, plan}
	case "verify_harness":
		return []step{{Tool: "status", Why: "overall state; the machine is onboarded when verify passes"}, plan}
	}
	return []step{{Tool: "status", Why: "overall state, what this server can do, and the lifecycle's next gate"}}
}
