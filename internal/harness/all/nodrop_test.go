package all_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

// Invariant 2, for every registered adapter and every profile field: removing
// one field from a fully populated profile must change what the adapter
// renders, what it warns, or make it refuse. If nothing changes, the field was
// silently dropped. Fields are addressed by the same dotted names
// hutil.Populated reports, resolved through json tags, so a new profile field
// is covered as soon as Populated knows it and the fixture sets it.
func TestNoSilentDrop(t *testing.T) {
	base, gw := hutiltest.Fixture()
	full := clone(t, base)
	full.Egress.AllowedDomains = append(full.Egress.AllowedDomains, "nodrop.example.com")
	full.Env = map[string]string{"NODROP": "1"}
	full.Instructions = "nodrop instructions"
	full.Login = policy.LoginAPI
	full.Telemetry.Protocol = "http/protobuf" // every adapter that renders telemetry speaks it (copilot has no grpc)
	e := &full.Extensions
	e.Marketplaces = []policy.Marketplace{{Source: policy.MarketplaceGitHub, Repo: "acme/plugins"}}
	e.BlockedMarketplaces = []policy.Marketplace{{Source: policy.MarketplaceGitHub, Repo: "evil/plugins"}}
	e.Plugins.Enabled, e.Plugins.Blocked = []string{"fmt@acme"}, []string{"bad@acme"}
	e.Skills.Deny, e.Skills.PluginOnly = []string{"nodrop-skill"}, true
	e.Subagents.Deny, e.Subagents.PluginOnly = []string{"nodrop-agent"}, true
	e.OutputStyle = "Explanatory"
	e.StatusLine.Command = "nodrop-status"
	e.Artifacts = []string{"nodrop-artifact"} // unresolved after clone: claude-code warns, the rest warn unsupported

	fields := hutil.Populated(full)
	for _, want := range []string{"permissions.deny", "mcp.denied", "hooks.items", "telemetry.enabled", "egress.allowedDomains", "env",
		"instructions", "login", "extensions.marketplaces", "extensions.plugins.enabled", "extensions.statusLine", "extensions.artifacts"} {
		if !slices.Contains(fields, want) {
			t.Fatalf("fixture does not populate %s (populated: %v)", want, fields)
		}
	}
	// implied: removing the field cannot change the output because another
	// field already forces the same result. Each entry is a reviewed reason,
	// not a way to make the test pass.
	implied := map[string]string{
		"claude-code/mcp.managedOnly":     "listing mcp.servers already renders allowManagedMcpServersOnly (the list is the allowlist)",
		"copilot-cli/mcp.managedOnly":     "listing mcp.servers already renders allowedMcpServers (the list is the allowlist)",
		"gemini-cli/mcp.managedOnly":      "listing mcp.servers already renders mcp.allowed (the list is the allowlist)",
		"codex/permissions.disableBypass": "with permissions.sandbox set, requirements.toml allowed_sandbox_modes already excludes danger-full-access; disableBypass adds that list only when sandbox is unset",
		"gemini-cli/login":                "with a gateway, auth is already pinned to gemini-api-key (login: api is the same result)",
	}
	for _, name := range harness.Names() {
		ad, _ := harness.Get(name)
		c := harness.Context{Gateway: gw, Ring: "ga", Release: "1.0.0", OS: harness.Linux}
		render := func(p *policy.Profile) (string, error) {
			files, warns, err := ad.Render(p, c)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			for _, f := range files {
				b.WriteString(f.Path + "\x00" + string(f.Data) + "\x00")
			}
			b.WriteString(strings.Join(warns, "\x00"))
			return b.String(), nil
		}
		ref, err := render(full)
		if err != nil {
			t.Fatalf("%s: full profile: %v", name, err)
		}
		for _, f := range fields {
			p := clone(t, full)
			if !zeroField(p, f) {
				t.Fatalf("cannot resolve profile field %q by json tags", f)
			}
			got, err := render(p)
			if _, ok := implied[name+"/"+f]; ok {
				continue
			}
			if err == nil && got == ref {
				t.Errorf("%s: profile field %q is silently dropped: removing it changes no file and no warning", name, f)
			}
		}
	}
}

func clone(t *testing.T, p *policy.Profile) *policy.Profile {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out policy.Profile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// zeroField zeroes the field at a dotted json path ("extensions.statusLine").
func zeroField(p *policy.Profile, path string) bool {
	v := reflect.ValueOf(p).Elem()
	for _, part := range strings.Split(path, ".") {
		found := false
		for i := 0; i < v.NumField(); i++ {
			if tag := strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0]; tag == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return false
		}
	}
	v.Set(reflect.Zero(v.Type()))
	return true
}
