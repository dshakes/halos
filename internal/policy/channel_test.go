package policy

import (
	"regexp"
	"strings"
	"testing"
)

var ociTag = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

func TestChannelName(t *testing.T) {
	long := strings.Repeat("e", 63)
	tests := []struct {
		name, ring, exp, variant, want string
	}{
		{"plain", "ring1-ga", "cli-upgrade", "treatment", "ring1-ga.x-cli-upgrade.treatment"},
		{"dotted names", "r0", "claude-2.1.3xx", "t.1", "r0.x-claude-2.1.3xx.t.1"},
		{"too long is hashed", strings.Repeat("r", 63), long, long, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChannelName(tt.ring, tt.exp, tt.variant)
			if tt.want != "" && got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
			if len(got) > MaxChannelLen || !ociTag.MatchString("ring-"+got+".pointer") {
				t.Fatalf("%q (len %d) does not fit the tag grammar", got, len(got))
			}
			if !strings.HasPrefix(got, tt.ring+".x-") {
				t.Fatalf("%q lost its ring prefix", got)
			}
		})
	}
	a, b := ChannelName("r", long, long+"x"), ChannelName("r", long, long)
	if a == b {
		t.Fatal("hashed channels collide")
	}
	if a != ChannelName("r", long, long+"x") {
		t.Fatal("not deterministic")
	}
}

// clientOrg adds a running client-axis experiment on r1 (profile base) whose
// treatment "next2" extends base and pins a newer CLI.
func clientOrg() *Org {
	o := validOrg()
	o.Profiles["next2"] = &Profile{Meta: Meta{Name: "next2"}, Extends: "base", Harnesses: map[string]HarnessSpec{"claude-code": {Version: "2.1.312"}}}
	o.Experiments = append(o.Experiments, &Experiment{
		Meta: Meta{Name: "cli"}, Type: ExperimentAB, Axis: AxisClient, Status: "running", Rings: []string{"r1"},
		Variants: []Variant{{Name: "control", Weight: 1, Control: true, Profile: "base"}, {Name: "treatment", Weight: 1, Profile: "next2"}},
		Metrics:  Metrics{Primary: MetricGoal{Metric: "halo.api.error_rate", Direction: "decrease"}},
		Stopping: Stopping{Method: "msprt", Alpha: 0.05},
	})
	return o
}

func TestClientExperimentsAndBaseline(t *testing.T) {
	o := clientOrg()
	if issues := o.Validate(); len(issues) != 0 {
		t.Fatalf("baseline should be clean: %v", issues)
	}
	if got := o.ClientExperiments("r1"); len(got) != 1 || got[0].Name != "cli" {
		t.Fatalf("ClientExperiments(r1) = %v", got)
	}
	if got := o.ClientExperiments("r0"); len(got) != 0 {
		t.Fatalf("ClientExperiments(r0) = %v", got)
	}
	o.Experiments[1].Status = "paused"
	if got := o.ClientExperiments("r1"); len(got) != 0 {
		t.Fatalf("paused experiment delivered: %v", got)
	}
}

func TestClientVariantGuardrails(t *testing.T) {
	tr := func(o *Org) *Profile { return o.Profiles["next2"] }
	// standalone: treatment no longer extends base (so it can drop base's rules).
	standalone := func(o *Org) *Profile {
		p := tr(o)
		p.Extends, p.Models = "", o.Profiles["base"].Models
		p.Permissions.DisableBypass, p.Telemetry.Enabled = true, true
		return p
	}
	tests := []struct {
		name     string
		mutate   func(*Org)
		wantPath string
		wantMsg  string
	}{
		{"unpinned version", func(o *Org) { tr(o).Harnesses["claude-code"] = HarnessSpec{Version: "latest"} }, "variants[1].profile", "exact semver"},
		{"widens allow", func(o *Org) { tr(o).Permissions.Allow = []string{"Bash(curl:*)"} }, "variants[1].profile", "permissions.allow widens the ring profile"},
		{"widens egress", func(o *Org) {
			o.Profiles["base"].Egress.AllowedDomains = []string{"gw.example.com"}
			tr(o).Egress.AllowedDomains = []string{"gw.example.com", "pastebin.com"}
		}, "variants[1].profile", "pastebin.com"},
		{"drops deny", func(o *Org) {
			o.Profiles["base"].Permissions.Deny = []string{"Bash(rm:*)"}
			standalone(o).Permissions.Deny = []string{"Read(.env)"}
		}, "variants[1].profile", "drops ring rule"},
		{"telemetry off", func(o *Org) { standalone(o).Telemetry.Enabled = false }, "variants[1].profile", "telemetry must be enabled"},
		{"bypass allowed", func(o *Org) { standalone(o).Permissions.DisableBypass = false }, "variants[1].profile", "disableBypass"},
		{"relaxes sandboxRequired", func(o *Org) {
			o.Profiles["base"].Permissions.SandboxRequired = true
			o.Profiles["base"].Permissions.Sandbox = "workspace-write"
			tr(o).Permissions.Sandbox = "off"
		}, "variants[1].profile", "relaxes"},
		{"adds mcp server", func(o *Org) { tr(o).MCP.Servers = []MCPServer{{Name: "x", URL: "https://x.example"}} }, "variants[1].profile", "mcp.servers adds"},
		{"auto mode", func(o *Org) { tr(o).Permissions.Mode = "auto" }, "variants[1].profile", `mode "auto"`},
		{"overlapping running client experiments", func(o *Org) {
			e := *o.Experiments[1]
			e.Name = "cli2"
			o.Experiments = append(o.Experiments, &e)
		}, "experiments[cli2].rings", "already enrolled"},
		{"channel collides with ring", func(o *Org) {
			o.Rings = append(o.Rings, &Ring{Meta: Meta{Name: "r1.x-cli.control"}, Order: 5, Profile: "base"})
		}, "variants[0].name", "collides with ring"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := clientOrg()
			tt.mutate(o)
			for _, is := range o.Validate() {
				if is.Severity == SeverityError && strings.Contains(is.Path, tt.wantPath) && strings.Contains(is.Message, tt.wantMsg) {
					return
				}
			}
			t.Fatalf("no error path~%q msg~%q in: %v", tt.wantPath, tt.wantMsg, o.Validate())
		})
	}
}
