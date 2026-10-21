package policy

import (
	"os"
	"strings"
	"testing"
	"time"
)

func ghWorkloads() *Workloads {
	return &Workloads{
		Audience: "halos",
		Issuers:  []WorkloadIssuer{{Name: "github", URL: "https://token.actions.githubusercontent.com"}},
		Rules: []WorkloadRule{{
			Name: "release-bot", Issuer: "github",
			Match:   map[string]string{"repository": "acme/*", "ref": "refs/heads/main", "environment": "ai-*"},
			Subject: "workload:gh:{repository}", Groups: []string{"ci-agents"},
		}},
	}
}

func TestMatchWorkloadGlobs(t *testing.T) {
	w := ghWorkloads()
	base := func(kv ...string) map[string]any {
		c := map[string]any{"repository": "acme/app", "ref": "refs/heads/main", "environment": "ai-prod"}
		for i := 0; i+1 < len(kv); i += 2 {
			if kv[i+1] == "<nil>" {
				delete(c, kv[i])
				continue
			}
			c[kv[i]] = kv[i+1]
		}
		return c
	}
	for _, tc := range []struct {
		name   string
		issuer string
		claims map[string]any
		sub    string // "" = no match
	}{
		{"all match", "github", base(), "workload:gh:acme/app"},
		{"glob does not cross /", "github", base("repository", "acme/team/app"), ""},
		{"other owner", "github", base("repository", "evil/app"), ""},
		{"owner prefix is not a glob match", "github", base("repository", "acme-evil/app"), ""},
		{"branch mismatch", "github", base("ref", "refs/heads/feature"), ""},
		{"exact is exact", "github", base("ref", "refs/heads/main2"), ""},
		{"missing claim never matches", "github", base("environment", "<nil>"), ""},
		{"other issuer's tokens never match", "gitlab", base(), ""},
		{"non-string claim", "github", map[string]any{"repository": []any{"acme/app"}, "ref": "refs/heads/main", "environment": "ai-x"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, sub, ok := w.MatchWorkload(tc.issuer, tc.claims)
			if ok != (tc.sub != "") || sub != tc.sub {
				t.Fatalf("got %q ok=%v, want %q", sub, ok, tc.sub)
			}
		})
	}
}

func TestWorkloadSubjectExpansion(t *testing.T) {
	r := WorkloadRule{Name: "r", Issuer: "i", Match: map[string]string{"sub": "x"}}
	for _, tc := range []struct {
		subject string
		claims  map[string]any
		want    string
	}{
		{"workload:{sub}", map[string]any{"sub": "x"}, "workload:x"},
		{"workload:{a}:{b}", map[string]any{"sub": "x", "a": "1", "b": true}, "workload:1:true"},
		{"workload:{missing}", map[string]any{"sub": "x"}, ""},
		{"workload:{a}", map[string]any{"sub": "x", "a": "{sub}"}, ""}, // no nested expansion
		{"workload:{a}", map[string]any{"sub": "x", "a": ""}, ""},
		{"{a}", map[string]any{"sub": "x", "a": "workload:y"}, "workload:y"},
		{"{a}", map[string]any{"sub": "x", "a": "alice@acme.com"}, ""}, // never a human id
		{"workload:{a", map[string]any{"sub": "x", "a": "1"}, ""},
	} {
		r.Subject = tc.subject
		got, ok := r.expandSubject(tc.claims)
		if ok != (tc.want != "") || (ok && got != tc.want) {
			t.Errorf("%s with %v: got %q ok=%v, want %q", tc.subject, tc.claims, got, ok, tc.want)
		}
	}
}

func TestWorkloadTTL(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 15 * time.Minute, 60: time.Minute, 3600: time.Hour, 99999: time.Hour} {
		if got := (WorkloadRule{MaxTTLSeconds: in}).TTL(); got != want {
			t.Errorf("TTL(%d)=%s want %s", in, got, want)
		}
	}
}

func TestValidateWorkloads(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*Workloads)
		want string // substring of an error path+message; "" = no workloads error
	}{
		{"valid", func(*Workloads) {}, ""},
		{"loopback http issuer ok", func(w *Workloads) { w.Issuers[0].URL = "http://127.0.0.1:8080" }, ""},
		{"no audience", func(w *Workloads) { w.Audience = "" }, "workloads.audience"},
		{"http issuer", func(w *Workloads) { w.Issuers[0].URL = "http://token.actions.githubusercontent.com" }, "workloads.issuers[0].url"},
		{"duplicate issuer", func(w *Workloads) { w.Issuers = append(w.Issuers, w.Issuers[0]) }, "workloads.issuers[1]"},
		{"unknown issuer", func(w *Workloads) { w.Rules[0].Issuer = "gitlab" }, "workloads.rules[0].issuer"},
		{"no match", func(w *Workloads) { w.Rules[0].Match = nil }, "workloads.rules[0].match"},
		{"only wildcards", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository": "*/*", "ref": "*"} }, "workloads.rules[0].match"},
		{"bad glob", func(w *Workloads) { w.Rules[0].Match["ref"] = "refs/[" }, "workloads.rules[0].match.ref"},
		{"human subject", func(w *Workloads) { w.Rules[0].Subject = "alice@acme.com" }, "workloads.rules[0].subject"},
		{"bare prefix subject", func(w *Workloads) { w.Rules[0].Subject = "workload:" }, "workloads.rules[0].subject"},
		{"unbalanced subject", func(w *Workloads) { w.Rules[0].Subject = "workload:{repository" }, "workloads.rules[0].subject"},
		{"ttl over an hour", func(w *Workloads) { w.Rules[0].MaxTTLSeconds = 3601 }, "workloads.rules[0].maxTTLSeconds"},
		{"duplicate rule", func(w *Workloads) { w.Rules = append(w.Rules, w.Rules[0]) }, "workloads.rules[1].name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := ghWorkloads()
			tc.mod(w)
			v := &validator{org: &Org{Workloads: w}}
			v.workloads()
			var got []string
			for _, i := range v.issues {
				if i.Severity == SeverityError {
					got = append(got, i.Path+": "+i.Message)
				}
			}
			all := strings.Join(got, "\n")
			if tc.want == "" && len(got) > 0 || tc.want != "" && !strings.Contains(all, tc.want) {
				t.Fatalf("want %q, got:\n%s", tc.want, all)
			}
		})
	}
}

func TestSchemaWorkloads(t *testing.T) {
	s := compileSchemas(t)["halos.schema.json"]
	good := "kind: Halos\norg: acme\nworkloads:\n  audience: halos\n  issuers:\n    - {name: github, url: https://token.actions.githubusercontent.com}\n" +
		"  rules:\n    - name: ci\n      issuer: github\n      match: {repository_owner: acme}\n      subject: workload:gh:{repository}\n      groups: [ci-agents]\n      maxTTLSeconds: 900\n"
	if err := s.Validate(yamlDocs(t, []byte(good))[0]); err != nil {
		t.Fatalf("valid workloads rejected: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown field":   strings.Replace(good, "groups: [ci-agents]", "bogus: 1", 1),
		"human subject":   strings.Replace(good, "workload:gh:{repository}", "alice@acme.com", 1),
		"ttl over 1h":     strings.Replace(good, "maxTTLSeconds: 900", "maxTTLSeconds: 7200", 1),
		"no match":        strings.Replace(good, "      match: {repository_owner: acme}\n", "", 1),
		"missing issuers": strings.Replace(good, "  issuers:\n    - {name: github, url: https://token.actions.githubusercontent.com}\n", "", 1),
	} {
		if err := s.Validate(yamlDocs(t, []byte(bad))[0]); err == nil {
			t.Errorf("%s: schema accepted it", name)
		}
	}
}

// examples/ci-agents (also loaded by TestExamplesValidate) stays schema-valid
// and its rules match the providers' documented claims.
func TestCIAgentsExampleWorkloads(t *testing.T) {
	b, err := os.ReadFile("../../examples/ci-agents/halos.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSchemas(t)["halos.schema.json"].Validate(yamlDocs(t, b)[0]); err != nil {
		t.Fatalf("schema: %v", err)
	}
	org, err := Load("../../examples/ci-agents")
	if err != nil {
		t.Fatal(err)
	}
	if issues := org.Validate(); HasErrors(issues) || len(org.Workloads.Rules) < 4 {
		t.Fatalf("issues %v", issues)
	}
	_, sub, ok := org.Workloads.MatchWorkload("gitlab", map[string]any{"namespace_path": "acme", "ref_protected": "true", "project_path": "acme/api"})
	if !ok || sub != "workload:gl:acme/api" {
		t.Fatalf("gitlab rule: %q %v", sub, ok)
	}
}

// The root document's workloads reach the loaded Org.
func TestLoadWorkloads(t *testing.T) {
	dir := writeRepo(t, map[string]string{RootFile: "org: acme\nworkloads:\n  audience: halos\n  issuers: [{name: gl, url: https://gitlab.com}]\n" +
		"  rules: [{name: r, issuer: gl, match: {namespace_path: acme}, subject: 'workload:gl:{project_path}'}]\n"})
	org, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if org.Workloads == nil || org.Workloads.Rules[0].Subject != "workload:gl:{project_path}" || org.Workloads.AllowsExperiments() {
		t.Fatalf("workloads not loaded: %+v", org.Workloads)
	}
}
