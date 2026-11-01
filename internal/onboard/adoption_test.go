package onboard

import (
	"context"
	"strings"
	"testing"
)

func TestSuggestToolsOmitsVersionsPolicyCannotPin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hs       []Harness
		want     map[string]string
		wantWarn string // substring; "" = no warning
	}{
		{"semver", []Harness{{Name: "claude-code", Installed: true, Version: "2.1.280"}}, map[string]string{"claude-code": "2.1.280"}, ""},
		{"prerelease", []Harness{{Name: "codex", Installed: true, Version: "0.99.0-beta.1"}}, map[string]string{"codex": "0.99.0-beta.1"}, ""},
		{"cursor date version", []Harness{{Name: "cursor-agent", Installed: true, Version: "2026.04.17-787b533"}}, map[string]string{}, "cursor-agent 2026.04.17-787b533"},
		{"mixed", []Harness{
			{Name: "claude-code", Installed: true, Version: "2.1.280"},
			{Name: "cursor-agent", Installed: true, Version: "2026.04.17-787b533"},
		}, map[string]string{"claude-code": "2.1.280"}, "cursor-agent@<x.y.z>"},
		{"not installed", []Harness{{Name: "cursor-agent", Version: "2026.04.17-787b533"}}, map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, warns := SuggestTools(tc.hs)
			if len(got) != len(tc.want) {
				t.Fatalf("tools = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("tools = %v, want %v", got, tc.want)
				}
			}
			if (tc.wantWarn == "") != (len(warns) == 0) || (tc.wantWarn != "" && !strings.Contains(strings.Join(warns, "\n"), tc.wantWarn)) {
				t.Fatalf("warnings = %q, want one containing %q", warns, tc.wantWarn)
			}
		})
	}
}

func TestLocalWithAutodetectedCursorVersionValidates(t *testing.T) {
	e := fake("", nil)
	lp := e.LookPath
	e.LookPath = func(b string) (string, error) {
		if b == "cursor-agent" {
			return "/usr/bin/cursor-agent", nil
		}
		return lp(b)
	}
	run := e.Run
	e.Run = func(ctx context.Context, p string, args ...string) ([]byte, error) {
		if strings.HasSuffix(p, "cursor-agent") {
			return []byte("2026.04.17-787b533\n"), nil
		}
		return run(ctx, p, args...)
	}
	tools, warns := AutoTools(Detect(context.Background(), e))
	if tools["cursor-agent"] != "" || tools["claude-code"] != "2.1.280" || len(warns) != 1 {
		t.Fatalf("tools = %v, warnings = %q", tools, warns)
	}
	in := initOpts()
	in.Tools = tools
	r, err := Local(LocalOptions{Dir: t.TempDir(), Init: in, GOOS: "linux", Warnings: warns})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid || len(r.Issues) != 0 || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "cursor-agent") {
		t.Fatalf("valid=%v issues=%q warnings=%q", r.Valid, r.Issues, r.Warnings)
	}
}

func TestCompanyGitignoreKeepsSecretsOut(t *testing.T) {
	files, err := Company(companyOpts())
	if err != nil {
		t.Fatal(err)
	}
	gi := string(files[".gitignore"])
	for _, want := range []string{"*.key", "*.token", ".halos/local/"} {
		if !strings.Contains(gi, want) {
			t.Errorf(".gitignore lacks %q:\n%s", want, gi)
		}
	}
}

func TestCompanyReadmeSteps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*CompanyOptions)
		want   []string
		not    []string
	}{
		{"git steps", func(*CompanyOptions) {}, []string{
			"git init -b main", "git add -A", "git remote add origin https://github.com/acme/halos-policy.git", "git push -u origin main",
		}, []string{"Review and merge this repo's PR"}},
		{"helm chart is not on OCI", func(*CompanyOptions) {}, []string{"from a Halos checkout", "not published to an OCI registry"}, []string{"oci://ghcr.io"}},
		{"every ring is published (standard)", func(*CompanyOptions) {}, []string{
			"--ring ring0-team --release-version 0.1.0", "--ring ring1-canary --release-version 0.1.1", "--ring ring2-early --release-version 0.1.2", "--ring ring3-ga --release-version 0.1.3",
		}, nil},
		{"every ring is published (fast)", func(c *CompanyOptions) { c.Init.Rollout = "fast" }, []string{"--release-version 0.1.0", "--release-version 0.1.1"}, []string{"--release-version 0.1.2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := companyOpts()
			tc.mutate(&o)
			files, err := Company(o)
			if err != nil {
				t.Fatal(err)
			}
			rd := string(files["README.md"])
			for _, w := range tc.want {
				if !strings.Contains(rd, w) {
					t.Errorf("README lacks %q:\n%s", w, rd)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(rd, w) {
					t.Errorf("README contains %q", w)
				}
			}
		})
	}
}

func TestLocalInvalidPolicyGivesActionableHint(t *testing.T) {
	in := initOpts()
	in.Tools = map[string]string{"claude-code": "latest"}
	r, err := Local(LocalOptions{Dir: t.TempDir(), Init: in, GOOS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Valid || len(r.Issues) == 0 || !strings.Contains(strings.Join(r.Next, "\n"), "--tools name@x.y.z") {
		t.Fatalf("valid=%v issues=%q next=%q", r.Valid, r.Issues, r.Next)
	}
}
