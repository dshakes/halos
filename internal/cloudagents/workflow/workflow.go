// Package workflow renders the repository files of the workflow-configured
// cloud agents (ADR-0034): the Claude Code and Gemini CLI GitHub Actions and
// Copilot's copilot-setup-steps.yml, SHA-pinned and least-privilege, and
// checks every rendered file against the security invariants. It imports only
// policy, so release builds can carry its output.
package workflow

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
)

// Action pins: every `uses:` a rendered workflow emits is a full commit SHA
// (a tag can be moved; a SHA cannot). Checked against each repository's
// releases on 2026-10-27; bump deliberately, in one place.
var pins = map[string]struct{ sha, tag string }{
	"actions/checkout":                     {"3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"},
	"anthropics/claude-code-action":        {"d70510b174a1244958df0b03166a54912811f3e6", "v1.0.264"},
	"google-github-actions/run-gemini-cli": {"f77273f4c914e4bf38440cf36a0369cb64a37489", "v0.1.22"},
}

// Rendered workflow paths, relative to a repository root. Copilot's name is
// fixed by GitHub; the others are Halos-owned, so inventory can tell a
// governed run from anything else in the repository.
const (
	ClaudeWorkflow  = ".github/workflows/halos-claude.yml"
	GeminiWorkflow  = ".github/workflows/halos-gemini.yml"
	CopilotWorkflow = ".github/workflows/copilot-setup-steps.yml"
)

// File is one rendered repository file. Releases carry it signed, for review
// and for the PR that adds it; halod never writes it to a machine.
type File struct {
	Vendor string   `json:"vendor"`
	Path   string   `json:"path"`
	Data   []byte   `json:"-"`
	Repos  []string `json:"repos,omitempty"` // policy repo patterns it is for
}

// Render renders the repository files of every enabled workflow-configured
// vendor (claude, gemini, copilot), with a warning for each control it cannot
// render (invariant 2). Every file passes Check. The org must validate.
func Render(org *policy.Org) ([]File, []string, error) {
	c := org.CloudAgents
	if c == nil {
		return nil, nil, nil
	}
	var files []File
	var warns []string
	for _, name := range policy.CloudVendors {
		a := c.Vendor(name)
		if a == nil {
			continue
		}
		if !a.Enabled {
			switch name {
			case policy.CloudClaude, policy.CloudGemini:
				warns = append(warns, fmt.Sprintf("%s: disabled: no workflow rendered; delete %s from repositories that have it", name, workflowPath(name)))
			case policy.CloudCopilot:
				warns = append(warns, "copilot: disabled: set Copilot cloud agent repository access to no repositories in the organization's Copilot settings (no public write API)")
			}
			continue
		}
		var f *File
		var w []string
		switch name {
		case policy.CloudClaude:
			f, w = renderClaude(c, audience(org), a)
		case policy.CloudGemini:
			f, w = renderGemini(c, audience(org), a)
		case policy.CloudCopilot:
			f, w = renderCopilot(a)
		default:
			warns = append(warns, fmt.Sprintf("%s: configured in the vendor console, not in repositories; see `halo admin plan`", name))
			continue
		}
		f.Vendor, f.Repos = name, slices.Clone(a.Repos)
		if err := Check(*f); err != nil {
			return nil, nil, err
		}
		files = append(files, *f)
		warns = append(warns, w...)
	}
	return files, warns, nil
}

func workflowPath(vendor string) string {
	return map[string]string{policy.CloudClaude: ClaudeWorkflow, policy.CloudGemini: GeminiWorkflow, policy.CloudCopilot: CopilotWorkflow}[vendor]
}

func uses(action string) string {
	p := pins[action]
	return fmt.Sprintf("%s@%s # %s", action, p.sha, p.tag)
}

func header(vendor string, a *policy.CloudAgent) string {
	repos := "every repository"
	if len(a.Repos) > 0 {
		repos = strings.Join(a.Repos, ", ")
	}
	return fmt.Sprintf("# Rendered by Halos from cloudAgents.%s (ADR-0034). Do not edit: change policy and\n# run `halo cloud-agents render`. For: %s\n", vendor, repos)
}

func timeout(a *policy.CloudAgent, def int) int {
	if a.TimeoutMinutes > 0 {
		return a.TimeoutMinutes
	}
	return def
}

// Run scripts are constants: a policy value reaches a script only through a
// step's env (a double-quoted YAML scalar) and a quoted shell variable, never
// by interpolation, so no policy string can inject shell or YAML. Check
// refuses any run script that is not one of these.
const (
	installScript = `set -euo pipefail
curl -fsSLo "$RUNNER_TEMP/install.sh" "https://raw.githubusercontent.com/dshakes/halos/${HALO_VERSION}/install/install.sh"
sh "$RUNNER_TEMP/install.sh" --version "$HALO_VERSION" --prefix "$RUNNER_TEMP/halo"
`
	tokenScript = `set -euo pipefail
"$RUNNER_TEMP/halo/bin/halo" ci token --format github --audience "$HALO_AUDIENCE"
`
)

var runScripts = []string{installScript, tokenScript}

// indent prefixes every line of s with n spaces (a YAML literal block body).
func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n"+pad) + "\n"
}

// workloadSteps exchange the job's GitHub OIDC token for a short-lived Halos
// gateway credential (ADR-0023), exported to later steps through $GITHUB_ENV.
// env values are strconv.Quote'd: valid YAML double-quoted scalars.
func workloadSteps(c *policy.CloudAgents, audience string) string {
	return fmt.Sprintf(`      - name: Install halo
        env:
          HALO_VERSION: %s
        run: |
%s      - name: Halos workload credential (ADR-0023)
        env:
          HALO_SERVER: %s
          HALO_AUDIENCE: %s
        run: |
%s`, strconv.Quote(c.HaloVersion), indent(installScript, 10), strconv.Quote(c.Server), strconv.Quote(audience), indent(tokenScript, 10))
}

// commonWarns are the controls the workflow vendors cannot express.
func commonWarns(name string, a *policy.CloudAgent) []string {
	var w []string
	if a.Network != nil && name != policy.CloudCopilot {
		w = append(w, fmt.Sprintf("%s: network is not rendered: the GitHub-hosted runner has no egress setting; use a self-hosted runner behind an egress proxy", name))
	}
	if a.MaxConcurrent.PerUser > 0 || a.MaxConcurrent.PerGroup > 0 {
		w = append(w, fmt.Sprintf("%s: maxConcurrent is enforced by halo-server from webhooks (alert, or pause with onOverLimit: pause), not by the workflow", name))
	}
	if len(a.Repos) > 0 {
		w = append(w, fmt.Sprintf("%s: repos is enforced by where you commit %s and by inventory alerts; GitHub does not stop a copied workflow", name, workflowPath(name)))
	}
	return w
}

// audience is the aud the job's GitHub OIDC token must carry: the GitHub
// Actions issuer's own audience when it overrides workloads.audience
// (Workloads.AudienceFor), else workloads.audience, else "halos".
func audience(org *policy.Org) string {
	w := org.Workloads
	if w == nil {
		return "halos"
	}
	for _, is := range w.Issuers {
		if p, _ := is.TenantClaims(); p == policy.GitHubActionsProvider {
			if a := w.AudienceFor(is); a != "" {
				return a
			}
		}
	}
	if w.Audience != "" {
		return w.Audience
	}
	return "halos"
}

// renderClaude: the Claude Code GitHub Action on @claude mentions. The App
// token exchange needs id-token: write even without workload identity.
func renderClaude(c *policy.CloudAgents, aud string, a *policy.CloudAgent) (*File, []string) {
	var b strings.Builder
	b.WriteString(header(policy.CloudClaude, a))
	fmt.Fprintf(&b, `name: Claude Code (Halos)
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]
  pull_request_review:
    types: [submitted]
  issues:
    types: [opened, assigned]
permissions: {}
jobs:
  claude:
    if: >-
      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude')) ||
      (github.event_name == 'pull_request_review_comment' && contains(github.event.comment.body, '@claude')) ||
      (github.event_name == 'pull_request_review' && contains(github.event.review.body, '@claude')) ||
      (github.event_name == 'issues' && (contains(github.event.issue.body, '@claude') || contains(github.event.issue.title, '@claude')))
    runs-on: ubuntu-latest
    timeout-minutes: %d
    permissions:
      contents: write
      pull-requests: write
      issues: write
      id-token: write
    steps:
      - uses: %s
        with:
          fetch-depth: 1
          persist-credentials: false
`, timeout(a, 30), uses("actions/checkout"))
	key := "${{ secrets.ANTHROPIC_API_KEY }}"
	if a.Identity == policy.CloudIdentityWorkload {
		b.WriteString(workloadSteps(c, aud))
		key = "${{ env.HALO_GATEWAY_TOKEN }}" // ANTHROPIC_BASE_URL (the gateway) comes from $GITHUB_ENV
	}
	fmt.Fprintf(&b, `      - uses: %s
        with:
          anthropic_api_key: %s
          settings: |
            {"permissions": {"disableBypassPermissionsMode": "disable"}}
`, uses("anthropics/claude-code-action"), key)
	if len(a.Models) > 0 {
		fmt.Fprintf(&b, "          claude_args: --model %s\n", a.Models[0])
	}
	w := commonWarns(policy.CloudClaude, a)
	if len(a.Models) > 1 {
		w = append(w, "claude: the workflow runs models[0]; the other models are allowed for cloud sessions and checked on observed tasks")
	}
	w = append(w, "claude: cloud sessions (claude.ai) are console-configured: see `halo admin plan` (vendorAdmin.claude)")
	return &File{Path: ClaudeWorkflow, Data: []byte(b.String())}, w
}

// renderGemini: the Gemini CLI GitHub Action on @gemini-cli mentions from
// repository members, with the CLI version pinned and YOLO mode refused.
func renderGemini(c *policy.CloudAgents, aud string, a *policy.CloudAgent) (*File, []string) {
	var b strings.Builder
	b.WriteString(header(policy.CloudGemini, a))
	fmt.Fprintf(&b, `name: Gemini CLI (Halos)
on:
  issue_comment:
    types: [created]
  pull_request_review_comment:
    types: [created]
permissions: {}
jobs:
  gemini:
    if: >-
      contains(github.event.comment.body, '@gemini-cli') &&
      contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    timeout-minutes: %d
    permissions:
      contents: read
      issues: write
      pull-requests: write
      id-token: write
    steps:
      - uses: %s
        with:
          fetch-depth: 1
          persist-credentials: false
`, timeout(a, 30), uses("actions/checkout"))
	key := "${{ secrets.GEMINI_API_KEY }}"
	if a.Identity == policy.CloudIdentityWorkload {
		b.WriteString(workloadSteps(c, aud))
		key = "${{ env.GEMINI_API_KEY }}" // the gateway credential; GOOGLE_GEMINI_BASE_URL comes from $GITHUB_ENV
	}
	fmt.Fprintf(&b, `      - uses: %s
        with:
          gemini_api_key: %s
          prompt: ${{ github.event.comment.body }}
          settings: |
            {"security": {"disableYoloMode": true}}
`, uses("google-github-actions/run-gemini-cli"), key)
	if a.Version != "" {
		fmt.Fprintf(&b, "          gemini_cli_version: %s\n", a.Version)
	}
	if len(a.Models) > 0 {
		fmt.Fprintf(&b, "          gemini_model: %s\n", a.Models[0])
	}
	w := commonWarns(policy.CloudGemini, a)
	if a.Version == "" {
		w = append(w, "gemini: version unset: the action installs its default Gemini CLI; pin cloudAgents.gemini.version")
	}
	return &File{Path: GeminiWorkflow, Data: []byte(b.String())}, w
}

// renderCopilot: copilot-setup-steps.yml, the one repository file the
// Copilot cloud agent reads. Only steps, permissions, runs-on, services,
// snapshot and timeout-minutes (at most 59) are honored; Copilot gets its own
// token, so the job keeps contents: read.
func renderCopilot(a *policy.CloudAgent) (*File, []string) {
	var b strings.Builder
	b.WriteString(header(policy.CloudCopilot, a))
	fmt.Fprintf(&b, `name: Copilot Setup Steps
on:
  workflow_dispatch:
  push:
    paths: [%[1]s]
  pull_request:
    paths: [%[1]s]
permissions: {}
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    timeout-minutes: %[2]d
    permissions:
      contents: read
    steps:
      - uses: %[3]s
        with:
          persist-credentials: false
`, CopilotWorkflow, timeout(a, 59), uses("actions/checkout"))
	w := commonWarns(policy.CloudCopilot, a)
	if a.Network != nil {
		w = append(w, "copilot: network is the Internet access (firewall) setting: `halo admin plan` reads it per repository; GitHub publishes no write API, set it in the console")
	}
	if len(a.Models) > 0 {
		w = append(w, "copilot: models are an organization Copilot policy, not repository config; not rendered")
	}
	return &File{Path: CopilotWorkflow, Data: []byte(b.String())}, w
}

var (
	usesRe   = regexp.MustCompile(`^\s*-?\s*uses:\s*(\S+)`)
	pinnedRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
)

// Check asserts the security invariants on a rendered file by reading its
// text, not by trusting how it was produced: no permission-bypass token
// (invariant 1), no literal credential, every action pinned to a full commit
// SHA, a top-level `permissions: {}` (jobs grant their own, least privilege),
// no `${{ }}` expression inside a run script (script injection), valid YAML,
// and every run script one Halos renders verbatim (runScripts), so a policy
// value reaches a shell only through env (shell and YAML injection).
func Check(f File) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cloudagents %s %s: security invariant violated: %s", f.Vendor, f.Path, fmt.Sprintf(format, a...))
	}
	s := string(f.Data)
	if tok := policy.BypassToken(s); tok != "" {
		return fail("contains permission-bypass token %q (invariant 1)", tok)
	}
	if policy.HasTokenShape(s) {
		return fail("contains a literal credential; reference a secret or the workload credential")
	}
	lines := strings.Split(s, "\n")
	if !slices.Contains(lines, "permissions: {}") {
		return fail("no top-level `permissions: {}`")
	}
	if strings.Contains(s, "write-all") || strings.Contains(s, "read-all") {
		return fail("blanket permissions")
	}
	runIndent := -1
	for i, l := range lines {
		ind := len(l) - len(strings.TrimLeft(l, " "))
		if runIndent >= 0 && strings.TrimSpace(l) != "" && ind <= runIndent {
			runIndent = -1
		}
		if runIndent >= 0 && strings.Contains(l, "${{") {
			return fail("line %d: expression inside a run script; pass it through env", i+1)
		}
		t := strings.TrimSpace(l)
		key := ind // column of the mapping key: past a "- " list marker
		if rest, ok := strings.CutPrefix(t, "- "); ok {
			t, key = rest, ind+2
		}
		if strings.HasPrefix(t, "run:") {
			if strings.Contains(t, "${{") {
				return fail("line %d: expression inside a run script; pass it through env", i+1)
			}
			runIndent = key
		}
		if m := usesRe.FindStringSubmatch(l); m != nil && !pinnedRe.MatchString(m[1]) {
			return fail("line %d: %s is not pinned to a full commit SHA", i+1, m[1])
		}
	}
	var doc struct {
		Jobs map[string]struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(f.Data, &doc); err != nil {
		return fail("not a valid workflow: %v", err)
	}
	for name, j := range doc.Jobs {
		for i, st := range j.Steps {
			if r, ok := st["run"]; ok {
				if s, _ := r.(string); !slices.Contains(runScripts, s) {
					return fail("jobs.%s.steps[%d]: run script is not one Halos renders; policy values reach a script only through env", name, i)
				}
			}
		}
	}
	return nil
}
