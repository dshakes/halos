package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// CloudAgents governs background coding agents that run on vendor or CI
// infrastructure instead of a developer machine (ADR-0034): Claude Code (the
// GitHub Action and cloud sessions), Codex cloud tasks, the Copilot cloud
// agent, Cursor cloud agents and the Gemini CLI GitHub Action. A vendor is
// governed when its key is present. Credentials never live here.
type CloudAgents struct {
	// Identities map vendor logins to Halos users, so a cloud task is
	// attributed, ring-resolved and killed like its human.
	Identities []CloudIdentity `yaml:"identities,omitempty" json:"identities,omitempty"`
	// Server is the halo-server base URL rendered workflows exchange their
	// OIDC token at (identity: workload).
	Server string `yaml:"server,omitempty" json:"server,omitempty"`
	// HaloVersion is the halo release tag rendered workflows install to do
	// that exchange (identity: workload).
	HaloVersion string `yaml:"haloVersion,omitempty" json:"haloVersion,omitempty"`

	Claude  *CloudAgent `yaml:"claude,omitempty" json:"claude,omitempty"`
	Codex   *CloudAgent `yaml:"codex,omitempty" json:"codex,omitempty"`
	Copilot *CloudAgent `yaml:"copilot,omitempty" json:"copilot,omitempty"`
	Cursor  *CloudAgent `yaml:"cursor,omitempty" json:"cursor,omitempty"`
	Gemini  *CloudAgent `yaml:"gemini,omitempty" json:"gemini,omitempty"`
}

// CloudIdentity is one person's vendor logins.
type CloudIdentity struct {
	// User is the Halos user id (what rings, experiments and budgets key on).
	User string `yaml:"user" json:"user"`
	// GitHub is the GitHub login that triggers GitHub-hosted agents
	// (Claude and Gemini actions, Copilot cloud agent).
	GitHub string `yaml:"github,omitempty" json:"github,omitempty"`
}

// CloudAgent is one vendor's cloud agent policy.
type CloudAgent struct {
	// Enabled false renders nothing that runs the agent and makes every
	// observed task a violation; it never deletes a vendor setting.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Repos the agent may work in: owner/repo or owner/* (every repo of owner).
	Repos []string `yaml:"repos,omitempty" json:"repos,omitempty"`
	// Models the agent may use (vendor model ids). The first is rendered as
	// the default where the vendor takes a model in config.
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
	// MaxConcurrent caps running tasks.
	MaxConcurrent CloudConcurrency `yaml:"maxConcurrent,omitempty" json:"maxConcurrent,omitempty"`
	// Budgets cap vendor-reported task spend (ADR-0017 budget fields).
	Budgets []Budget `yaml:"budgets,omitempty" json:"budgets,omitempty"`
	// Network is the egress the agent's sandbox gets, where the vendor has one.
	Network *CloudNetwork `yaml:"network,omitempty" json:"network,omitempty"`
	// Identity "workload" makes rendered workflows call the model through the
	// Halos gateway with a short-lived workload credential (ADR-0023) instead
	// of a long-lived vendor key. Empty uses the vendor's repository secret.
	Identity string `yaml:"identity,omitempty" json:"identity,omitempty"`
	// OnOverLimit is alert (default: report only) or pause (also pause the
	// agent where the vendor API can, reversibly; never auto-resumed).
	OnOverLimit string `yaml:"onOverLimit,omitempty" json:"onOverLimit,omitempty"`
	// Version pins the agent CLI where the vendor takes one (gemini).
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	// TimeoutMinutes caps one rendered workflow job (copilot at most 59).
	TimeoutMinutes int `yaml:"timeoutMinutes,omitempty" json:"timeoutMinutes,omitempty"`
}

// CloudConcurrency caps running tasks per user and per group.
type CloudConcurrency struct {
	PerUser  int `yaml:"perUser,omitempty" json:"perUser,omitempty"`
	PerGroup int `yaml:"perGroup,omitempty" json:"perGroup,omitempty"`
	// Groups that each get a PerGroup counter (required with perGroup).
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
}

// CloudNetwork is the sandbox egress mode.
type CloudNetwork struct {
	// Mode: none (no egress), allowlist (only Allow, plus the vendor's
	// package-registry list when Recommended) or full (any host; warned).
	Mode string `yaml:"mode" json:"mode"`
	// Allow are extra domains (a leading "*." matches subdomains).
	Allow []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	// Recommended keeps the vendor's own dependency allowlist (allowlist only).
	Recommended bool `yaml:"recommended,omitempty" json:"recommended,omitempty"`
}

// Cloud agent vendors, identity modes, network modes and over-limit actions.
const (
	CloudClaude  = "claude"
	CloudCodex   = "codex"
	CloudCopilot = "copilot"
	CloudCursor  = "cursor"
	CloudGemini  = "gemini"

	CloudIdentityWorkload = "workload"

	NetworkNone      = "none"
	NetworkAllowlist = "allowlist"
	NetworkFull      = "full"

	OverLimitAlert = "alert"
	OverLimitPause = "pause"
)

// CloudVendors lists the vendors in a fixed order.
var CloudVendors = []string{CloudClaude, CloudCodex, CloudCopilot, CloudCursor, CloudGemini}

// Vendor returns one vendor's policy (nil when ungoverned).
func (c *CloudAgents) Vendor(name string) *CloudAgent {
	if c == nil {
		return nil
	}
	return map[string]*CloudAgent{CloudClaude: c.Claude, CloudCodex: c.Codex, CloudCopilot: c.Copilot, CloudCursor: c.Cursor, CloudGemini: c.Gemini}[name]
}

// UserForGitHub is the Halos user a GitHub login maps to (case-insensitive,
// as GitHub logins are).
func (c *CloudAgents) UserForGitHub(login string) (string, bool) {
	if c == nil || login == "" {
		return "", false
	}
	for _, id := range c.Identities {
		if strings.EqualFold(id.GitHub, login) {
			return id.User, true
		}
	}
	return "", false
}

// Pauses reports whether the agent pauses on an over-limit.
func (a *CloudAgent) Pauses() bool { return a != nil && a.OnOverLimit == OverLimitPause }

// RepoAllowed reports whether owner/repo matches one of a's repo patterns
// (case-insensitive). No patterns means every repository.
func (a *CloudAgent) RepoAllowed(repo string) bool {
	if a == nil {
		return false
	}
	if len(a.Repos) == 0 {
		return true
	}
	owner, _, _ := strings.Cut(repo, "/")
	return slices.ContainsFunc(a.Repos, func(p string) bool {
		po, pr, _ := strings.Cut(p, "/")
		return strings.EqualFold(po, owner) && (pr == "*" || strings.EqualFold(p, repo))
	})
}

// ModelAllowed reports whether model may be used. No list means any model;
// an empty model (the vendor did not report one) is allowed.
func (a *CloudAgent) ModelAllowed(model string) bool {
	return a != nil && (len(a.Models) == 0 || model == "" || slices.Contains(a.Models, model))
}

var (
	repoPatRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/([A-Za-z0-9._-]{1,100}|\*)$`)
	cloudModel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)
	haloTagRe  = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	versionRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
)

// cloudSupport is where each control is enforced per vendor; anything else is
// warned (invariant 2). Sources are in ADR-0034 and internal/harness/FACTS.md.
var cloudSupport = map[string]struct{ models, network, identity, version, timeout bool }{
	CloudClaude:  {models: true, network: true, identity: true, timeout: true},
	CloudCodex:   {network: true},
	CloudCopilot: {network: true, timeout: true},
	CloudCursor:  {},
	CloudGemini:  {models: true, identity: true, version: true, timeout: true},
}

func (v *validator) cloudAgents() {
	c := v.org.CloudAgents
	if c == nil {
		return
	}
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	users, logins := map[string]bool{}, map[string]bool{}
	for i, id := range c.Identities {
		p := fmt.Sprintf("cloudAgents.identities[%d]", i)
		if strings.TrimSpace(id.User) == "" {
			v.errf(p+".user", "the Halos user id is required")
		}
		if users[id.User] {
			v.errf(p+".user", "duplicate user %q", id.User)
		}
		users[id.User] = true
		if id.GitHub == "" {
			v.errf(p, "name at least one vendor login (github)")
			continue
		}
		if !vendorOrgRe.MatchString(id.GitHub) {
			v.errf(p+".github", "%q is not a GitHub login", id.GitHub)
		}
		if l := strings.ToLower(id.GitHub); logins[l] {
			v.errf(p+".github", "GitHub login %q is mapped twice", id.GitHub)
		} else {
			logins[l] = true
		}
	}
	workload := false
	for _, name := range CloudVendors {
		a := c.Vendor(name)
		if a == nil {
			continue
		}
		p := "cloudAgents." + name
		sup := cloudSupport[name]
		for i, r := range a.Repos {
			if !repoPatRe.MatchString(r) {
				v.errf(fmt.Sprintf("%s.repos[%d]", p, i), "%q is not owner/repo or owner/*", r)
			}
		}
		for i, m := range a.Models {
			if !cloudModel.MatchString(m) {
				v.errf(fmt.Sprintf("%s.models[%d]", p, i), "%q is not a model id", m)
			}
		}
		if len(a.Models) > 0 && !sup.models {
			v.warnf(p+".models", "%s takes no model in repository config; models are checked on observed tasks only where the vendor reports one", name)
		}
		mc := a.MaxConcurrent
		if mc.PerUser < 0 || mc.PerGroup < 0 {
			v.errf(p+".maxConcurrent", "limits must be >= 0")
		}
		if mc.PerGroup > 0 && len(mc.Groups) == 0 {
			v.errf(p+".maxConcurrent.groups", "perGroup needs the groups that get a counter")
		}
		names := map[string]bool{}
		for i, b := range a.Budgets {
			bp := fmt.Sprintf("%s.budgets[%d]", p, i)
			if !nameRe.MatchString(b.Name) {
				v.errf(bp+".name", "%q must match %s", b.Name, nameRe)
			} else if names[b.Name] {
				v.errf(bp+".name", "duplicate budget name %q", b.Name)
			}
			names[b.Name] = true
			v.budgetEntry(bp, b, rings)
			if b.Action == BudgetEnforce {
				v.errf(bp+".action", "cloud task spend is reported after the fact; use onOverLimit: pause, not action enforce")
			}
			if name == CloudCursor && b.LimitUSD > 0 {
				v.warnf(bp+".limitUSD", "cursor reports tokens per agent, not cost; only limitTokens is counted")
			}
		}
		if len(a.Budgets) > 0 && name != CloudCursor {
			v.warnf(p+".budgets", "%s reports no per-task usage Halos can read; its budgets count nothing until it does", name)
		}
		if a.Network != nil {
			v.cloudNetwork(p+".network", name, a.Network, sup.network)
		}
		switch a.Identity {
		case "":
		case CloudIdentityWorkload:
			if !sup.identity {
				v.errf(p+".identity", "%s does not run in a workflow Halos renders; workload identity applies to claude and gemini", name)
			}
			workload = true
		default:
			v.oneOf(p+".identity", "identity", a.Identity, []string{CloudIdentityWorkload})
		}
		if a.OnOverLimit != "" {
			v.oneOf(p+".onOverLimit", "onOverLimit", a.OnOverLimit, []string{OverLimitAlert, OverLimitPause})
		}
		if a.Version != "" {
			if !versionRe.MatchString(a.Version) {
				v.errf(p+".version", "%q is not a semantic version", a.Version)
			}
			if !sup.version {
				v.warnf(p+".version", "%s takes no CLI version in config; not rendered", name)
			}
		}
		switch {
		case a.TimeoutMinutes < 0:
			v.errf(p+".timeoutMinutes", "must be >= 0")
		case name == CloudCopilot && a.TimeoutMinutes > 59:
			v.errf(p+".timeoutMinutes", "the Copilot cloud agent job allows at most 59")
		case a.TimeoutMinutes > 0 && !sup.timeout:
			v.warnf(p+".timeoutMinutes", "%s runs no workflow Halos renders; not rendered", name)
		}
		if va := v.org.VendorAdmin; name != CloudGemini && va != nil && map[string]*VendorTarget{CloudClaude: va.Claude, CloudCodex: va.Codex, CloudCopilot: va.Copilot, CloudCursor: va.Cursor}[name] == nil {
			v.warnf(p, "%s's cloud agent console settings are planned by `halo admin plan` only when vendorAdmin.%s is set", name, name)
		}
		if !a.Enabled && (len(a.Repos) > 0 || len(a.Models) > 0) {
			v.warnf(p, "disabled: repos and models are kept for when it is enabled; every observed task is a violation")
		}
	}
	if workload {
		if v.org.Workloads == nil || !slices.ContainsFunc(v.org.Workloads.Issuers, func(i WorkloadIssuer) bool {
			p, _ := i.TenantClaims()
			return p == "GitHub Actions"
		}) {
			v.errf("cloudAgents", "identity: workload needs a workloads issuer for GitHub Actions (ADR-0023)")
		}
		if v.org.Gateway == nil {
			v.errf("cloudAgents", "identity: workload routes the agent through the Halos gateway; define one")
		}
		if u, err := url.Parse(c.Server); c.Server == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			v.errf("cloudAgents.server", "identity: workload needs the halo-server https base URL, got %q", c.Server)
		}
		if !haloTagRe.MatchString(c.HaloVersion) {
			v.errf("cloudAgents.haloVersion", "identity: workload needs the halo release tag to install (vX.Y.Z), got %q", c.HaloVersion)
		}
	}
}

func (v *validator) cloudNetwork(p, vendor string, n *CloudNetwork, supported bool) {
	v.oneOf(p+".mode", "mode", n.Mode, []string{NetworkNone, NetworkAllowlist, NetworkFull})
	if !supported {
		v.warnf(p, "%s exposes no egress setting; enforce egress at the runner or network boundary", vendor)
	}
	if n.Mode == NetworkFull {
		v.warnf(p+".mode", "full egress lets a prompt-injected agent exfiltrate code and secrets; prefer allowlist")
	}
	if n.Mode != NetworkAllowlist && (len(n.Allow) > 0 || n.Recommended) {
		v.errf(p, "allow and recommended apply to mode allowlist only")
	}
	if n.Mode == NetworkAllowlist && len(n.Allow) == 0 && !n.Recommended {
		v.errf(p, "an empty allowlist is mode none")
	}
	for i, d := range n.Allow {
		if !domainRe.MatchString(d) {
			v.errf(fmt.Sprintf("%s.allow[%d]", p, i), "%q is not a lowercase domain (optionally *.domain)", d)
		}
	}
}
