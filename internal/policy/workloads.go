package policy

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"
)

// SubjectWorkload is Subject.Kind for a CI / cloud workload: a principal
// halo-server minted from a federated OIDC token (ADR-0023), not a human.
const SubjectWorkload = "workload"

// WorkloadSubjectPrefix starts every workload subject id, so a workload can
// never take a human's id (ring membership, budgets, audit).
const WorkloadSubjectPrefix = "workload:"

// Workload token lifetimes: halo-server never mints one longer than
// MaxWorkloadTTL; a rule without maxTTLSeconds gets DefaultWorkloadTTL.
const (
	DefaultWorkloadTTL = 15 * time.Minute
	MaxWorkloadTTL     = time.Hour
)

// Workloads federates headless agents (CI jobs, cloud workloads) into the
// gateway: halo-server exchanges a token from a trusted OIDC issuer for a
// short-lived gateway credential when a rule matches its claims (ADR-0023).
type Workloads struct {
	// Audience CI tokens must carry (each issuer may override). Required.
	Audience string           `yaml:"audience" json:"audience"`
	Issuers  []WorkloadIssuer `yaml:"issuers" json:"issuers"`
	// Rules are tried in order; the first whose every match entry holds wins.
	Rules []WorkloadRule `yaml:"rules" json:"rules"`
	// Experiments enrolls workloads in experiments like humans. Default false:
	// workload traffic gets control routing and no shadow, so CI runs never
	// skew experiment evidence.
	Experiments bool `yaml:"experiments,omitempty" json:"experiments,omitempty"`
}

// WorkloadIssuer is one trusted OIDC issuer (GitHub Actions, GitLab, ...).
type WorkloadIssuer struct {
	Name string `yaml:"name" json:"name"`
	// URL is the exact iss claim; discovery is <url>/.well-known/openid-configuration.
	URL      string `yaml:"url" json:"url"`
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	// TenantClaim names the claim that identifies the tenant (org, group,
	// account) a token was minted for; every rule of this issuer must match it
	// exactly. Required for an issuer Halos does not know (see TenantClaims);
	// for a known one it may only narrow the choice to one of its claims.
	TenantClaim string `yaml:"tenantClaim,omitempty" json:"tenantClaim,omitempty"`
}

// knownIssuer is a public OIDC issuer that signs tokens for every tenant on
// it, with whatever audience the job asks for, and the claims that name the
// tenant. Claim names are the providers' documented ones:
//
//   - GitHub: https://docs.github.com/en/actions/reference/security/oidc
//   - GitLab: https://docs.gitlab.com/ci/secrets/id_token_authentication/
//   - Buildkite: https://buildkite.com/docs/agent/v3/cli-oidc
//   - CircleCI: https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/
//   - Google: https://cloud.google.com/compute/docs/instances/verifying-instance-identity
//   - Microsoft Entra: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
type knownIssuer struct {
	provider string
	url      string // the iss, or its prefix up to a "/" (per-tenant issuer paths)
	claims   []string
	// ids are the claims among claims that never change. A rule that pins the
	// tenant only by the others (names, slugs, paths) is warned: a renamed or
	// deleted tenant's name can be re-registered by someone else.
	ids []string
}

var knownIssuers = []knownIssuer{
	{"GitHub Actions", "https://token.actions.githubusercontent.com", []string{"repository_owner_id", "repository_owner", "repository", "repository_id"}, []string{"repository_owner_id", "repository_id"}},
	{"GitLab.com", "https://gitlab.com", []string{"namespace_id", "namespace_path", "project_id", "project_path"}, []string{"namespace_id", "project_id"}},
	{"Buildkite", "https://agent.buildkite.com", []string{"organization_id", "organization_slug"}, []string{"organization_id"}},
	{"CircleCI", "https://oidc.circleci.com/org", []string{"oidc.circleci.com/org-id"}, nil},
	{"Google", "https://accounts.google.com", []string{"email", "sub"}, nil},
	{"Microsoft Entra ID", "https://login.microsoftonline.com", []string{"tid"}, nil},
	{"Microsoft Entra ID", "https://sts.windows.net", []string{"tid"}, nil},
}

// knownIssuerFor is the knownIssuers entry for issuer URL u, if any.
func knownIssuerFor(u string) (knownIssuer, bool) {
	u = strings.ToLower(strings.TrimRight(u, "/"))
	for _, k := range knownIssuers {
		if u == k.url || strings.HasPrefix(u, k.url+"/") {
			return k, true
		}
	}
	return knownIssuer{}, false
}

// TenantClaims returns the provider name ("" for an issuer Halos does not
// know) and the claims a rule of issuer i may pin its tenant with (none for
// an unknown issuer without tenantClaim). For a known issuer tenantClaim
// only narrows the provider's own tenant claims: a tenantClaim that is not
// one of them (ref, environment, ...) names no tenant and is ignored, so a
// rule pinning only it never counts as pinned (Validate reports it).
func (i WorkloadIssuer) TenantClaims() (provider string, claims []string) {
	if k, ok := knownIssuerFor(i.URL); ok {
		if slices.Contains(k.claims, i.TenantClaim) {
			return k.provider, []string{i.TenantClaim}
		}
		return k.provider, k.claims
	}
	if i.TenantClaim != "" {
		return "", []string{i.TenantClaim}
	}
	return "", nil
}

// pinsTenant reports whether pat selects one tenant: a literal, or a literal
// followed by "/*" (one path segment under it, e.g. repository: acme/*).
// "acme*" or "*" would also match acme-evil or anyone.
func pinsTenant(pat string) bool {
	lit := strings.TrimSuffix(pat, "/*")
	return lit != "" && !strings.ContainsAny(lit, `*?[\`)
}

// WorkloadRule maps matching tokens of one issuer to a workload subject.
type WorkloadRule struct {
	Name   string `yaml:"name" json:"name"`
	Issuer string `yaml:"issuer" json:"issuer"` // WorkloadIssuer.Name
	// Match: claim name -> exact value or path.Match glob ("*" never crosses "/").
	// Every entry must hold; a missing claim never matches.
	Match map[string]string `yaml:"match" json:"match"`
	// Subject is the workload id; must start with "workload:". {claim}
	// expands to that (matched) claim's value, e.g. workload:gh:{repository}.
	Subject string   `yaml:"subject" json:"subject"`
	Groups  []string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// MaxTTLSeconds bounds the minted credential (default 900, at most 3600).
	MaxTTLSeconds int `yaml:"maxTTLSeconds,omitempty" json:"maxTTLSeconds,omitempty"`
}

// TTL is the rule's credential lifetime.
func (r WorkloadRule) TTL() time.Duration {
	if r.MaxTTLSeconds <= 0 {
		return DefaultWorkloadTTL
	}
	return min(time.Duration(r.MaxTTLSeconds)*time.Second, MaxWorkloadTTL)
}

// IssuerByURL returns the trusted issuer whose URL is exactly iss.
func (w *Workloads) IssuerByURL(iss string) (WorkloadIssuer, bool) {
	if w != nil {
		for _, i := range w.Issuers {
			if i.URL == iss {
				return i, true
			}
		}
	}
	return WorkloadIssuer{}, false
}

// AudienceFor is the aud a token from issuer i must carry.
func (w *Workloads) AudienceFor(i WorkloadIssuer) string {
	if i.Audience != "" {
		return i.Audience
	}
	return w.Audience
}

// AllowsExperiments reports whether workload subjects may be enrolled in
// experiments (and shadowed).
func (w *Workloads) AllowsExperiments() bool { return w != nil && w.Experiments }

// pinnedTenantClaims is the set of issuer is's tenant claims that rule r
// matches exactly (a literal, or literal/*).
func (r WorkloadRule) pinnedTenantClaims(is WorkloadIssuer) map[string]bool {
	_, claims := is.TenantClaims()
	pinned := map[string]bool{}
	for _, c := range claims {
		if pat, ok := r.Match[c]; ok && pinsTenant(pat) {
			pinned[c] = true
		}
	}
	return pinned
}

// UnpinnedRules names the rules that pin no tenant of their issuer (or name
// no declared issuer). Validate refuses them; MatchWorkload never matches
// them, so a policy that reached a server without validation still cannot
// admit another tenant's jobs.
func (w *Workloads) UnpinnedRules() []string {
	if w == nil {
		return nil
	}
	var out []string
	for _, r := range w.Rules {
		if !w.tenantPinned(r) {
			out = append(out, r.Name)
		}
	}
	return out
}

func (w *Workloads) tenantPinned(r WorkloadRule) bool {
	for _, is := range w.Issuers {
		if is.Name == r.Issuer {
			return len(r.pinnedTenantClaims(is)) > 0
		}
	}
	return false
}

// TightenWorkloads is the part of a refused policy next (SecurityIssues
// found errors) that still applies over good, the last policy that passed:
// workload rule removals, so an unrelated error elsewhere cannot block the
// emergency removal of a compromised rule. The result is good's rules that
// next still has unchanged (equal, under an issuer of the same name);
// additions and modifications are not applied, nor is anything else in next.
// It returns good itself when no rule is dropped, else a shallow copy of good
// with its own Workloads, plus the names of the dropped rules. Neither input
// is modified.
func TightenWorkloads(good, next *Org) (*Org, []string) {
	if good == nil || good.Workloads == nil || len(good.Workloads.Rules) == 0 {
		return good, nil
	}
	var nw *Workloads
	if next != nil {
		nw = next.Workloads
	}
	var keep []WorkloadRule
	var dropped []string
	for _, r := range good.Workloads.Rules {
		still := nw != nil && slices.ContainsFunc(nw.Rules, func(n WorkloadRule) bool { return reflect.DeepEqual(n, r) }) &&
			slices.ContainsFunc(nw.Issuers, func(i WorkloadIssuer) bool { return i.Name == r.Issuer })
		if still {
			keep = append(keep, r)
		} else {
			dropped = append(dropped, r.Name)
		}
	}
	if len(dropped) == 0 {
		return good, nil
	}
	cp, wl := *good, *good.Workloads
	wl.Rules = keep
	cp.Workloads = &wl
	return &cp, dropped
}

// MatchWorkload returns the first rule for issuer whose match entries all
// hold on claims, plus its expanded subject. Claims are verified token claims.
// A rule that pins no tenant (UnpinnedRules) is skipped, whatever loaded it.
func (w *Workloads) MatchWorkload(issuer string, claims map[string]any) (WorkloadRule, string, bool) {
	if w == nil {
		return WorkloadRule{}, "", false
	}
	for _, r := range w.Rules {
		if r.Issuer != issuer || len(r.Match) == 0 {
			continue
		}
		if !r.matches(claims) || !w.tenantPinned(r) {
			continue
		}
		if sub, ok := r.expandSubject(claims); ok {
			return r, sub, true
		}
	}
	return WorkloadRule{}, "", false
}

func (r WorkloadRule) matches(claims map[string]any) bool {
	for claim, pat := range r.Match {
		v, ok := ClaimString(claims, claim)
		if !ok {
			return false
		}
		if m, err := path.Match(pat, v); err != nil || !m {
			return false
		}
	}
	return true
}

// expandSubject substitutes {claim} placeholders. A placeholder whose claim
// is missing, or a value that would smuggle in another placeholder, fails.
func (r WorkloadRule) expandSubject(claims map[string]any) (string, bool) {
	var b strings.Builder
	s := r.Subject
	for {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return "", false
		}
		v, ok := ClaimString(claims, s[i+1:i+j])
		if !ok || v == "" || strings.ContainsAny(v, "{}") {
			return "", false
		}
		b.WriteString(s[:i])
		b.WriteString(v)
		s = s[i+j+1:]
	}
	out := b.String()
	return out, strings.HasPrefix(out, WorkloadSubjectPrefix)
}

// ClaimString renders a scalar claim (string, bool, number) as a string.
// Objects, arrays and absent claims report false.
func ClaimString(claims map[string]any, name string) (string, bool) {
	switch v := claims[name].(type) {
	case string:
		return v, true
	case bool:
		return fmt.Sprint(v), true
	case float64:
		return fmt.Sprint(v), true
	}
	return "", false
}

func (v *validator) workloads() {
	w := v.org.Workloads
	if w == nil {
		return
	}
	if w.Audience == "" {
		v.errf("workloads.audience", "required: the aud CI tokens must carry (e.g. halos)")
	}
	issuers := map[string]WorkloadIssuer{}
	urls := map[string]bool{}
	for i, is := range w.Issuers {
		p := fmt.Sprintf("workloads.issuers[%d]", i)
		if _, dup := issuers[is.Name]; is.Name == "" || dup {
			v.errf(p+".name", "%q must be a non-empty, unique issuer name", is.Name)
		}
		if !secureIssuerURL(is.URL) {
			v.errf(p+".url", "%q must be an absolute https URL (http only for loopback)", is.URL)
		}
		if urls[is.URL] {
			v.errf(p+".url", "duplicate issuer url %q", is.URL)
		}
		issuers[is.Name], urls[is.URL] = is, true
		provider, known := (WorkloadIssuer{URL: is.URL}).TenantClaims()
		switch {
		case provider == "" && is.TenantClaim == "":
			v.errf(p+".tenantClaim", "required: Halos does not know issuer %q, so name the claim that identifies your tenant (org, group or account); every rule must match it exactly, or one issuer that signs for other tenants admits them all", is.URL)
		case provider != "" && is.TenantClaim != "" && !slices.Contains(known, is.TenantClaim):
			v.errf(p+".tenantClaim", "%q does not identify a %s tenant; use one of %s", is.TenantClaim, provider, strings.Join(known, ", "))
		}
	}
	if len(w.Rules) == 0 {
		v.warnf("workloads.rules", "no rules: every token exchange is denied")
	}
	names := map[string]bool{}
	for i, r := range w.Rules {
		p := fmt.Sprintf("workloads.rules[%d]", i)
		if r.Name == "" {
			v.errf(p+".name", "required")
		} else if names[r.Name] {
			v.errf(p+".name", "duplicate rule %q", r.Name)
		}
		names[r.Name] = true
		is, ok := issuers[r.Issuer]
		if !ok {
			v.errf(p+".issuer", "%q is not a workloads.issuers name", r.Issuer)
		}
		for _, claim := range sortedKeys(r.Match) {
			if _, err := path.Match(r.Match[claim], ""); err != nil {
				v.errf(p+".match."+claim, "%q is not a valid glob: %v", r.Match[claim], err)
			}
		}
		if ok {
			v.workloadTenantPin(p, r, is)
		}
		if !strings.HasPrefix(r.Subject, WorkloadSubjectPrefix) || len(r.Subject) == len(WorkloadSubjectPrefix) {
			v.errf(p+".subject", "%q must start with %q so a workload can never take a human's id", r.Subject, WorkloadSubjectPrefix)
		}
		if strings.Count(r.Subject, "{") != strings.Count(r.Subject, "}") {
			v.errf(p+".subject", "%q has unbalanced {claim} placeholders", r.Subject)
		}
		if r.MaxTTLSeconds < 0 || time.Duration(r.MaxTTLSeconds)*time.Second > MaxWorkloadTTL {
			v.errf(p+".maxTTLSeconds", "%d must be 1..%d", r.MaxTTLSeconds, int(MaxWorkloadTTL.Seconds()))
		}
	}
}

// workloadTenantPin: rule r (at path p) must match one of its issuer's tenant
// claims exactly. Any audience check is moot here: a public issuer mints a
// token with whatever aud the job asks for, for every tenant on it, so
// "ref: refs/heads/main" or "repository_owner: acme*" admits anyone's job.
func (v *validator) workloadTenantPin(p string, r WorkloadRule, is WorkloadIssuer) {
	provider, claims := is.TenantClaims()
	if len(claims) == 0 {
		return // issuers[].tenantClaim is reported
	}
	pinned := r.pinnedTenantClaims(is)
	if len(pinned) == 0 {
		who := provider
		if who == "" {
			who = is.URL
		}
		v.errf(p+".match", "pins no tenant: %s signs tokens for every tenant on it, with any audience a job asks for, so this rule would admit other organizations' jobs. "+
			"Match one of %s exactly (a literal, or literal/* for one path segment, e.g. repository: acme/*); globs like acme* also match acme-evil",
			who, strings.Join(claims, ", "))
		return
	}
	if k, ok := knownIssuerFor(is.URL); ok && len(k.ids) > 0 && !slices.ContainsFunc(k.ids, func(c string) bool { return pinned[c] }) {
		v.warnf(p+".match", "pins the tenant by name only: a %s tenant can be renamed or deleted and the name re-registered by someone else, who then matches; add %s, which never changes",
			k.provider, strings.Join(k.ids, " or "))
	}
	if provider != "GitHub Actions" {
		return
	}
	if _, env := r.Match["environment"]; !env {
		if _, wf := r.Match["job_workflow_ref"]; !wf {
			v.warnf(p+".match", "any workflow in the matched repositories mints this credential, including pull_request_target and workflow_run jobs that run on the base branch with fork-supplied code; for production pin environment (with required reviewers) or job_workflow_ref")
		}
	}
}

func secureIssuerURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	ip := net.ParseIP(h)
	return u.Scheme == "http" && (h == "localhost" || (ip != nil && ip.IsLoopback()))
}
