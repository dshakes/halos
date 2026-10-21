package policy

import (
	"fmt"
	"net"
	"net/url"
	"path"
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

// MatchWorkload returns the first rule for issuer whose match entries all
// hold on claims, plus its expanded subject. Claims are verified token claims.
func (w *Workloads) MatchWorkload(issuer string, claims map[string]any) (WorkloadRule, string, bool) {
	if w == nil {
		return WorkloadRule{}, "", false
	}
	for _, r := range w.Rules {
		if r.Issuer != issuer || len(r.Match) == 0 {
			continue
		}
		if !r.matches(claims) {
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

// hasLiteralPrefix: the pattern constrains the value (it does not start with a
// wildcard), e.g. "acme/*" but not "*" or "*/app".
func hasLiteralPrefix(pat string) bool {
	return pat != "" && !strings.ContainsAny(pat[:1], `*?[\`)
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
		if _, ok := issuers[r.Issuer]; !ok {
			v.errf(p+".issuer", "%q is not a workloads.issuers name", r.Issuer)
		}
		pinned := false
		for _, claim := range sortedKeys(r.Match) {
			pat := r.Match[claim]
			if _, err := path.Match(pat, ""); err != nil {
				v.errf(p+".match."+claim, "%q is not a valid glob: %v", pat, err)
			}
			pinned = pinned || hasLiteralPrefix(pat)
		}
		if !pinned {
			// A public issuer (GitHub, GitLab.com, Google) signs tokens for everyone:
			// an unpinned rule would admit any repository or account on it.
			v.errf(p+".match", "at least one claim must be pinned by a pattern that does not start with a wildcard (e.g. repository_owner: acme)")
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
