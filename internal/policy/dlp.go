package policy

import (
	"fmt"
	"regexp"
	"slices"
)

// DLP is the gateway's data-loss prevention and prompt-injection defense
// (ADR-0033). halo-proxy and halo-kong scan model-call request bodies;
// halo-proxy also scans streamed responses (monitor only).
type DLP struct {
	// Secrets: outbound secret detection on request content.
	Secrets DLPSecrets `yaml:"secrets,omitempty" json:"secrets,omitzero"`
	// Injection: prompt-injection signals on tool results entering the model.
	Injection DLPInjection `yaml:"injection,omitempty" json:"injection,omitzero"`
	// Rules override the actions per ring and org unit; the first rule whose
	// rings and units both match the caller wins.
	Rules []DLPRule `yaml:"rules,omitempty" json:"rules,omitempty"`
	// MaxScanBytes bounds how much of one request body is scanned (default
	// 4 MiB). A larger body is scanned up to the cap and counted as truncated.
	MaxScanBytes int64 `yaml:"maxScanBytes,omitempty" json:"maxScanBytes,omitempty"`
	// ScanResponses scans streamed and plain responses for echoed secrets
	// (monitor only, halo-proxy). Default true.
	ScanResponses *bool `yaml:"scanResponses,omitempty" json:"scanResponses,omitempty"`
}

// DLPSecrets configures the secret detectors.
type DLPSecrets struct {
	// Action: monitor (count and audit), redact (replace each secret with
	// [REDACTED:<detector>:<hash8>]) or block (refuse the request). Default monitor.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	// Disable turns built-in detectors off by id.
	Disable []string `yaml:"disable,omitempty" json:"disable,omitempty"`
	// Patterns are org detectors (RE2). The whole match is the secret unless
	// the regex has a capture group, then the first group is.
	Patterns []DLPPattern `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// DLPPattern is one org-defined secret detector.
type DLPPattern struct {
	ID    string `yaml:"id" json:"id"`
	Regex string `yaml:"regex" json:"regex"`
}

// DLPInjection configures prompt-injection scoring.
type DLPInjection struct {
	// Action: monitor (count and audit) or block (refuse at or above
	// Threshold). Default monitor. Model content is never modified.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	// Threshold is the score at which a tool result counts as an injection
	// (default 4).
	Threshold int `yaml:"threshold,omitempty" json:"threshold,omitempty"`
}

// DLPRule overrides the actions for callers in Rings and Units (empty = any).
// A unit matches its descendants too.
type DLPRule struct {
	Rings     []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Units     []string `yaml:"units,omitempty" json:"units,omitempty"`
	Secrets   string   `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Injection string   `yaml:"injection,omitempty" json:"injection,omitempty"`
}

// DLP actions.
const (
	DLPMonitor = "monitor"
	DLPRedact  = "redact"
	DLPBlock   = "block"
	DLPOff     = "off"
)

// DLP defaults and bounds.
const (
	DefaultDLPThreshold    = 4
	DefaultDLPMaxScanBytes = 4 << 20
	maxDLPPatterns         = 64
	maxDLPRegexLen         = 1024
)

// DLPDetectorIDs are the built-in secret detector ids (internal/gateway owns
// the detectors; tests keep the two lists equal).
var DLPDetectorIDs = []string{
	"anthropic-api-key", "aws-access-key-id", "gcp-service-account", "generic-secret", "github-token",
	"gitlab-token", "jwt", "openai-api-key", "private-key", "slack-token", "slack-webhook", "stripe-key",
}

// ScoreThreshold is Threshold with the default applied.
func (d *DLPInjection) ScoreThreshold() int {
	if d.Threshold <= 0 {
		return DefaultDLPThreshold
	}
	return d.Threshold
}

// ScanLimit is MaxScanBytes with the default applied.
func (d *DLP) ScanLimit() int64 {
	if d == nil || d.MaxScanBytes <= 0 {
		return DefaultDLPMaxScanBytes
	}
	return d.MaxScanBytes
}

// Responses reports whether responses are scanned (default true).
func (d *DLP) Responses() bool { return d != nil && (d.ScanResponses == nil || *d.ScanResponses) }

// Actions returns the secret and injection actions for a caller in ring and
// unit chain units (the caller's unit first, then its ancestors): the first
// matching rule's non-empty actions over the defaults. off disables a scan.
func (d *DLP) Actions(ring string, units []string) (secrets, injection string) {
	if d == nil {
		return DLPOff, DLPOff
	}
	secrets, injection = orDefault(d.Secrets.Action, DLPMonitor), orDefault(d.Injection.Action, DLPMonitor)
	for _, r := range d.Rules {
		if len(r.Rings) > 0 && !slices.Contains(r.Rings, ring) {
			continue
		}
		if len(r.Units) > 0 && !slices.ContainsFunc(units, func(u string) bool { return slices.Contains(r.Units, u) }) {
			continue
		}
		secrets, injection = orDefault(r.Secrets, secrets), orDefault(r.Injection, injection)
		break
	}
	return secrets, injection
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var (
	dlpSecretActions    = []string{DLPOff, DLPMonitor, DLPRedact, DLPBlock}
	dlpInjectionActions = []string{DLPOff, DLPMonitor, DLPBlock}
)

func (v *validator) dlp(g *Gateway) {
	d := g.DLP
	if d == nil {
		return
	}
	if g.Engine == EngineExternal {
		v.warnf("gateway.dlp", "dlp is applied by halo-proxy and halo-kong; engine external does not apply it")
	} else if g.Engine == "kong" && d.Responses() {
		v.warnf("gateway.dlp.scanResponses", "halo-kong scans requests only; responses are scanned by halo-proxy")
	}
	if d.Secrets.Action != "" {
		v.oneOf("gateway.dlp.secrets.action", "action", d.Secrets.Action, dlpSecretActions)
	}
	if d.Injection.Action != "" {
		v.oneOf("gateway.dlp.injection.action", "action", d.Injection.Action, dlpInjectionActions)
	}
	if d.Injection.Threshold < 0 || d.Injection.Threshold > 20 {
		v.errf("gateway.dlp.injection.threshold", "%d must be between 1 and 20", d.Injection.Threshold)
	}
	if d.MaxScanBytes < 0 || d.MaxScanBytes > 64<<20 {
		v.errf("gateway.dlp.maxScanBytes", "%d must be between 0 (default 4 MiB) and 64 MiB", d.MaxScanBytes)
	}
	for i, id := range d.Secrets.Disable {
		if !slices.Contains(DLPDetectorIDs, id) {
			v.errf(fmt.Sprintf("gateway.dlp.secrets.disable[%d]", i), "unknown detector %q; built-in detectors: %v", id, DLPDetectorIDs)
		}
	}
	if len(d.Secrets.Patterns) > maxDLPPatterns {
		v.errf("gateway.dlp.secrets.patterns", "at most %d patterns", maxDLPPatterns)
	}
	ids := map[string]bool{}
	for i, p := range d.Secrets.Patterns {
		path := fmt.Sprintf("gateway.dlp.secrets.patterns[%d]", i)
		switch {
		case !nameRe.MatchString(p.ID):
			v.errf(path+".id", "%q must match %s", p.ID, nameRe)
		case ids[p.ID] || slices.Contains(DLPDetectorIDs, p.ID):
			v.errf(path+".id", "duplicate detector id %q", p.ID)
		}
		ids[p.ID] = true
		if len(p.Regex) == 0 || len(p.Regex) > maxDLPRegexLen {
			v.errf(path+".regex", "regex must be 1 to %d bytes", maxDLPRegexLen)
			continue
		}
		re, err := regexp.Compile(p.Regex) // Go regexp is RE2: linear time, no backreferences
		if err != nil {
			v.errf(path+".regex", "not a valid RE2 regex: %v", err)
		} else if re.MatchString("") {
			v.errf(path+".regex", "matches the empty string")
		}
	}
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	units := map[string]bool{}
	for _, u := range v.org.Units {
		units[u.Name] = true
	}
	for i, r := range d.Rules {
		path := fmt.Sprintf("gateway.dlp.rules[%d]", i)
		if r.Secrets != "" {
			v.oneOf(path+".secrets", "secrets", r.Secrets, dlpSecretActions)
		}
		if r.Injection != "" {
			v.oneOf(path+".injection", "injection", r.Injection, dlpInjectionActions)
		}
		if r.Secrets == "" && r.Injection == "" {
			v.errf(path, "set secrets, injection or both")
		}
		for _, n := range r.Rings {
			if !rings[n] {
				v.errf(path+".rings", "ring %q not defined", n)
			}
		}
		for _, n := range r.Units {
			if !units[n] {
				v.errf(path+".units", "unit %q not defined", n)
			}
		}
	}
}
