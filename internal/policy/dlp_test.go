package policy

import (
	"bytes"
	"strings"
	"testing"
)

func dlpOrg(d *DLP) *Org {
	o := validOrg()
	o.Units = []*Unit{{Meta: Meta{Name: "payments"}, Owners: []string{"@acme/payments"}, Members: UnitMembers{Groups: []string{"payments"}}}}
	o.Gateway.DLP = d
	return o
}

func TestValidateDLP(t *testing.T) {
	ok := &DLP{
		Secrets:   DLPSecrets{Action: DLPRedact, Disable: []string{"jwt"}, Patterns: []DLPPattern{{ID: "acme-token", Regex: `acme_[a-z0-9]{32}`}}},
		Injection: DLPInjection{Action: DLPMonitor, Threshold: 5},
		Rules:     []DLPRule{{Rings: []string{"r0"}, Units: []string{"payments"}, Secrets: DLPBlock, Injection: DLPBlock}},
	}
	if issues := dlpOrg(ok).Validate(); len(issues) != 0 {
		t.Fatalf("valid dlp: %v", issues)
	}
	with := func(f func(*DLP)) *Org {
		d := *ok
		d.Secrets.Patterns = append([]DLPPattern(nil), ok.Secrets.Patterns...)
		d.Rules = append([]DLPRule(nil), ok.Rules...)
		f(&d)
		return dlpOrg(&d)
	}
	for _, tt := range []struct {
		name, path, msg string
		org             *Org
		sev             Severity
	}{
		{"bad secrets action", "gateway.dlp.secrets.action", "invalid", with(func(d *DLP) { d.Secrets.Action = "allow" }), SeverityError},
		{"redact is not an injection action", "gateway.dlp.injection.action", "invalid", with(func(d *DLP) { d.Injection.Action = DLPRedact }), SeverityError},
		{"threshold out of range", "gateway.dlp.injection.threshold", "between", with(func(d *DLP) { d.Injection.Threshold = 99 }), SeverityError},
		{"scan cap too big", "gateway.dlp.maxScanBytes", "64 MiB", with(func(d *DLP) { d.MaxScanBytes = 1 << 30 }), SeverityError},
		{"unknown detector", "gateway.dlp.secrets.disable[0]", "unknown detector", with(func(d *DLP) { d.Secrets.Disable = []string{"aws"} }), SeverityError},
		{"not RE2", "gateway.dlp.secrets.patterns[0].regex", "RE2", with(func(d *DLP) { d.Secrets.Patterns[0].Regex = `(a)\1` }), SeverityError},
		{"lookahead is not RE2", "gateway.dlp.secrets.patterns[0].regex", "RE2", with(func(d *DLP) { d.Secrets.Patterns[0].Regex = `x(?=y)` }), SeverityError},
		{"matches empty", "gateway.dlp.secrets.patterns[0].regex", "empty string", with(func(d *DLP) { d.Secrets.Patterns[0].Regex = `a*` }), SeverityError},
		{"pattern id shadows a detector", "gateway.dlp.secrets.patterns[0].id", "duplicate", with(func(d *DLP) { d.Secrets.Patterns[0].ID = "jwt" }), SeverityError},
		{"bad pattern id", "gateway.dlp.secrets.patterns[0].id", "must match", with(func(d *DLP) { d.Secrets.Patterns[0].ID = "Acme Token" }), SeverityError},
		{"rule with no action", "gateway.dlp.rules[0]", "set secrets", with(func(d *DLP) { d.Rules[0].Secrets, d.Rules[0].Injection = "", "" }), SeverityError},
		{"rule unknown ring", "gateway.dlp.rules[0].rings", "not defined", with(func(d *DLP) { d.Rules[0].Rings = []string{"ghost"} }), SeverityError},
		{"rule unknown unit", "gateway.dlp.rules[0].units", "not defined", with(func(d *DLP) { d.Rules[0].Units = []string{"ghost"} }), SeverityError},
		{"kong scans requests only", "gateway.dlp.scanResponses", "requests only", func() *Org { o := dlpOrg(ok); o.Gateway.Engine = "kong"; return o }(), SeverityWarning},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, i := range tt.org.Validate() {
				if strings.Contains(i.Path, tt.path) && strings.Contains(i.Message, tt.msg) && i.Severity == tt.sev {
					return
				}
			}
			t.Fatalf("want %s %s ~%q, got %v", tt.sev, tt.path, tt.msg, tt.org.Validate())
		})
	}
}

func TestDLPDefaults(t *testing.T) {
	var d *DLP
	if d.ScanLimit() != DefaultDLPMaxScanBytes || d.Responses() {
		t.Fatal("nil DLP: default cap, no response scan")
	}
	d = &DLP{}
	if (&d.Injection).ScoreThreshold() != DefaultDLPThreshold || !d.Responses() {
		t.Fatal("defaults")
	}
	if s, i := d.Actions("any", nil); s != DLPMonitor || i != DLPMonitor {
		t.Fatalf("default actions %s %s", s, i)
	}
}

// A policy without gateway.dlp compiles to the same snapshot bytes as before.
func TestDLPOmittedFromSnapshot(t *testing.T) {
	b, err := Compile(validOrg())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("dlp")) || bytes.Contains(b, []byte("DLP")) {
		t.Fatalf("snapshot mentions dlp: %s", b)
	}
}
