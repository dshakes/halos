package policy

import (
	"fmt"
	"strings"
)

// VendorAdmin drives the vendors' cloud admin consoles from this policy
// (ADR-0025): `halo admin plan` diffs them, `halo admin apply` writes the
// vendors that have a public write API, and `halo admin export` writes the
// artifacts an admin pastes into the rest. A vendor is managed when its key is
// present.
type VendorAdmin struct {
	// Ring whose profile the consoles get. Console settings are org-wide, so
	// exactly one ring's profile can win; empty means the last ring (GA).
	Ring    string        `yaml:"ring,omitempty" json:"ring,omitempty"`
	Claude  *VendorTarget `yaml:"claude,omitempty" json:"claude,omitempty"`
	Codex   *VendorTarget `yaml:"codex,omitempty" json:"codex,omitempty"`
	Gemini  *VendorTarget `yaml:"gemini,omitempty" json:"gemini,omitempty"`
	Copilot *VendorTarget `yaml:"copilot,omitempty" json:"copilot,omitempty"`
	Cursor  *VendorTarget `yaml:"cursor,omitempty" json:"cursor,omitempty"`
}

// VendorTarget names the tenant one vendor's console settings apply to.
// Credentials never live here: `halo admin` reads them from a file or an
// environment variable named on its command line.
type VendorTarget struct {
	// Org is the tenant: the GitHub organization login (copilot, required),
	// or the Claude organization / ChatGPT workspace / Cursor team id recorded
	// in exported artifacts.
	Org string `yaml:"org,omitempty" json:"org,omitempty"`
	// Project is the Google Cloud project holding the Gemini Code Assist
	// settings (gemini, required).
	Project string `yaml:"project,omitempty" json:"project,omitempty"`
	// Location of the Gemini settings resources (gemini; default global).
	Location string `yaml:"location,omitempty" json:"location,omitempty"`
	// ReleaseChannel pins Gemini Code Assist's release channel (gemini):
	// stable | experimental. Empty leaves the channel unmanaged.
	ReleaseChannel string `yaml:"releaseChannel,omitempty" json:"releaseChannel,omitempty"`
}

// VendorAdminRing is the ring whose profile the consoles get: VendorAdmin.Ring,
// else the ring with the highest order (GA). Empty when there are no rings.
func (o *Org) VendorAdminRing() string {
	if o.VendorAdmin != nil && o.VendorAdmin.Ring != "" {
		return o.VendorAdmin.Ring
	}
	var ga *Ring
	for _, r := range o.Rings {
		if ga == nil || r.Order > ga.Order {
			ga = r
		}
	}
	if ga == nil {
		return ""
	}
	return ga.Name
}

var releaseChannels = []string{"stable", "experimental"}

func (v *validator) vendorAdmin() {
	va := v.org.VendorAdmin
	if va == nil {
		return
	}
	ring := v.org.VendorAdminRing()
	if ring == "" {
		v.errf("vendorAdmin", "needs at least one ring: the consoles get a ring's profile")
		return
	}
	if va.Ring != "" {
		if _, ok := v.org.ringByName(va.Ring); !ok {
			v.errf("vendorAdmin.ring", "unknown ring %q", va.Ring)
		} else if ga := (&Org{Rings: v.org.Rings}).VendorAdminRing(); va.Ring != ga {
			v.warnf("vendorAdmin.ring", "console settings are org-wide: every member, including ring %s, gets ring %s's console settings", ga, va.Ring)
		}
	}
	for name, t := range map[string]*VendorTarget{"claude": va.Claude, "codex": va.Codex, "gemini": va.Gemini, "copilot": va.Copilot, "cursor": va.Cursor} {
		if t == nil {
			continue
		}
		p := "vendorAdmin." + name
		if name != "gemini" && (t.Project != "" || t.Location != "" || t.ReleaseChannel != "") {
			v.errf(p, "project, location and releaseChannel apply to gemini only")
		}
		switch name {
		case "copilot":
			if t.Org == "" {
				v.errf(p+".org", "the GitHub organization login is required")
			} else if strings.ContainsAny(t.Org, "/?#% ") {
				v.errf(p+".org", "%q is not a GitHub organization login", t.Org)
			}
		case "gemini":
			if t.Project == "" {
				v.errf(p+".project", "the Google Cloud project id is required")
			} else if strings.ContainsAny(t.Project, "/?#% ") {
				v.errf(p+".project", "%q is not a Google Cloud project id", t.Project)
			}
			if t.Location != "" && !gcpRegion.MatchString(t.Location) {
				v.errf(p+".location", "%q is not a Google Cloud location", t.Location)
			}
			if t.ReleaseChannel != "" {
				v.oneOf(p, "releaseChannel", t.ReleaseChannel, releaseChannels)
			}
		}
	}
}

func (o *Org) ringByName(name string) (*Ring, bool) {
	for _, r := range o.Rings {
		if r.Name == name {
			return r, true
		}
	}
	return nil, false
}

// String names the target for logs and plan output (never a credential).
func (t VendorTarget) String() string {
	if t.Project != "" {
		return fmt.Sprintf("projects/%s/locations/%s", t.Project, t.GeminiLocation())
	}
	return t.Org
}

// GeminiLocation is Location with the default (global) applied.
func (t VendorTarget) GeminiLocation() string {
	if t.Location == "" {
		return "global"
	}
	return t.Location
}
