// Package vendoradmin renders one Halos policy into the settings of the
// vendors' cloud admin consoles (Claude for Teams/Enterprise, ChatGPT
// workspaces, Gemini for Google Cloud, GitHub Copilot, Cursor), reads the live
// settings where a vendor publishes a read API, diffs them, and applies the
// diff where it publishes a write API (ADR-0025). Everything else is exported
// as an artifact with manual steps.
//
// Render is pure. Read and Apply go through a Client that takes a base URL, so
// tests run against httptest fakes. Credentials are never part of policy;
// errors are redacted of them.
package vendoradmin

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/dshakes/halos/internal/policy"
)

// Access says what Halos can do with a console setting.
type Access string

const (
	AccessWrite  Access = "write"  // public read and write API: plan diffs, apply writes
	AccessRead   Access = "read"   // public read API only: plan diffs, a human changes it
	AccessManual Access = "manual" // no API: exported, a human sets it, drift is unverifiable
)

// Setting is one desired console setting. Key is "<resource>.<field>" in the
// vendor's own naming, so a diff reads like the vendor's API.
type Setting struct {
	Key    string `json:"key"`
	Value  any    `json:"value"`
	From   string `json:"from"` // the policy field it derives from
	Access Access `json:"access"`
	// Strict is the value that is the tighter control (a scalar setting);
	// changing a setting away from it (or from a StrictAlso value, which the
	// vendor treats the same) is a loosening. List settings loosen when an
	// entry the console has is missing from the desired list.
	Strict     any   `json:"-"`
	StrictAlso []any `json:"-"`
	// Sticky settings loosen whenever an existing value changes (a binding
	// target: moving it un-governs the old target).
	Sticky bool `json:"-"`
}

// Change is one setting whose live value differs from the desired one.
type Change struct {
	Key     string `json:"key"`
	Current any    `json:"current"` // nil = unset
	Desired any    `json:"desired"`
	Access  Access `json:"access"`
	// Loosens is true when applying it would weaken a control the console
	// has now. apply refuses these: a human makes that call in the console.
	Loosens bool `json:"loosens,omitempty"`
}

// Artifact is a file an admin pastes into a console that has no write API.
type Artifact struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Plan is one vendor's desired state and, after Diff, its drift.
type Plan struct {
	Vendor  string    `json:"vendor"`
	Target  string    `json:"target"`
	Desired []Setting `json:"desired"`
	Changes []Change  `json:"changes"`
	Read    bool      `json:"read"` // the live state was read and diffed
	// Conflicts are console resources Halos does not own that govern the same
	// target (a non-halos Gemini setting bound to the project); apply refuses.
	Conflicts []string   `json:"conflicts,omitempty"`
	Warnings  []string   `json:"warnings"`
	Manual    []string   `json:"manual,omitempty"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// Report is every enabled vendor's plan for one policy.
type Report struct {
	Ring     string   `json:"ring"`
	Profile  string   `json:"profile"`
	Warnings []string `json:"warnings"`
	Vendors  []*Plan  `json:"vendors"`
}

// Drift reports whether any vendor's live state differs from the policy.
func (r *Report) Drift() bool {
	return slices.ContainsFunc(r.Vendors, func(p *Plan) bool { return len(p.Changes) > 0 })
}

// HasAPI reports whether a vendor has any setting Halos can read.
func (p *Plan) HasAPI() bool {
	return slices.ContainsFunc(p.Desired, func(s Setting) bool { return s.Access != AccessManual })
}

// conflictsKey is the Client.Read key listing console resources Halos does
// not own that govern the same target (Plan.Conflicts).
const conflictsKey = "#conflicts"

// Diff fills p.Changes from current, the live values Client.Read returned
// (a missing key is unset). Manual settings are not diffed: nothing can read
// them. A list setting's live value is []any: Halos owns its string entries;
// any other entry (a Copilot {"if-any-match": [...]} rule) is preserved, so
// the desired value is the desired strings followed by those entries.
func (p *Plan) Diff(current map[string]any) {
	p.Read, p.Changes = true, []Change{}
	p.Conflicts, _ = current[conflictsKey].([]string)
	for _, s := range p.Desired {
		if s.Access == AccessManual {
			continue
		}
		cur, want := current[s.Key], s.Value
		if strs, ok := s.Value.([]string); ok {
			want = MergeList(strs, cur)
		}
		if equal(cur, want) {
			continue
		}
		p.Changes = append(p.Changes, Change{Key: s.Key, Current: cur, Desired: want, Access: s.Access, Loosens: loosens(s, cur)})
	}
}

// MergeList is want's strings (sorted, deduplicated) followed by the
// non-string entries of the live list cur, in their live order.
func MergeList(want []string, cur any) []any {
	ws := slices.Clone(want)
	slices.Sort(ws)
	ws = slices.Compact(ws)
	out := make([]any, 0, len(ws))
	for _, w := range ws {
		out = append(out, w)
	}
	have, _ := cur.([]any)
	for _, h := range have {
		if _, isStr := h.(string); !isStr {
			out = append(out, h)
		}
	}
	return out
}

// Loosenings are the changes apply refuses: the ones Halos would write.
// Loosening read-only settings are shown by plan but are a human's call.
func (p *Plan) Loosenings() []Change {
	var out []Change
	for _, c := range p.Changes {
		if c.Loosens && c.Access == AccessWrite {
			out = append(out, c)
		}
	}
	return out
}

func loosens(s Setting, cur any) bool {
	if cur == nil {
		return false
	}
	if want, ok := s.Value.([]string); ok {
		have, _ := cur.([]any)
		return slices.ContainsFunc(have, func(x any) bool {
			str, isStr := x.(string)
			return isStr && !slices.Contains(want, str)
		})
	}
	if s.Sticky {
		return !equal(cur, s.Value)
	}
	if s.Strict == nil || equal(s.Value, s.Strict) {
		return false
	}
	return equal(cur, s.Strict) || slices.ContainsFunc(s.StrictAlso, func(v any) bool { return equal(cur, v) })
}

func equal(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// Sanitize drops control (Cc) and format (Cf) characters from s, so a policy
// or console value cannot move the cursor, recolour or hide text in a
// terminal (ESC sequences, CR) or reorder it (bidi overrides) in STEPS.md.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// CheckForbidden refuses a plan that would emit a permission-bypass token
// (invariant 1; policy.BypassToken is the one shared check).
func (p *Plan) CheckForbidden() error {
	for _, s := range p.Desired {
		b, err := json.Marshal(s.Value)
		if err != nil {
			return fmt.Errorf("%s: %s: encode value for invariant 1 check: %w", p.Vendor, s.Key, err)
		}
		if f := policy.BypassToken(string(b)); f != "" {
			return fmt.Errorf("%s: %s would set permission-bypass token %q (invariant 1)", p.Vendor, s.Key, f)
		}
	}
	for _, a := range p.Artifacts {
		if f := policy.BypassToken(a.Content); f != "" {
			return fmt.Errorf("%s: artifact %s contains permission-bypass token %q (invariant 1)", p.Vendor, a.Name, f)
		}
	}
	return nil
}

// Render renders every vendor vendorAdmin enables from the profile of
// org.VendorAdminRing(). It reads nothing outside org. The org must validate.
func Render(org *policy.Org) (*Report, error) {
	va := org.VendorAdmin
	if va == nil {
		return nil, fmt.Errorf("vendoradmin: halos.yaml has no vendorAdmin section")
	}
	ringName := org.VendorAdminRing()
	var ring *policy.Ring
	for _, r := range org.Rings {
		if r.Name == ringName {
			ring = r
		}
	}
	if ring == nil {
		return nil, fmt.Errorf("vendoradmin: unknown ring %q", ringName)
	}
	prof, err := org.ResolveProfile(ring.Profile)
	if err != nil {
		return nil, fmt.Errorf("vendoradmin: ring %s: %w", ring.Name, err)
	}
	rep := &Report{Ring: ring.Name, Profile: ring.Profile, Warnings: []string{}, Vendors: []*Plan{}}
	var others []string
	for _, r := range org.Rings {
		if r.Name != ring.Name {
			others = append(others, r.Name)
		}
	}
	if len(others) > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("console settings are org-wide: members of rings %s get ring %s's console settings; ring rollouts reach only machine-delivered config", strings.Join(others, ", "), ring.Name))
	}
	if ring.Release != "" {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("ring %s is pinned to release %s; console settings are rendered from profile %s, not from the pinned release", ring.Name, ring.Release, ring.Profile))
	}
	if len(org.Units) > 0 {
		rep.Warnings = append(rep.Warnings, "unit overlays are not applied to consoles: every unit gets the org baseline there")
	}
	for _, v := range registry {
		t := v.target(va)
		if t == nil {
			continue
		}
		p, err := v.render(input{org: org, ring: ring.Name, profile: prof, target: *t})
		if err != nil {
			return nil, fmt.Errorf("vendoradmin: %s: %w", v.name, err)
		}
		p.Vendor, p.Target = v.name, t.String()
		if p.Warnings == nil {
			p.Warnings = []string{}
		}
		if p.Desired == nil {
			p.Desired = []Setting{}
		}
		if err := p.CheckForbidden(); err != nil {
			return nil, err
		}
		rep.Vendors = append(rep.Vendors, p)
	}
	return rep, nil
}

// Vendors lists the vendor names Render knows, in render order.
func Vendors() []string {
	out := make([]string, 0, len(registry))
	for _, v := range registry {
		out = append(out, v.name)
	}
	return out
}

// RenderProfile renders one vendor for a profile (tests, the no-silent-drop check).
func RenderProfile(vendor string, org *policy.Org, p *policy.Profile, t policy.VendorTarget) (*Plan, error) {
	for _, v := range registry {
		if v.name == vendor {
			pl, err := v.render(input{org: org, ring: "ga", profile: p, target: t})
			if err != nil {
				return nil, err
			}
			pl.Vendor, pl.Target = v.name, t.String()
			return pl, pl.CheckForbidden()
		}
	}
	return nil, fmt.Errorf("vendoradmin: unknown vendor %q", vendor)
}
