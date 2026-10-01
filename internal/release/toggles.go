package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/toggle"
)

// ToggleEntry is one client-axis toggle in a release manifest. Being inside the
// signed manifest, neither the rules nor the fragments can be altered in transit.
type ToggleEntry struct {
	Name    string              `json:"name"`
	Default bool                `json:"default"`
	Expires string              `json:"expires,omitempty"`
	Rules   []policy.ToggleRule `json:"rules,omitempty"`
	// Fragments is harness -> OS -> deltas, one per file the toggle changes
	// (FileEntry.Path is the managed file the delta applies to; the blob is
	// JSON, see toggle.Delta). The release's own files are the toggle-off state.
	Fragments map[string]map[string][]FileEntry `json:"fragments,omitempty"`
}

// toggleBuild accumulates a release's toggle entries while Build renders.
type toggleBuild struct {
	m       *Manifest
	entries map[string]*ToggleEntry
	targets map[string][]string // toggle -> harnesses its client payload names
}

func newToggleBuild(org *policy.Org, m *Manifest) *toggleBuild {
	tb := &toggleBuild{m: m, entries: map[string]*ToggleEntry{}, targets: map[string][]string{}}
	if org == nil {
		return tb
	}
	for _, t := range org.Toggles {
		if t.Axis == policy.AxisClient && t.Client != nil {
			tb.entries[t.Name] = &ToggleEntry{Name: t.Name, Default: t.Default, Expires: t.Expires, Rules: t.Rules, Fragments: map[string]map[string][]FileEntry{}}
			for h := range t.Client.Harnesses {
				tb.targets[t.Name] = append(tb.targets[t.Name], h)
			}
		}
	}
	return tb
}

// add renders every toggle's "on" state for one harness and OS (the base render
// is base/baseWarns) and records the delta. The toggled profile goes through
// the same adapter and CheckRendered as the base, so a forbidden value fails
// the build and an unsupported field surfaces as a manifest warning.
func (tb *toggleBuild) add(org *policy.Org, ad harness.Adapter, prof *policy.Profile, os harness.OS,
	base []harness.File, baseWarns []string, opts Options, blobs map[string][]byte,
) error {
	name := ad.Name()
	for _, t := range org.Toggles {
		e, patch := tb.entries[t.Name], t.Client
		if e == nil || !hasPatch(patch, name) {
			continue
		}
		on := patch.Harnesses[name].Apply(prof, name)
		files, warns, err := ad.Render(on, harness.Context{
			Gateway: opts.Gateway, Ring: tb.m.Ring, Release: opts.Version, OS: os, Experiment: opts.Experiment, Variant: opts.Variant,
		})
		if err != nil {
			return fmt.Errorf("toggle %q: render %s for %s: %w", t.Name, name, os, err)
		}
		if err := CheckRendered(name, os, files, on, opts.Gateway); err != nil {
			return fmt.Errorf("toggle %q: %w", t.Name, err)
		}
		for _, w := range warns {
			if !slices.Contains(baseWarns, w) {
				tb.m.Warnings = append(tb.m.Warnings, fmt.Sprintf("toggle %s: %s/%s: %s", t.Name, name, os, w))
			}
		}
		byPath := map[string][]byte{}
		for _, f := range base {
			byPath[f.Path] = f.Data
		}
		var entries []FileEntry
		for _, f := range files {
			d, err := toggle.Delta(f.Path, byPath[f.Path], f.Data)
			if err != nil {
				return fmt.Errorf("toggle %q: %s/%s: %w", t.Name, name, os, err)
			}
			if d == nil {
				continue
			}
			sum := sha256.Sum256(d)
			h := hex.EncodeToString(sum[:])
			blobs[h] = d
			entries = append(entries, FileEntry{Path: f.Path, Mode: f.Mode, SHA256: h})
		}
		if len(entries) == 0 {
			tb.m.Warnings = append(tb.m.Warnings, fmt.Sprintf("toggle %s: %s/%s: fragment changes nothing (already in the profile, or unsupported by the adapter)", t.Name, name, os))
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		if e.Fragments[name] == nil {
			e.Fragments[name] = map[string][]FileEntry{}
		}
		e.Fragments[name][string(os)] = entries
	}
	return nil
}

// finish writes the entries (in policy order) to the manifest.
func (tb *toggleBuild) finish() {
	if tb.m == nil {
		return
	}
	order := make([]string, 0, len(tb.entries))
	for n := range tb.entries {
		order = append(order, n)
	}
	sort.Strings(order)
	for _, n := range order {
		sort.Strings(tb.targets[n])
		for _, h := range tb.targets[n] {
			if _, ok := tb.m.Harnesses[h]; !ok {
				tb.m.Warnings = append(tb.m.Warnings, fmt.Sprintf("toggle %s: harness %q is not enabled by profile %q; its fragment is not delivered", n, h, tb.m.Profile))
			}
		}
		tb.m.Toggles = append(tb.m.Toggles, *tb.entries[n])
	}
}

func hasPatch(c *policy.ToggleClient, h string) bool {
	p, ok := c.Harnesses[h]
	return ok && len(p.MCPServers)+len(p.Hooks)+len(p.Env)+len(p.Overrides) > 0
}
