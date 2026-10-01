package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/toggle"
)

// applied is one file to write: a manifest entry (SHA256 matches data) and its
// content; ok is false when the release lacks the blob.
type applied struct {
	f    release.FileEntry
	data []byte
	ok   bool
}

// activeToggles evaluates the verified release's client-axis toggles for this
// device (its ring, enrolled subject and IdP groups) against the signed kill
// list. A killed toggle is off whatever its rules say; a device without a
// subject id never lands in a percent rollout. It returns the toggles that are
// on, sorted by name, and the kill list's toggle names as seen now.
func (a *Agent) activeToggles(rel *release.Release, ring, subject string) (on []release.ToggleEntry, killed []string) {
	killed = slices.Clone(a.Kill.Killed().Toggles)
	sort.Strings(killed)
	for _, t := range rel.Manifest.Toggles {
		d := toggle.Eval(t.Name, t.Default, t.Rules, toggle.Subject{ID: subject, Groups: a.groups, Ring: ring}, slices.Contains(killed, t.Name))
		a.log().Info("toggle evaluated", "toggle", t.Name, "on", d.On, "why", d.Why)
		if d.On {
			on = append(on, t)
		}
	}
	sort.Slice(on, func(i, j int) bool { return on[i].Name < on[j].Name })
	return on, killed
}

// withToggles returns the files to write for one harness: the release's own
// (toggle-off) files with the fragments of the toggles that are on merged in.
// Everything merged comes from the signature-verified release. A fragment that
// fails to merge is reported and skipped: that file keeps its toggle-off
// content rather than blocking the rest of the release.
func (a *Agent) withToggles(rel *release.Release, harnessName string, he release.HarnessEntry, on []release.ToggleEntry) ([]applied, []error) {
	var out []applied
	idx := map[string]int{}
	for _, f := range he.Files[a.Cfg.OS] {
		data, ok := rel.Content(f)
		idx[f.Path] = len(out)
		out = append(out, applied{f, data, ok})
	}
	deltas := map[string][][]byte{}
	mode := map[string]uint32{}
	var order []string
	var errs []error
	for _, t := range on {
		for _, ff := range t.Fragments[harnessName][a.Cfg.OS] {
			d, ok := rel.Content(ff)
			if !ok {
				errs = append(errs, fmt.Errorf("toggle %s: fragment blob for %s missing", t.Name, ff.Path))
				continue
			}
			if _, seen := deltas[ff.Path]; !seen {
				order = append(order, ff.Path)
				mode[ff.Path] = ff.Mode
			}
			deltas[ff.Path] = append(deltas[ff.Path], d)
		}
	}
	for _, p := range order {
		var base []byte
		i, had := idx[p]
		if had {
			if !out[i].ok {
				continue // base blob missing: already reported by the caller
			}
			base = out[i].data
		}
		merged, err := toggle.Merge(p, base, deltas[p]...)
		if err != nil {
			errs = append(errs, fmt.Errorf("toggles: %w", err))
			continue
		}
		sum := sha256.Sum256(merged)
		f := release.FileEntry{Path: p, Mode: mode[p], SHA256: hex.EncodeToString(sum[:])}
		if had {
			f.Mode = out[i].f.Mode
			out[i] = applied{f, merged, true}
		} else {
			out = append(out, applied{f, merged, true})
		}
	}
	return out, errs
}
