package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
)

// UnitEntry is one org unit in a release manifest (ADR-0018): its member
// selector, so halod picks the device's unit with policy.MatchUnit, and the
// unit's rendered files. Being inside the signed manifest, neither can be
// altered in transit.
type UnitEntry struct {
	Name   string   `json:"name"`
	Parent string   `json:"parent,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Users  []string `json:"users,omitempty"`
	// Files is harness -> OS -> the files the unit's effective profile renders
	// differently from the release's own: whole files (not deltas), so an
	// overlay can narrow a list. The release's own files are the no-unit state.
	Files map[string]map[string][]FileEntry `json:"files,omitempty"`
}

// Policy returns the unit as halod evaluates it.
func (e UnitEntry) Policy() *policy.Unit {
	return &policy.Unit{Meta: policy.Meta{Name: e.Name}, Parent: e.Parent, Members: policy.UnitMembers{Groups: e.Groups, Users: e.Users}}
}

// MatchUnit returns the manifest unit s belongs to (policy.MatchUnit), or nil.
func (m Manifest) MatchUnit(s policy.Subject) *UnitEntry {
	us := make([]*policy.Unit, len(m.Units))
	for i, e := range m.Units {
		us[i] = e.Policy()
	}
	u := policy.MatchUnit(us, s)
	if u == nil {
		return nil
	}
	return &m.Units[slices.IndexFunc(m.Units, func(e UnitEntry) bool { return e.Name == u.Name })]
}

// unitBuild renders every unit's effective profile beside the base render.
type unitBuild struct {
	m       *Manifest
	units   []*policy.Unit
	profs   map[string]*policy.Profile
	entries map[string]*UnitEntry
}

func newUnitBuild(org *policy.Org, prof *policy.Profile, m *Manifest) (*unitBuild, error) {
	ub := &unitBuild{m: m, profs: map[string]*policy.Profile{}, entries: map[string]*UnitEntry{}}
	if org == nil {
		return ub, nil
	}
	ub.units = slices.Clone(org.Units)
	sort.Slice(ub.units, func(i, j int) bool { return ub.units[i].Name < ub.units[j].Name })
	for _, u := range ub.units {
		p, err := org.EffectiveProfile(prof, u.Name)
		if err == nil {
			p, err = org.WithMCPRegistry(p, m.Ring, u.Name) // prof already holds the ring's registry servers
		}
		if err != nil {
			return nil, fmt.Errorf("unit %q: %w", u.Name, err)
		}
		ub.profs[u.Name] = p
		ub.entries[u.Name] = &UnitEntry{Name: u.Name, Parent: u.Parent, Groups: u.Members.Groups, Users: u.Members.Users, Files: map[string]map[string][]FileEntry{}}
	}
	return ub, nil
}

// add renders each unit for one harness and OS (base/baseWarns is the
// release's own render) and records the files that differ. Unit renders go
// through CheckRendered like the base, so a forbidden value fails the build.
func (ub *unitBuild) add(ad harness.Adapter, os harness.OS, base []harness.File, baseWarns []string, opts Options, blobs map[string][]byte) error {
	name := ad.Name()
	byPath := map[string][]byte{}
	for _, f := range base {
		byPath[f.Path] = f.Data
	}
	for _, u := range ub.units {
		p := ub.profs[u.Name]
		files, warns, err := ad.Render(p, harness.Context{
			Gateway: opts.Gateway, Ring: ub.m.Ring, Release: opts.Version, OS: os, Experiment: opts.Experiment, Variant: opts.Variant,
		})
		if err != nil {
			return fmt.Errorf("unit %q: render %s for %s: %w", u.Name, name, os, err)
		}
		if err := CheckRendered(name, os, files, p, opts.Gateway); err != nil {
			return fmt.Errorf("unit %q: %w", u.Name, err)
		}
		for _, w := range warns {
			if !slices.Contains(baseWarns, w) {
				ub.m.Warnings = append(ub.m.Warnings, fmt.Sprintf("unit %s: %s/%s: %s", u.Name, name, os, w))
			}
		}
		rendered := map[string]bool{}
		var entries []FileEntry
		for _, f := range files {
			rendered[f.Path] = true
			if b, ok := byPath[f.Path]; ok && bytes.Equal(b, f.Data) {
				continue
			}
			sum := sha256.Sum256(f.Data)
			h := hex.EncodeToString(sum[:])
			blobs[h] = f.Data
			entries = append(entries, FileEntry{Path: f.Path, Mode: f.Mode, SHA256: h})
		}
		for _, f := range base {
			if !rendered[f.Path] {
				return fmt.Errorf("unit %q: %s/%s renders no %s, and a unit can only replace or add files", u.Name, name, os, f.Path)
			}
		}
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		e := ub.entries[u.Name]
		if e.Files[name] == nil {
			e.Files[name] = map[string][]FileEntry{}
		}
		e.Files[name][string(os)] = entries
	}
	return nil
}

// finish writes the entries, sorted by name, to the manifest.
func (ub *unitBuild) finish() {
	for _, u := range ub.units {
		ub.m.Units = append(ub.m.Units, *ub.entries[u.Name])
	}
}
