package release

import (
	"fmt"
	"sort"
	"strings"
)

// Diff returns a human-readable summary of what changes going from a to b:
// harness version/install changes, and per-file added/removed/changed with a
// line diff (changed lines only, no context; ponytail: add hunks if reviewers ask).
// Empty string means no differences.
func Diff(a, b *Release) string {
	var sb strings.Builder
	if a.Manifest.Version != b.Manifest.Version {
		fmt.Fprintf(&sb, "release version: %s -> %s\n", a.Manifest.Version, b.Manifest.Version)
	}
	for _, name := range union(keys(a.Manifest.Harnesses), keys(b.Manifest.Harnesses)) {
		ha, aok := a.Manifest.Harnesses[name]
		hb, bok := b.Manifest.Harnesses[name]
		switch {
		case !aok:
			fmt.Fprintf(&sb, "harness %s: added (version %s)\n", name, hb.Version)
		case !bok:
			fmt.Fprintf(&sb, "harness %s: removed\n", name)
		case ha.Version != hb.Version:
			fmt.Fprintf(&sb, "harness %s: version %s -> %s\n", name, ha.Version, hb.Version)
		}
		for _, os := range union(keys(ha.Files), keys(hb.Files)) {
			fa, fb := index(ha.Files[os]), index(hb.Files[os])
			for _, p := range union(keys(fa), keys(fb)) {
				ea, aok := fa[p]
				eb, bok := fb[p]
				switch {
				case !aok:
					fmt.Fprintf(&sb, "\n+++ %s/%s %s (new file)\n", name, os, p)
					for _, l := range lines(b.Blobs[eb.SHA256]) {
						sb.WriteString("+" + l + "\n")
					}
				case !bok:
					fmt.Fprintf(&sb, "\n--- %s/%s %s (removed)\n", name, os, p)
				case ea.SHA256 != eb.SHA256:
					fmt.Fprintf(&sb, "\n--- %s/%s %s\n+++ %s/%s %s\n", name, os, p, name, os, p)
					sb.WriteString(lineDiff(lines(a.Blobs[ea.SHA256]), lines(b.Blobs[eb.SHA256])))
				case ea.Mode != eb.Mode:
					fmt.Fprintf(&sb, "\n%s/%s %s: mode %04o -> %04o\n", name, os, p, ea.Mode, eb.Mode)
				}
			}
		}
	}
	return sb.String()
}

func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lineDiff is an LCS diff emitting only -/+ lines.
func lineDiff(a, b []string) string {
	l := make([][]int, len(a)+1)
	for i := range l {
		l[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				l[i][j] = l[i+1][j+1] + 1
			} else {
				l[i][j] = max(l[i+1][j], l[i][j+1])
			}
		}
	}
	var sb strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i++
			j++
		case j < len(b) && (i == len(a) || l[i][j+1] >= l[i+1][j]):
			sb.WriteString("+" + b[j] + "\n")
			j++
		default:
			sb.WriteString("-" + a[i] + "\n")
			i++
		}
	}
	return sb.String()
}

func index(fs []FileEntry) map[string]FileEntry {
	m := make(map[string]FileEntry, len(fs))
	for _, f := range fs {
		m[f.Path] = f
	}
	return m
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(a, b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
