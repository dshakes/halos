// Package release builds immutable, content-addressed release bundles: a
// deterministic tar holding manifest.json plus every rendered file (as
// blobs/<sha256>). The tar's sha256 is the release digest.
package release

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/policy"
)

// ProfileResolver is satisfied by *policy.Org once it grows ResolveProfile.
type ProfileResolver interface {
	ResolveProfile(name string) (*policy.Profile, error)
}

// Options tunes Build. Zero value is valid.
type Options struct {
	Org       string          // defaults to the resolver's Org.Name when it is a *policy.Org
	Version   string          // release version label, e.g. "1.4.0"
	CreatedAt time.Time       // zero => Unix epoch, keeping builds reproducible
	OSes      []harness.OS    // defaults to darwin, linux, windows
	Gateway   *policy.Gateway // defaults to Org.Gateway when resolver is a *policy.Org
	// Experiment/Variant mark a client-axis variant release: stamped into the
	// manifest and into the harness config (telemetry resource attributes).
	Experiment, Variant string
	// Experiments is the ring release's client-axis experiment table (see BuildRing).
	Experiments []Experiment
}

// FileEntry describes one rendered file in the manifest.
type FileEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// HarnessEntry is one harness's pinned version, installer and files, per OS.
type HarnessEntry struct {
	Version        string                 `json:"version"`
	InstallCommand map[string]string      `json:"installCommand,omitempty"`
	Files          map[string][]FileEntry `json:"files"`
	// Artifacts are verified install artifacts keyed by "<goos>-<goarch>"
	// (or "any"), filled by ResolveArtifacts; see artifacts.go.
	Artifacts map[string]Artifact `json:"artifacts,omitempty"`
}

// Manifest is manifest.json inside the bundle.
type Manifest struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Org           string                  `json:"org"`
	Version       string                  `json:"version"`
	Profile       string                  `json:"profile"`
	Ring          string                  `json:"ring"`
	CreatedAt     time.Time               `json:"createdAt"`
	Harnesses     map[string]HarnessEntry `json:"harnesses"`
	Warnings      []string                `json:"warnings,omitempty"`
	// Experiment/Variant are set on a client-axis variant release only: the
	// release served on channel policy.ChannelName(Ring, Experiment, Variant).
	Experiment string `json:"experiment,omitempty"`
	Variant    string `json:"variant,omitempty"`
	// Experiments (ring releases only) lists the running client-axis
	// experiments enrolling Ring. Signed with the release, it is what halod
	// uses to pick a device's variant channel.
	Experiments []Experiment `json:"experiments,omitempty"`
}

// Experiment is one client-axis experiment in a ring release manifest: just
// what halod needs to compute the same assignment as the gateway.
type Experiment struct {
	Name     string              `json:"name"`
	Salt     string              `json:"salt"`
	Variants []ExperimentVariant `json:"variants"`
}

// ExperimentVariant is a variant and the channel serving its release.
type ExperimentVariant struct {
	Name    string  `json:"name"`
	Weight  float64 `json:"weight"`
	Channel string  `json:"channel"`
}

// Release is a built (or opened) bundle.
type Release struct {
	Manifest Manifest
	Blobs    map[string][]byte // sha256 hex -> content
	Tar      []byte
	Digest   string // "sha256:<hex>" of Tar
}

// Content returns the bytes for a manifest file entry.
func (r *Release) Content(f FileEntry) ([]byte, bool) { b, ok := r.Blobs[f.SHA256]; return b, ok }

var allOSes = []harness.OS{harness.Darwin, harness.Linux, harness.Windows}

// Build renders profileName for every enabled harness and OS.
func Build(org ProfileResolver, profileName, ringName string, opts Options) (*Release, error) {
	prof, err := org.ResolveProfile(profileName)
	if err != nil {
		return nil, fmt.Errorf("release: resolve profile %q: %w", profileName, err)
	}
	if o, ok := org.(*policy.Org); ok {
		if opts.Org == "" {
			opts.Org = o.Name
		}
		if opts.Gateway == nil {
			opts.Gateway = o.Gateway
		}
	}
	oses := opts.OSes
	if len(oses) == 0 {
		oses = allOSes
	}
	m := Manifest{
		SchemaVersion: 1, Org: opts.Org, Version: opts.Version, Profile: profileName, Ring: ringName,
		CreatedAt: opts.CreatedAt.UTC(), Harnesses: map[string]HarnessEntry{},
		Experiment: opts.Experiment, Variant: opts.Variant, Experiments: opts.Experiments,
	}
	if opts.CreatedAt.IsZero() {
		m.CreatedAt = time.Unix(0, 0).UTC()
	}
	blobs := map[string][]byte{}
	names := make([]string, 0, len(prof.Harnesses))
	for n := range prof.Harnesses {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		ad, ok := harness.Get(name)
		if !ok {
			return nil, fmt.Errorf("release: profile %q enables unknown harness %q (registered: %v)", profileName, name, harness.Names())
		}
		spec := prof.Harnesses[name]
		he := HarnessEntry{Version: spec.Version, InstallCommand: map[string]string{}, Files: map[string][]FileEntry{}}
		for _, os := range oses {
			files, warns, err := ad.Render(prof, harness.Context{
				Gateway: opts.Gateway, Ring: ringName, Release: opts.Version, OS: os, Experiment: opts.Experiment, Variant: opts.Variant,
			})
			if err != nil {
				return nil, fmt.Errorf("release: render %s for %s: %w", name, os, err)
			}
			if err := CheckRendered(name, os, files, prof, opts.Gateway); err != nil {
				return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
			}
			for _, w := range warns {
				m.Warnings = append(m.Warnings, fmt.Sprintf("%s/%s: %s", name, os, w))
			}
			if spec.Version != "" {
				he.InstallCommand[string(os)] = ad.InstallCommand(spec.Version, os)
			}
			entries := make([]FileEntry, 0, len(files))
			for _, f := range files {
				sum := sha256.Sum256(f.Data)
				h := hex.EncodeToString(sum[:])
				blobs[h] = f.Data
				entries = append(entries, FileEntry{Path: f.Path, Mode: f.Mode, SHA256: h})
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
			he.Files[string(os)] = entries
		}
		m.Harnesses[name] = he
	}
	sort.Strings(m.Warnings)
	return pack(m, blobs)
}

func pack(m Manifest, blobs map[string][]byte) (*Release, error) {
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("release: marshal manifest: %w", err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write("manifest.json", mj); err != nil {
		return nil, fmt.Errorf("release: write tar: %w", err)
	}
	keys := make([]string, 0, len(blobs))
	for k := range blobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := write("blobs/"+k, blobs[k]); err != nil {
			return nil, fmt.Errorf("release: write tar: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("release: close tar: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return &Release{Manifest: m, Blobs: blobs, Tar: buf.Bytes(), Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// maxBundle caps what Open will read, guarding against decompression-style abuse.
const maxBundle = 256 << 20

// Open parses a bundle tar and verifies every blob against its name and every
// manifest entry against a blob. It does NOT verify signatures; see internal/bundle.
func Open(tarData []byte) (*Release, error) {
	tr := tar.NewReader(bytes.NewReader(tarData))
	var mj []byte
	blobs := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release: read tar: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxBundle))
		if err != nil {
			return nil, fmt.Errorf("release: read %s: %w", h.Name, err)
		}
		switch {
		case h.Name == "manifest.json":
			mj = data
		case strings.HasPrefix(h.Name, "blobs/"):
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != strings.TrimPrefix(h.Name, "blobs/") {
				return nil, fmt.Errorf("release: blob %s content does not match its name", h.Name)
			}
			blobs[strings.TrimPrefix(h.Name, "blobs/")] = data
		default:
			return nil, fmt.Errorf("release: unexpected tar entry %q", h.Name)
		}
	}
	if mj == nil {
		return nil, fmt.Errorf("release: bundle has no manifest.json")
	}
	var m Manifest
	if err := json.Unmarshal(mj, &m); err != nil {
		return nil, fmt.Errorf("release: parse manifest: %w", err)
	}
	if m.SchemaVersion != 1 {
		return nil, fmt.Errorf("release: unsupported manifest schemaVersion %d", m.SchemaVersion)
	}
	for hn, he := range m.Harnesses {
		for os, fs := range he.Files {
			for _, f := range fs {
				if _, ok := blobs[f.SHA256]; !ok {
					return nil, fmt.Errorf("release: manifest %s/%s file %s references missing blob %s", hn, os, f.Path, f.SHA256)
				}
			}
		}
	}
	sum := sha256.Sum256(tarData)
	return &Release{Manifest: m, Blobs: blobs, Tar: tarData, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
