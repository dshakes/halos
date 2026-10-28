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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/cloudagents/workflow"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
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
	// Artifact/ArtifactPath tie the file to a Manifest.SupplyChain entry and
	// its path inside it; halod checks both before writing (ADR-0028).
	Artifact     string `json:"artifact,omitempty"`
	ArtifactPath string `json:"artifactPath,omitempty"`
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
	// Toggles are the client-axis feature toggles: targeting rules plus the
	// per-harness fragments halod merges for the toggles that are on for it.
	Toggles []ToggleEntry `json:"toggles,omitempty"`
	// Units are the org units (ADR-0018): member selectors plus each unit's
	// rendered files, which halod applies in place of the release's own.
	Units []UnitEntry `json:"units,omitempty"`
	// RemoteAgents pins the A2A agents this ring's members (or some of its
	// units' members) may call, with each AgentCard's digest (ADR-0024):
	// signed with the release, so a changed card is a policy change.
	RemoteAgents []RemoteAgentEntry `json:"remoteAgents,omitempty"`
	// SupplyChain pins the extension artifacts this release delivers
	// (ADR-0028): each one's digest and file listing, signed with the release.
	SupplyChain []SupplyChainEntry `json:"supplyChain,omitempty"`
	// MCPMode and MCPServers carry the halos.yaml mcp registry (ADR-0029):
	// its mode and the servers ring's members (or some of its units' members)
	// get, pinned, so halod reports unapproved and version-drifted servers in
	// user configs. Empty when the policy has no registry.
	MCPMode    string          `json:"mcpMode,omitempty"`
	MCPServers []policy.MCPPin `json:"mcpServers,omitempty"`
	// CloudAgents are the repository files of the workflow-configured cloud
	// agents (ADR-0034), signed with the release for review and the PR that
	// adds them. halod never writes them: they belong in repositories.
	CloudAgents []CloudAgentFile `json:"cloudAgents,omitempty"`
}

// CloudAgentFile is one rendered cloud agent repository file.
type CloudAgentFile struct {
	Vendor string   `json:"vendor"`
	Path   string   `json:"path"` // relative to the repository root
	SHA256 string   `json:"sha256"`
	Repos  []string `json:"repos,omitempty"` // policy repo patterns it is for
}

// RemoteAgentEntry is one allowlisted remote agent in a release manifest.
type RemoteAgentEntry struct {
	Name    string   `json:"name"`
	CardURL string   `json:"cardURL"`
	Digest  string   `json:"digest"`
	Skills  []string `json:"skills,omitempty"`
	// Units, when set, are the only units (and units below them) whose
	// members may call it; empty = every member of the ring.
	Units []string `json:"units,omitempty"`
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
	// Attestations (AI-BOM and provenance, see Attest) describe the release
	// by digest; they are not part of Tar. bundle.Publish stores them as a
	// signed OCI referrer when set.
	Attestations *Attestations
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
		if prof, err = o.WithMCPRegistry(prof, ringName, ""); err != nil {
			return nil, fmt.Errorf("release: profile %q: mcp registry: %w", profileName, err)
		}
	}
	oses := opts.OSes
	if len(oses) == 0 {
		oses = allOSes
	}
	var org0 *policy.Org
	if o, ok := org.(*policy.Org); ok {
		org0 = o
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
	toggles := newToggleBuild(org0, &m)
	units, err := newUnitBuild(org0, prof, &m)
	if err != nil {
		return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
	}
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
			if org0 != nil {
				if err := toggles.add(org0, ad, prof, os, files, warns, opts, blobs); err != nil {
					return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
				}
			}
			if err := units.add(ad, os, files, warns, opts, blobs); err != nil {
				return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
			}
			entries := make([]FileEntry, 0, len(files))
			for _, f := range files {
				sum := sha256.Sum256(f.Data)
				h := hex.EncodeToString(sum[:])
				blobs[h] = f.Data
				entries = append(entries, FileEntry{Path: f.Path, Mode: f.Mode, SHA256: h, Artifact: f.Artifact, ArtifactPath: f.ArtifactPath})
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
			he.Files[string(os)] = entries
		}
		m.Harnesses[name] = he
	}
	toggles.finish()
	units.finish()
	if m.SupplyChain, err = supplyChainEntries(prof); err != nil {
		return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
	}
	if err := m.CheckArtifactFiles(); err != nil {
		return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
	}
	m.RemoteAgents = remoteAgents(org0, prof, ringName)
	if org0 != nil && org0.MCP != nil {
		m.MCPMode, m.MCPServers = policy.MCPModeAllowlist, org0.MCP.MCPPins(ringName)
		if !org0.MCP.Allowlist() {
			m.MCPMode = policy.MCPModeWarn
		}
	}
	if org0 != nil {
		files, warns, err := workflow.Render(org0)
		if err != nil {
			return nil, fmt.Errorf("release: profile %q: %w", profileName, err)
		}
		for _, f := range files {
			sum := sha256.Sum256(f.Data)
			h := hex.EncodeToString(sum[:])
			blobs[h] = f.Data
			m.CloudAgents = append(m.CloudAgents, CloudAgentFile{Vendor: f.Vendor, Path: f.Path, SHA256: h, Repos: f.Repos})
		}
		for _, w := range warns {
			m.Warnings = append(m.Warnings, "cloudAgents."+w)
		}
	}
	if len(m.RemoteAgents) > 0 {
		for _, name := range names {
			m.Warnings = append(m.Warnings, name+": "+remoteAgentsWarning(name))
		}
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

// Open parses a bundle tar and verifies every blob against its name and every
// manifest entry against a blob. It does NOT verify signatures; see internal/bundle.
// Only regular files are accepted, and since the tar is uncompressed no entry
// may yield more bytes than the tar itself holds: archive/tar expands PAX/GNU
// sparse entries, so a few KiB could otherwise decode to gigabytes.
func Open(tarData []byte) (*Release, error) {
	tr := tar.NewReader(bytes.NewReader(tarData))
	var mj []byte
	blobs := map[string][]byte{}
	budget := int64(len(tarData))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release: read tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("release: tar entry %q is not a regular file (type %q)", h.Name, h.Typeflag)
		}
		if h.Size > budget {
			return nil, fmt.Errorf("release: tar entry %q expands to %d bytes, more than the %d-byte bundle holds", h.Name, h.Size, len(tarData))
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, fmt.Errorf("release: read %s: %w", h.Name, err)
		}
		budget -= int64(len(data))
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
	for _, t := range m.Toggles {
		for hn, byOS := range t.Fragments {
			for os, fs := range byOS {
				for _, f := range fs {
					if _, ok := blobs[f.SHA256]; !ok {
						return nil, fmt.Errorf("release: manifest toggle %s/%s/%s file %s references missing blob %s", t.Name, hn, os, f.Path, f.SHA256)
					}
				}
			}
		}
	}
	for _, f := range m.CloudAgents {
		if _, ok := blobs[f.SHA256]; !ok {
			return nil, fmt.Errorf("release: manifest cloud agent %s file %s references missing blob %s", f.Vendor, f.Path, f.SHA256)
		}
	}
	sum := sha256.Sum256(tarData)
	return &Release{Manifest: m, Blobs: blobs, Tar: tarData, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// remoteAgents lists the agents.remote entries ring's members may call: the
// ring is listed, or some unit is (whose members then may), narrowed by the
// profile's agents.remote.
func remoteAgents(org *policy.Org, prof *policy.Profile, ring string) []RemoteAgentEntry {
	if org == nil || org.Agents == nil {
		return nil
	}
	var out []RemoteAgentEntry
	for _, ra := range org.Agents.Remote {
		if len(prof.Agents.Remote) > 0 && !slices.Contains(prof.Agents.Remote, ra.Name) {
			continue
		}
		e := RemoteAgentEntry{Name: ra.Name, CardURL: ra.CardURL, Digest: ra.Digest, Skills: ra.Skills}
		switch {
		case ring != "" && slices.Contains(ra.Rings, ring):
		case len(ra.Units) > 0:
			e.Units = ra.Units
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}

// remoteAgentsWarning explains, per harness, why agents.remote is not
// rendered (invariant 2: warn, never drop silently). Checked against each
// CLI's documentation (ADR-0024): only Gemini CLI documents A2A remote agents,
// and only as per-user or per-project files.
func remoteAgentsWarning(h string) string {
	const enforce = "enforce the allowlist with POST /api/v1/agents/egress at the egress proxy, and the pinned card digests in this manifest"
	if h == "gemini-cli" {
		return "agents.remote is not rendered: Gemini CLI defines remote A2A subagents only in per-user and per-project agents/*.md files (kind: remote), with no system-level allowlist; " +
			"experimental.enableAgents: false (harnesses.gemini-cli.overrides) turns off every subagent; " + enforce
	}
	return "agents.remote is not rendered: the CLI documents no A2A or remote-agent setting; " + enforce
}
