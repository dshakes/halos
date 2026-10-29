package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/supplychain"
)

// SupplyChainEntry is one extension artifact in a release manifest (ADR-0028).
type SupplyChainEntry struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	// Digest is supplychain.DigestOf(Files): the content pin.
	Digest string `json:"digest"`
	// Signer is the trusted identity whose signature over Digest verified at
	// build time, if the artifact is signed.
	Signer string `json:"signer,omitempty"`
	// Files is the listing the digest covers: path in the artifact -> sha256
	// hex. Empty when the content was not resolved (nothing is delivered).
	Files map[string]string `json:"files,omitempty"`
}

// supplyChainEntries pins p's resolved artifacts, failing on content that
// does not match the digest policy pinned.
func supplyChainEntries(p *policy.Profile) ([]SupplyChainEntry, error) {
	var out []SupplyChainEntry
	for _, a := range p.Resolved {
		e := SupplyChainEntry{Name: a.Name, Kind: a.Kind, Source: a.Source, Digest: a.Digest, Signer: a.Signer}
		if a.Files != nil {
			if err := a.Files.Check(); err != nil {
				return nil, fmt.Errorf("artifact %s: %w", a.Name, err)
			}
			got := a.Files.Digest()
			if a.Digest != "" && got != a.Digest {
				return nil, fmt.Errorf("artifact %s (%s): content digest %s does not match the pinned %s", a.Name, a.Source, got, a.Digest)
			}
			e.Digest, e.Files = got, a.Files.Sums()
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Artifact returns the supply-chain entry named name.
func (m Manifest) Artifact(name string) (SupplyChainEntry, bool) {
	i := slices.IndexFunc(m.SupplyChain, func(e SupplyChainEntry) bool { return e.Name == name })
	if i < 0 {
		return SupplyChainEntry{}, false
	}
	return m.SupplyChain[i], true
}

// CheckArtifactFile is what halod runs before writing an artifact file: the
// artifact's listing must hash to its pinned digest and list f's path with
// f's hash, and data (when non-nil) must hash to that too.
func (m Manifest) CheckArtifactFile(f FileEntry, data []byte) error {
	if f.Artifact == "" {
		return nil
	}
	e, ok := m.Artifact(f.Artifact)
	if !ok {
		return fmt.Errorf("supply chain: %s claims artifact %q, which the manifest does not pin", f.Path, f.Artifact)
	}
	if got := supplychain.DigestOf(e.Files); len(e.Files) == 0 || got != e.Digest {
		return fmt.Errorf("supply chain: artifact %s listing hashes to %s, not its pinned digest %s", e.Name, got, e.Digest)
	}
	if want, ok := e.Files[f.ArtifactPath]; !ok || want != f.SHA256 {
		return fmt.Errorf("supply chain: %s is not artifact %s's %q (sha256 %s)", f.Path, e.Name, f.ArtifactPath, f.SHA256)
	}
	if data != nil {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("supply chain: %s content does not hash to %s", f.Path, f.SHA256)
		}
	}
	return nil
}

// CheckArtifactFiles runs CheckArtifactFile (without content) over every
// artifact file the manifest delivers: harness, unit and toggle files.
func (m Manifest) CheckArtifactFiles() error {
	check := func(byOS map[string][]FileEntry) error {
		for _, fs := range byOS {
			for _, f := range fs {
				if err := m.CheckArtifactFile(f, nil); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, he := range m.Harnesses {
		if err := check(he.Files); err != nil {
			return err
		}
	}
	for _, u := range m.Units {
		for _, byOS := range u.Files {
			if err := check(byOS); err != nil {
				return err
			}
		}
	}
	for _, t := range m.Toggles {
		for _, byOS := range t.Fragments {
			if err := check(byOS); err != nil {
				return err
			}
		}
	}
	return nil
}
