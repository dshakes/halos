package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SnapshotVersion identifies the envelope format written by Compile.
const SnapshotVersion = "halos.dev/snapshot/v1"

// snapshotEnvelope is what the gateway consumes: the org plus a format
// version and the sha256 of the compact org JSON, so a truncated or hand-edited
// file is rejected instead of silently routing traffic.
type snapshotEnvelope struct {
	Version string          `json:"version"`
	Digest  string          `json:"digest"` // "sha256:<hex>" over the compact Org JSON
	Org     json.RawMessage `json:"org"`
}

// Compile renders org as deterministic JSON (same input => same bytes: maps
// are key-sorted by encoding/json, no timestamps) for the gateway plane.
func Compile(org *Org) ([]byte, error) {
	if org == nil {
		return nil, fmt.Errorf("policy: compile snapshot: nil org")
	}
	ob, err := json.Marshal(org)
	if err != nil {
		return nil, fmt.Errorf("policy: compile snapshot for %q: %w", org.Name, err)
	}
	b, err := json.Marshal(snapshotEnvelope{Version: SnapshotVersion, Digest: digest(ob), Org: ob})
	if err != nil {
		return nil, fmt.Errorf("policy: compile snapshot for %q: %w", org.Name, err)
	}
	return append(b, '\n'), nil
}

// ParseSnapshot reads a Compile envelope (verifying version and digest) or,
// for backwards compatibility, a bare json.Marshal(*Org) document.
func ParseSnapshot(b []byte) (*Org, error) {
	var env snapshotEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("policy: parse snapshot: %w", err)
	}
	raw := b
	if env.Version != "" || env.Digest != "" {
		if env.Version != SnapshotVersion {
			return nil, fmt.Errorf("policy: snapshot version %q not supported (want %q)", env.Version, SnapshotVersion)
		}
		var c bytes.Buffer
		if err := json.Compact(&c, env.Org); err != nil {
			return nil, fmt.Errorf("policy: snapshot org: %w", err)
		}
		if got := digest(c.Bytes()); got != env.Digest {
			return nil, fmt.Errorf("policy: snapshot digest mismatch: file says %q, content is %q", env.Digest, got)
		}
		raw = env.Org
	}
	var o Org
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("policy: parse snapshot org: %w", err)
	}
	return &o, nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
