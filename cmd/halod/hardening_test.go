package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/harness"
)

// snapshot records every path under root with its mode and content.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		m[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// tamperTarget is a registry that serves altered bytes for the release
// (never the pointer): "layer" flips a byte of the layer; "manifest" swaps the
// release manifest's layer for an attacker's tar, keeping the signature.
type tamperTarget struct {
	oras.ReadOnlyTarget
	mode         string
	evil         ocispec.Descriptor
	layerFetches int
}

func (t *tamperTarget) Fetch(ctx context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := t.ReadOnlyTarget.Fetch(ctx, d)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	switch {
	case d.MediaType == bundle.LayerMediaType:
		t.layerFetches++
		if t.mode == "layer" {
			b[len(b)/2] ^= 1
		}
	case t.mode == "manifest" && d.MediaType == ocispec.MediaTypeImageManifest:
		var m ocispec.Manifest
		if json.Unmarshal(b, &m) == nil && m.ArtifactType == bundle.ArtifactType {
			m.Layers[0] = t.evil
			b, _ = json.Marshal(m)
		}
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// TestTamperedReleaseTouchesNothing: a registry serving a tampered layer, or
// a release manifest re-pointed at another tar with the original signature
// copied over, is refused before anything is parsed, executed or written:
// the managed files, binaries and state stay byte-identical.
func TestTamperedReleaseTouchesNothing(t *testing.T) {
	for _, mode := range []string{"layer", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			e.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}}, true)
			if _, err := e.a.Once(ctx); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, e.root)

			evilRel := e.publish(t, "2", "3.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`"evil"`)}}, true)
			evil := content.NewDescriptorFromBytes(bundle.LayerMediaType, append(evilRel.Tar, make([]byte, 512)...))
			if err := e.store.Push(ctx, evil, bytes.NewReader(append(evilRel.Tar, make([]byte, 512)...))); err != nil {
				t.Fatal(err)
			}
			tt := &tamperTarget{ReadOnlyTarget: e.store, mode: mode, evil: evil}
			e.a.Open = func(context.Context) (oras.ReadOnlyTarget, error) { return tt, nil }
			e.cmds = nil
			downloads := e.vendor.downloads.Load()

			st, err := e.a.Once(ctx)
			if err == nil || st.LastError == "" {
				t.Fatal("tampered release accepted")
			}
			if mode == "manifest" && tt.layerFetches != 0 {
				t.Fatalf("layer fetched for a manifest that failed its digest: %d", tt.layerFetches)
			}
			if len(e.cmds) != 0 || e.vendor.downloads.Load() != downloads {
				t.Fatalf("ran %v / downloaded for an unverified release", e.cmds)
			}
			after := snapshot(t, e.root)
			if len(after) != len(before) {
				t.Fatalf("files changed:\nbefore %v\nafter  %v", before, after)
			}
			for p, v := range before {
				if after[p] != v {
					t.Fatalf("%s changed: %q -> %q", p, v, after[p])
				}
			}
		})
	}
}

// TestUntrustedTargetReplacedNotAdopted: a managed file that already exists
// but is not trusted (group/other-writable here; a non-root owner is the same
// check) is replaced with a fresh root-owned file, never chmod-ed in place.
// Chmod would leave anyone who opened it while it was writable holding a
// writable descriptor to the live managed config.
func TestUntrustedTargetReplacedNotAdopted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	e := newEnv(t)
	e.a.Install = false
	ctx := context.Background()
	e.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}}, true)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.root, settings)
	want := e.read(settings)
	if err := os.Chmod(p, 0o666); err != nil { // as if planted world-writable
		t.Fatal(err)
	}
	fd, err := os.OpenFile(p, os.O_RDWR, 0) // the local user grabs a writable fd
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := fd.WriteAt([]byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`), 0); err != nil {
		t.Fatal(err)
	}
	if got := e.read(settings); got != want {
		t.Fatalf("managed file still writable through a pre-existing fd: %q", got)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
}
