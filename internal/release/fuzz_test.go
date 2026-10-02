package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// FuzzOpen: the bundle tar and its manifest are untrusted until the signature
// over the tar is checked, and Open runs on every pull. For any input it must
// not panic, must never hold more blob bytes than the tar itself, and when it
// accepts a bundle every manifest file must resolve to a blob whose sha256 is
// its name. A built release must round-trip.
func FuzzOpen(f *testing.F) {
	rel, err := Build(resolver{p: prof("1.0.0", "fake")}, "p", "canary", Options{Version: "1", Org: "acme"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(rel.Tar)
	empty := sha256.Sum256(nil)
	manifest := regEntry("manifest.json", []byte(`{"schemaVersion":1}`))
	trailer := make([]byte, 1024)
	f.Add(append(append(append([]byte{}, manifest...), regEntry("blobs/"+hex.EncodeToString(empty[:]), nil)...), trailer...))
	f.Add(append(append(append([]byte{}, manifest...), sparseEntry("blobs/"+hex.EncodeToString(empty[:]), 1<<20)...), trailer...))
	f.Add(regEntry("manifest.json", []byte(`{"schemaVersion":2}`)))
	f.Add(regEntry("blobs/../x", []byte("x")))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		r, err := Open(data)
		if err != nil {
			return
		}
		if !bytes.Equal(r.Tar, data) {
			t.Fatal("Open returned a tar other than its input")
		}
		sum := sha256.Sum256(data)
		if r.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("digest %s is not the sha256 of the input", r.Digest)
		}
		held := 0
		for name, b := range r.Blobs {
			held += len(b)
			s := sha256.Sum256(b)
			if hex.EncodeToString(s[:]) != name {
				t.Fatalf("blob %s does not hash to its name", name)
			}
		}
		if held > len(data) {
			t.Fatalf("blobs hold %d bytes, tar is %d", held, len(data))
		}
		if r.Manifest.SchemaVersion != 1 {
			t.Fatalf("accepted schemaVersion %d", r.Manifest.SchemaVersion)
		}
		for hn, he := range r.Manifest.Harnesses {
			for os, fs := range he.Files {
				for _, fe := range fs {
					if _, ok := r.Blobs[fe.SHA256]; !ok {
						t.Fatalf("%s/%s %s references missing blob", hn, os, fe.Path)
					}
				}
			}
		}
		if bytes.Equal(data, rel.Tar) {
			mj, _ := json.Marshal(r.Manifest)
			want, _ := json.Marshal(rel.Manifest)
			if !bytes.Equal(mj, want) {
				t.Fatal("built release did not round-trip")
			}
		}
	})
}
