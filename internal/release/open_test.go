package release

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// rawTarHeader builds one ustar header block by hand, so tests can emit
// entries archive/tar.Writer refuses to write (PAX sparse maps).
func rawTarHeader(name string, size int, flag byte) []byte {
	b := make([]byte, 512)
	copy(b, name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	b[156] = flag
	copy(b[257:], "ustar\x0000")
	copy(b[148:], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func tarPad(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

func paxRecord(k, v string) string {
	s := " " + k + "=" + v + "\n"
	for n := len(s); ; {
		t := fmt.Sprintf("%d%s", n, s)
		if len(t) == n {
			return t
		}
		n = len(t)
	}
}

// sparseEntry is a PAX 1.0 sparse file: a few hundred bytes in the tar that
// archive/tar expands to realSize zero bytes on read.
func sparseEntry(name string, realSize int) []byte {
	pax := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", name) + paxRecord("GNU.sparse.realsize", fmt.Sprint(realSize))
	out := append(rawTarHeader("PaxHeaders/x", len(pax), tar.TypeXHeader), tarPad([]byte(pax))...)
	data := tarPad([]byte("0\n")) // sparse map with no data regions: all holes
	out = append(out, rawTarHeader("x", len(data), tar.TypeReg)...)
	return append(out, data...)
}

func regEntry(name string, data []byte) []byte {
	return append(rawTarHeader(name, len(data), tar.TypeReg), tarPad(data)...)
}

// TestOpenRefusesExpansionAndLinks: the bundle tar is uncompressed, so no
// entry may yield more bytes than the tar holds (a PAX sparse entry is a
// decompression bomb: ~3 KiB in, realsize zeros out), and only regular files
// are accepted (a symlink/hardlink entry named like an empty blob would
// otherwise pass the content-hash check).
func TestOpenRefusesExpansionAndLinks(t *testing.T) {
	manifest := regEntry("manifest.json", []byte(`{"schemaVersion":1}`))
	trailer := make([]byte, 1024)

	const real = 32 << 20
	sum := sha256.Sum256(make([]byte, real))
	bomb := append(append(append([]byte{}, manifest...), sparseEntry("blobs/"+hex.EncodeToString(sum[:]), real)...), trailer...)

	empty := sha256.Sum256(nil)
	var link bytes.Buffer
	tw := tar.NewWriter(&link)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(`{"schemaVersion":1}`))})
	_, _ = tw.Write([]byte(`{"schemaVersion":1}`))
	_ = tw.WriteHeader(&tar.Header{Name: "blobs/" + hex.EncodeToString(empty[:]), Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
	_ = tw.Close()

	var hard bytes.Buffer
	tw = tar.NewWriter(&hard)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(`{"schemaVersion":1}`))})
	_, _ = tw.Write([]byte(`{"schemaVersion":1}`))
	_ = tw.WriteHeader(&tar.Header{Name: "blobs/" + hex.EncodeToString(empty[:]), Typeflag: tar.TypeLink, Linkname: "manifest.json"})
	_ = tw.Close()

	tests := []struct {
		name string
		tar  []byte
		want string
	}{
		{"sparse bomb", bomb, "expands"},
		{"symlink entry", link.Bytes(), "not a regular file"},
		{"hardlink entry", hard.Bytes(), "not a regular file"},
		{"absolute path", append(append(append([]byte{}, manifest...), regEntry("/etc/passwd", nil)...), trailer...), "unexpected tar entry"},
		{"dot-dot path", append(append(append([]byte{}, manifest...), regEntry("blobs/../../x", nil)...), trailer...), "../../x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Open(tt.tar)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Open = %v, want error ~%q", err, tt.want)
			}
		})
	}
	// control: the same layout with real regular entries opens.
	ok := append(append(append([]byte{}, manifest...), regEntry("blobs/"+hex.EncodeToString(empty[:]), nil)...), trailer...)
	if _, err := Open(ok); err != nil {
		t.Fatalf("plain bundle refused: %v", err)
	}
}
