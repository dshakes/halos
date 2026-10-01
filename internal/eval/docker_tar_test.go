package eval

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestParseUser(t *testing.T) {
	for _, tc := range []struct {
		in       string
		uid, gid int
		wantErr  bool
	}{
		{"1000:1000", 1000, 1000, false},
		{"1000", 1000, 1000, false},
		{"7:9", 7, 9, false},
		{"eval", 0, 0, true},
		{"1000:eval", 0, 0, true},
		{"", 0, 0, true},
	} {
		uid, gid, err := parseUser(tc.in)
		if (err != nil) != tc.wantErr || uid != tc.uid || gid != tc.gid {
			t.Errorf("parseUser(%q) = %d,%d,%v", tc.in, uid, gid, err)
		}
	}
}

func TestTarDirOwnership(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "sub", "a.go"), []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.go", filepath.Join(d, "sub", "ln")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tarDir(&buf, d, 1000, 1001); err != nil {
		t.Fatal(err)
	}
	got := map[string]*tar.Header{}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = h
	}
	for _, n := range []string{"sub/", "sub/a.go", "sub/ln"} {
		h := got[n]
		if h == nil {
			t.Fatalf("missing %q in %v", n, got)
		}
		if h.Uid != 1000 || h.Gid != 1001 {
			t.Errorf("%s owner %d:%d, want 1000:1001", n, h.Uid, h.Gid)
		}
	}
	if got["sub/ln"].Linkname != "a.go" {
		t.Errorf("symlink target %q", got["sub/ln"].Linkname)
	}
}

func TestTarDirMissing(t *testing.T) {
	if err := tarDir(io.Discard, filepath.Join(t.TempDir(), "nope"), 1, 1); err == nil {
		t.Fatal("want error for missing dir")
	}
}

// A symlink pointing outside the task tree is copied as a link, never followed:
// the secret's bytes must not appear anywhere in the tar.
func TestTarDirNeverFollowsEscapingSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "credentials")
	secret := []byte("aws_secret_access_key=do-not-copy")
	if err := os.WriteFile(outside, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(d, "creds")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tarDir(&buf, d, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatal("tar contains the target of an escaping symlink")
	}
}
