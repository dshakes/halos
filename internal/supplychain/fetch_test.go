package supplychain

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
)

// gitRepo makes a repository with one commit holding files and returns its
// file:// URL and commit id.
func gitRepo(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	d := t.TempDir()
	for p, s := range files {
		write(t, filepath.Join(d, filepath.FromSlash(p)), s)
	}
	run := func(args ...string) string {
		out, err := execGit(context.Background(), d, args...)
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	run("add", "-A")
	run("-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x")
	return "file://" + filepath.ToSlash(d), run("rev-parse", "HEAD")
}

func TestFetchGit(t *testing.T) {
	url, commit := gitRepo(t, map[string]string{"skills/s/SKILL.md": "# s\n", "README.md": "r\n"})
	ctx := context.Background()
	tr, err := FetchGit(ctx, url, commit, "skills/s", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Tree{"SKILL.md": []byte("# s\n")}).Digest(); tr.Digest() != want {
		t.Fatalf("digest %s, want %s", tr.Digest(), want)
	}
	if _, err := FetchGit(ctx, url, "main", "", nil); err == nil || !strings.Contains(err.Error(), "not a full object id") {
		t.Fatalf("branch accepted as a pin: %v", err)
	}
	if _, err := FetchGit(ctx, url, strings.Repeat("0", 40), "", nil); err == nil {
		t.Fatal("unknown commit fetched")
	}
	if _, err := FetchGit(ctx, url, commit, "../x", nil); err == nil {
		t.Fatal("escaping sub path accepted")
	}
	// A checkout that is not the pinned commit is refused.
	lie := func(ctx context.Context, dir string, args ...string) ([]byte, error) {
		if args[0] == "rev-parse" {
			return []byte(strings.Repeat("1", 40) + "\n"), nil
		}
		return execGit(ctx, dir, args...)
	}
	if _, err := FetchGit(ctx, url, commit, "", lie); err == nil || !strings.Contains(err.Error(), "checked out") {
		t.Fatalf("moved checkout accepted: %v", err)
	}
}

func TestSplitOCIRef(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	repo, dg, err := SplitOCIRef("ghcr.io/acme/skills@" + d)
	if err != nil || repo != "ghcr.io/acme/skills" || dg != d {
		t.Fatalf("got %q %q %v", repo, dg, err)
	}
	for _, bad := range []string{"ghcr.io/acme/skills:v1", "ghcr.io/acme/skills@sha256:abc", "skills@" + d, "GHCR.io/a@" + d} {
		if _, _, err := SplitOCIRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// pushOCI stores files as an oras-style artifact (one titled layer each).
func pushOCI(t *testing.T, s *memory.Store, files map[string]string, ann map[string]string) string {
	t.Helper()
	ctx := context.Background()
	var layers []ocispec.Descriptor
	for name, data := range files {
		d := content.NewDescriptorFromBytes("application/octet-stream", []byte(data))
		d.Annotations = map[string]string{ocispec.AnnotationTitle: name}
		for k, v := range ann {
			d.Annotations[k] = v
		}
		if err := s.Push(ctx, d, strings.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		layers = append(layers, d)
	}
	m, err := oras.PackManifest(ctx, s, oras.PackManifestVersion1_1, "application/vnd.acme.skill", oras.PackManifestOptions{Layers: layers})
	if err != nil {
		t.Fatal(err)
	}
	// A registry resolves a digest reference; the memory store only resolves
	// tags, so tag the manifest with its own digest.
	if err := s.Tag(ctx, m, m.Digest.String()); err != nil {
		t.Fatal(err)
	}
	return m.Digest.String()
}

func TestFetchOCI(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	dg := pushOCI(t, s, map[string]string{"SKILL.md": "# s\n", "ref.md": "r\n"}, nil)
	tr, err := FetchOCI(ctx, s, dg)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Tree{"SKILL.md": []byte("# s\n"), "ref.md": []byte("r\n")}).Digest(); tr.Digest() != want {
		t.Fatalf("digest %s, want %s", tr.Digest(), want)
	}
	if _, err := FetchOCI(ctx, s, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("missing manifest fetched")
	}
	packed := pushOCI(t, s, map[string]string{"dir": "tgz"}, map[string]string{"io.deis.oras.content.unpack": "true"})
	if _, err := FetchOCI(ctx, s, packed); err == nil || !strings.Contains(err.Error(), "packed directory") {
		t.Fatalf("packed directory accepted: %v", err)
	}
	escape := pushOCI(t, s, map[string]string{"../evil": "x"}, nil)
	if _, err := FetchOCI(ctx, s, escape); err == nil {
		t.Fatal("escaping layer title accepted")
	}
}

// tamperTarget serves every layer blob with one byte flipped.
type tamperTarget struct{ *memory.Store }

func (t tamperTarget) Fetch(ctx context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := t.Store.Fetch(ctx, d)
	if err != nil || d.MediaType != "application/octet-stream" {
		return rc, err
	}
	b, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	b[0] ^= 1
	return io.NopCloser(bytes.NewReader(b)), nil
}

// A registry that serves a layer whose bytes do not match its digest is refused.
func TestFetchOCITamperedLayer(t *testing.T) {
	s := memory.New()
	dg := pushOCI(t, s, map[string]string{"SKILL.md": "# s\n"}, nil)
	if _, err := FetchOCI(context.Background(), tamperTarget{s}, dg); err == nil {
		t.Fatal("tampered layer fetched")
	}
}
