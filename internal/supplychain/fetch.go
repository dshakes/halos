package supplychain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
)

var (
	// CommitRe is a full git object id (SHA-1 or SHA-256 repositories).
	CommitRe = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	// OCIRefRe is a digest-pinned OCI reference: host/repo@sha256:<hex>.
	OCIRefRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.:-]*[a-z0-9])?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$`)
)

// GitRunner runs git with args in dir; injectable for tests.
type GitRunner func(ctx context.Context, dir string, args ...string) ([]byte, error)

func execGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.CombinedOutput()
}

// FetchGit fetches exactly commit from url (shallow) and reads sub ("" = the
// whole repository) from it. The checkout is verified to be commit, so a
// moved branch or tag can never stand in for the pin.
func FetchGit(ctx context.Context, url, commit, sub string, run GitRunner) (Tree, error) {
	if !CommitRe.MatchString(commit) {
		return nil, fmt.Errorf("git commit %q is not a full object id; branches and tags are not pins", commit)
	}
	if sub != "" {
		if err := CheckPath(sub); err != nil {
			return nil, err
		}
	}
	if run == nil {
		run = execGit
	}
	dir, err := os.MkdirTemp("", "halo-artifact-git-")
	if err != nil {
		return nil, fmt.Errorf("git temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }() // best effort
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth=1", "--no-tags", url, commit},
		{"-c", "advice.detachedHead=false", "checkout", "-q", "--detach", "FETCH_HEAD"},
	} {
		if out, err := run(ctx, dir, args...); err != nil {
			return nil, fmt.Errorf("git %s %s: %w: %s", args[0], url, err, strings.TrimSpace(string(out)))
		}
	}
	head, err := run(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("git rev-parse: %w: %s", err, head)
	}
	if got := strings.TrimSpace(string(head)); got != commit {
		return nil, fmt.Errorf("git %s checked out %s, want %s", url, got, commit)
	}
	t, err := ReadPath(filepath.Join(dir, filepath.FromSlash(sub)))
	if err != nil {
		return nil, fmt.Errorf("git %s@%s: %w", url, commit, err)
	}
	return t, nil
}

// SplitOCIRef splits a digest-pinned "host/repo@sha256:..." reference.
func SplitOCIRef(ref string) (repo, dgst string, err error) {
	if !OCIRefRe.MatchString(ref) {
		return "", "", fmt.Errorf("oci reference %q must be pinned by digest (host/repo@sha256:<64 hex>); tags are not pins", ref)
	}
	i := strings.LastIndex(ref, "@")
	return ref[:i], ref[i+1:], nil
}

const maxOCIManifest = 1 << 20

// FetchOCI reads the artifact whose OCI manifest has digest dgst from src.
// Each layer is one file named by its org.opencontainers.image.title
// annotation, which is what `oras push <ref> <file>...` writes. Every blob is
// digest-verified as it is read. ponytail: directory layers (oras push of a
// directory, a tar+gzip blob) are refused; push the files instead.
func FetchOCI(ctx context.Context, src oras.ReadOnlyTarget, dgst string) (Tree, error) {
	d, err := digest.Parse(dgst)
	if err != nil {
		return nil, fmt.Errorf("oci digest %q: %w", dgst, err)
	}
	desc, err := src.Resolve(ctx, dgst)
	if err != nil {
		return nil, fmt.Errorf("oci resolve %s: %w", dgst, err)
	}
	if desc.Digest != d || desc.Size <= 0 || desc.Size > maxOCIManifest {
		return nil, fmt.Errorf("oci %s: resolved to %s (%d bytes)", dgst, desc.Digest, desc.Size)
	}
	mb, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, fmt.Errorf("oci fetch manifest %s: %w", dgst, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return nil, fmt.Errorf("oci parse manifest %s: %w", dgst, err)
	}
	t := Tree{}
	var total int64
	for _, l := range m.Layers {
		name := l.Annotations[ocispec.AnnotationTitle]
		if l.Annotations["io.deis.oras.content.unpack"] == "true" {
			return nil, fmt.Errorf("oci %s: layer %s is a packed directory; push each file as its own layer", dgst, name)
		}
		if err := CheckPath(name); err != nil {
			return nil, fmt.Errorf("oci %s: layer %s title: %w", dgst, l.Digest, err)
		}
		if _, dup := t[name]; dup {
			return nil, fmt.Errorf("oci %s: two layers are titled %s", dgst, name)
		}
		if total += l.Size; l.Size < 0 || total > MaxBytes || len(t) >= MaxFiles {
			return nil, fmt.Errorf("oci %s exceeds the artifact limits (%d files, %d bytes)", dgst, MaxFiles, MaxBytes)
		}
		b, err := content.FetchAll(ctx, src, l) // verifies size and digest
		if err != nil {
			return nil, fmt.Errorf("oci %s: fetch %s: %w", dgst, name, err)
		}
		t[name] = b
	}
	if err := t.Check(); err != nil {
		return nil, fmt.Errorf("oci %s: %w", dgst, err)
	}
	return t, nil
}
