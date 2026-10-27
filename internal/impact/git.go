package impact

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dshakes/halos/internal/promote"
)

// maxArchive bounds a base policy checkout; policy repos are YAML and small.
const maxArchive = 64 << 20

// CheckoutAt writes the policy dir as it is at git ref base into a new temp
// dir (git archive: the working tree, index and HEAD are never touched) and
// returns it with a cleanup func.
func CheckoutAt(ctx context.Context, dir, base string) (string, func(), error) {
	if base == "" || strings.HasPrefix(base, "-") || strings.ContainsAny(base, " \t\n:") {
		return "", nil, fmt.Errorf("--diff %q: want a git ref (branch, tag or commit)", base)
	}
	out, err := promote.Run(ctx, dir, "git", "rev-parse", "--show-toplevel", "--show-prefix")
	if err != nil {
		return "", nil, fmt.Errorf("--diff needs the policy dir inside a git checkout: %w", err)
	}
	top, prefix, _ := strings.Cut(strings.TrimRight(string(out), "\n"), "\n")
	tree := base
	if prefix = strings.TrimSpace(prefix); prefix != "" {
		tree += ":" + prefix
	}
	// From the top level: in a subdirectory, git archive limits itself to it.
	b, err := promote.Run(ctx, strings.TrimSpace(top), "git", "archive", "--format=tar", tree)
	if err != nil {
		return "", nil, fmt.Errorf("read policy at %s: %w", base, err)
	}
	tmp, err := os.MkdirTemp("", "halo-plan-base-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if err := untar(bytes.NewReader(b), tmp); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("read policy at %s: %w", base, err)
	}
	return tmp, cleanup, nil
}

// untar writes regular files and directories only; any path leaving dst is
// refused.
func untar(r io.Reader, dst string) error {
	tr := tar.NewReader(r)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(h.Name)
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("archive entry %q leaves the checkout", h.Name)
		}
		p := filepath.Join(dst, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; total > maxArchive {
				return fmt.Errorf("policy archive larger than %d bytes", maxArchive)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				return err
			}
			f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, werr := io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				return werr
			}
		}
	}
}
