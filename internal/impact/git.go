package impact

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/promote"
)

// maxArchive bounds a base policy checkout; policy repos are YAML and small.
var maxArchive int64 = 64 << 20 // var: tests lower it

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
	tmp, err := os.MkdirTemp("", "halo-plan-base-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if err := archiveTo(ctx, strings.TrimSpace(top), tree, tmp); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("read policy at %s: %w", base, err)
	}
	return tmp, cleanup, nil
}

// archiveTo streams `git archive tree` (run in top: in a subdirectory, git
// archive limits itself to it) into dst, so a large archive is refused at the
// cap instead of after buffering all of it. core.autocrlf=false and
// core.eol=lf keep the committed bytes: Git for Windows defaults to
// autocrlf=true, which would rewrite LF to CRLF and change every artifact
// digest and rendered file in the base.
func archiveTo(ctx context.Context, top, tree, dst string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops git if untar gives up early
	cmd := exec.CommandContext(ctx, "git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "archive", "--format=tar", tree)
	cmd.Dir = top
	// Killing the Git for Windows launcher can leave its child holding the
	// pipes; stop waiting for them once ctx is done.
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	uerr := untar(out, dst)
	if uerr == nil {
		// git pads the tar to a 10 KiB record past the end marker untar stops
		// at; read it, or git blocks on a small (Windows: 4 KiB) pipe forever.
		_, uerr = io.Copy(io.Discard, out)
	}
	if uerr != nil {
		cancel()
	}
	werr := cmd.Wait()
	if uerr != nil {
		return uerr
	}
	if werr != nil {
		return fmt.Errorf("git archive: %w: %s", werr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// capReader fails once more than n bytes have been read, and on every read
// after (io.ReadFull drops an error that comes with a full buffer).
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	tooBig := fmt.Errorf("policy archive larger than %d bytes", maxArchive)
	if c.n < 0 {
		return 0, tooBig
	}
	if int64(len(p)) > c.n+1 {
		p = p[:c.n+1]
	}
	n, err := c.r.Read(p)
	if c.n -= int64(n); c.n < 0 {
		return n, tooBig
	}
	return n, err
}

// untar writes regular files and directories only; any path leaving dst, or
// that is not local on this OS (a backslash or a drive or stream colon reads
// as a separator or volume on Windows), is refused. The stream (headers
// included) and the file contents are each capped at maxArchive.
func untar(r io.Reader, dst string) error {
	tr := tar.NewReader(&capReader{r: r, n: maxArchive})
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
		if strings.ContainsAny(h.Name, `\:`) || !filepath.IsLocal(filepath.FromSlash(name)) {
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
