// Package fsutil holds small filesystem helpers shared across commands.
package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// WriteAtomic writes data to path so a reader sees either the old or the new
// content, never a partial file: temp file in the same directory, fsync,
// chmod perm, rename, fsync the directory. The directory must exist.
func WriteAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".halo-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           // best effort: already failing
			_ = os.Remove(tmp.Name()) // best effort: already failing
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		return nil // directories cannot be fsynced on Windows
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }() // read-only handle
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	return nil
}

// ExistingPerm returns path's permission bits, or def when it cannot be stat'd.
// Use with WriteAtomic to keep an existing file's mode.
func ExistingPerm(path string, def fs.FileMode) fs.FileMode {
	if st, err := os.Stat(path); err == nil {
		return st.Mode().Perm()
	}
	return def
}
