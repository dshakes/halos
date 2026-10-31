package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLocked means another process holds the directory's lock.
var ErrLocked = errors.New("directory is in use by another process")

// DirLock is an exclusive advisory lock on a directory, held through a file in
// it for as long as the process lives or until Close. The operating system
// drops it when the process dies, so a crash never leaves a stale lock.
type DirLock struct{ f *os.File }

// LockDir takes the exclusive lock on dir (created if absent) via dir/.lock,
// without waiting. It returns an error wrapping ErrLocked if another process
// (or another LockDir in this one) holds it.
func LockDir(dir string) (*DirLock, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &DirLock{f}, nil
}

// Close releases the lock. It is safe to call twice.
func (l *DirLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return f.Close() // closing the descriptor releases the lock
}
