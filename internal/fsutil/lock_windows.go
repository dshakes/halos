//go:build windows

package fsutil

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes a non-blocking exclusive LockFileEx lock on the whole file.
func lockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION), errors.Is(err, windows.ERROR_IO_PENDING):
		return fmt.Errorf("%w (is another halo-server running on it?)", ErrLocked)
	}
	return err
}
