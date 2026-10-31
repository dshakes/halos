//go:build !windows

package fsutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockFile takes a non-blocking exclusive flock (the lock follows the open file
// description, so a second open in the same process also conflicts).
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // fd fits int
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return fmt.Errorf("%w (is another halo-server running on it?)", ErrLocked)
		default:
			return err
		}
	}
}
