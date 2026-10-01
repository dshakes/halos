//go:build !windows

package fsutil

import (
	"fmt"
	"os"
)

// RestrictToOwner is a no-op here: the 0600 mode the caller creates files with
// already is owner-only. (Windows replaces the DACL.)
func RestrictToOwner(string) error { return nil }

// VerifyPrivate reports whether group and other have no access to path.
func VerifyPrivate(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; want no group/other access", path, m)
	}
	return nil
}
