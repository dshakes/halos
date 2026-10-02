//go:build !windows

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
)

// stateMode is state.json's mode: root-only.
const stateMode fs.FileMode = 0o600

// trustedUID is accepted as an owner in addition to root. It stays 0 in
// production; tests set it to their own uid.
var trustedUID uint32

// checkTrusted: owned by root, and (unless a symlink) not group/other
// writable. Root-owned sticky dirs (/tmp) are accepted: others can add entries
// there but not replace ours, and any entry they add fails this check itself.
func checkTrusted(p string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read owner", p)
	}
	m := fi.Mode()
	if m&fs.ModeSymlink != 0 && st.Uid != 0 { // symlinks only if root made them (e.g. macOS /etc)
		return fmt.Errorf("%s is a symlink owned by uid %d; refusing to follow", p, st.Uid)
	}
	if st.Uid != 0 && st.Uid != trustedUID {
		return fmt.Errorf("%w: %s is owned by uid %d; must be owned by root", errUntrustedOwner, p, st.Uid)
	}
	if m&fs.ModeSymlink == 0 && m.Perm()&0o022 != 0 && (!m.IsDir() || m&fs.ModeSticky == 0 || st.Uid != 0) {
		return fmt.Errorf("%s has mode %04o; must not be group/other-writable", p, m.Perm())
	}
	return nil
}

// mkdirManaged creates dir (and parents) root-owned 0755; checkChain
// verifies the result.
func mkdirManaged(dir string) error { return os.MkdirAll(dir, 0o755) }

// consoleUser is the human at the machine (halod itself runs as root).
// darwin: owner of /dev/console. linux: best effort via loginctl seat0.
func consoleUser(ctx context.Context, run Runner) string {
	switch runtime.GOOS {
	case "darwin":
		fi, err := os.Stat("/dev/console")
		if err != nil {
			return ""
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid == 0 {
			return ""
		}
		if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil {
			return u.Username
		}
	case "linux":
		for _, bin := range []string{"/usr/bin/loginctl", "/bin/loginctl"} {
			if _, err := os.Stat(bin); err != nil {
				continue
			}
			out, err := run(ctx, bin, "list-sessions", "--no-legend")
			if err != nil {
				return ""
			}
			return seat0User(string(out))
		}
	}
	return ""
}
