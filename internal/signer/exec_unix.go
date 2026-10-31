//go:build !windows

package signer

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// killProcessGroup starts the signer in its own process group and, on
// timeout or cancellation, kills the whole group: an HSM helper the signer
// spawned cannot outlive it holding the key session.
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// reapProcessGroup kills whatever is left of the signer's process group
// after it exited (normally or not): a helper it backgrounded must not
// survive it. ESRCH (nothing left) is the normal case.
func reapProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // ESRCH ignored: the group is already gone
}

// signerWorkDir: the signer runs in / so nothing it resolves relative to its
// working directory comes from wherever Halos was started.
func signerWorkDir(string) string { return "/" }

// checkSignerDir refuses an ancestor directory of the signer that someone
// else could use to swap it: owned by anyone but root or the current user,
// or group- or world-writable without the sticky bit.
func checkSignerDir(dir string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("signer: exec signer directory %s is group- or world-writable (%v) and not sticky: anyone could replace the signer", dir, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("signer: exec signer directory %s: cannot read its owner", dir)
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Getuid() {
		return fmt.Errorf("signer: exec signer directory %s is owned by uid %d, not root or the current user", dir, uid)
	}
	return nil
}

// checkSignerFile refuses a file that is group- or world-writable or owned
// by anyone but root or the current user.
func checkSignerFile(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("signer: exec signer %s is group- or world-writable (%v): anyone could replace the key holder", path, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("signer: exec signer %s: cannot read its owner", path)
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Getuid() {
		return fmt.Errorf("signer: exec signer %s is owned by uid %d, not root or the current user", path, uid)
	}
	return nil
}
