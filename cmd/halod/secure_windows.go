//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedUID is unused on windows (kept so tests compile everywhere).
var trustedUID uint32

// checkTrusted requires the owner SID to be SYSTEM, BUILTIN\Administrators or
// TrustedInstaller, and a DACL that gives nobody else write access (see
// checkACEs: strict for files, managed dirs and halod's own dirs; ancestors
// such as C:\ProgramData may let users create entries).
func checkTrusted(p string, fi fs.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: read security info: %w", p, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: read owner: %w", p, err)
	}
	if o := owner.String(); !trustedSID(o) {
		return fmt.Errorf("%w: %s is owned by %s; must be owned by SYSTEM or Administrators (squatted? remove it and let halod recreate it)", errUntrustedOwner, p, o)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: read DACL: %w", p, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: NULL DACL grants everyone full access", p)
	}
	aces := make([]ace, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var e *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &e); err != nil {
			return fmt.Errorf("%s: read ACE %d: %w", p, i, err)
		}
		switch e.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
		default:
			// object/callback ACEs: can't evaluate, so don't trust
			return fmt.Errorf("%s: unsupported ACE type %d", p, e.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&e.SidStart))
		aces = append(aces, ace{
			SID:         sid.String(),
			Allow:       e.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE,
			InheritOnly: e.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0,
			Inherits:    e.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0,
			Mask:        uint32(e.Mask),
		})
	}
	return checkACEs(p, aces, !fi.IsDir() || strictWindowsPath(p))
}

// stateMode is state.json's mode. 0600 would make fsutil grant the *writing user* alone, so a
// state file first written by an admin running `halod once` (enrollment) is rejected by checkTrusted
// when the SYSTEM task later runs. 0644 leaves the file with the DACL it inherits from the managed
// var dir: SYSTEM and Administrators full control, Users read-only.
const stateMode fs.FileMode = 0o644

// managedDACL: SYSTEM and Administrators full control, Users read/execute,
// inherited by everything below, not inheriting from the parent (protected).
const managedDACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// mkdirManaged creates dir and any missing parents; each directory halod
// creates gets managedDACL, so a managed dir under C:\ProgramData does not
// inherit its "Users may create files" entry.
func mkdirManaged(dir string) error {
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := mkdirManaged(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(managedDACL)
	if err != nil {
		return fmt.Errorf("managed DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("managed DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("%s: set DACL: %w", dir, err)
	}
	return nil
}

// ponytail: console user not detected on windows (WTSGetActiveConsoleSessionId
// + WTSQuerySessionInformation would do it).
func consoleUser(context.Context, Runner) string { return "" }
