//go:build windows

package fsutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RestrictToOwner replaces path's DACL with one that grants full control to the
// current user only and does not inherit from the parent: the Windows
// equivalent of mode 0600, which Go's os.Chmod cannot express.
func RestrictToOwner(path string) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return fmt.Errorf("owner-only DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("owner-only DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict %s to its owner: %w", path, err)
	}
	return nil
}

func currentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	return u.User.Sid, nil
}

// VerifyPrivate reports whether only the current user can reach path: a
// protected DACL (no inheritance) whose every ACE is an allow for that user.
func VerifyPrivate(path string) error {
	want, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: read DACL: %w", path, err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("%s: read DACL control: %w", path, err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s: DACL inherits from its parent", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s: no DACL (%v)", path, err)
	}
	if dacl.AceCount != 1 {
		return fmt.Errorf("%s: DACL has %d entries, want 1", path, dacl.AceCount)
	}
	var e *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &e); err != nil {
		return fmt.Errorf("%s: read ACE: %w", path, err)
	}
	if e.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return fmt.Errorf("%s: ACE type %d, want allow", path, e.Header.AceType)
	}
	if sid := (*windows.SID)(unsafe.Pointer(&e.SidStart)); !sid.Equals(want) {
		return fmt.Errorf("%s: ACE grants %s, want only %s", path, sid, want)
	}
	return nil
}
