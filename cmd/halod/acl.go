package main

import (
	"errors"
	"fmt"
	"strings"
)

// errUntrustedOwner marks a path owned by someone other than root/SYSTEM/
// Administrators: typically a squatted managed directory. Status reports it
// with ErrorCode "untrusted_owner".
var errUntrustedOwner = errors.New("untrusted owner")

// ace is one Windows DACL entry, reduced to what the trust check needs.
// Kept platform-neutral so the policy is unit-tested everywhere.
type ace struct {
	SID         string // string form, e.g. S-1-5-32-545
	Allow       bool   // false: deny ACE (only ever removes access)
	InheritOnly bool   // applies to children only, not to this object
	Inherits    bool   // propagates to children created here (OI or CI)
	Mask        uint32
}

// Well-known SIDs allowed to hold write access anywhere on the chain.
const (
	sidSystem          = "S-1-5-18"
	sidAdministrators  = "S-1-5-32-544"
	sidCreatorOwner    = "S-1-3-0"
	trustedInstallerID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// Access mask bits (winnt.h).
const (
	fileWriteData       = 0x2 // file: write; dir: add file
	fileAppendData      = 0x4 // file: append; dir: add subdirectory
	fileWriteEA         = 0x10
	fileDeleteChild     = 0x40
	fileWriteAttributes = 0x100
	accessDelete        = 0x10000
	writeDAC            = 0x40000
	writeOwner          = 0x80000
	genericAll          = 0x10000000
	genericWrite        = 0x40000000
)

const writeMask = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild | fileWriteAttributes |
	accessDelete | writeDAC | writeOwner | genericAll | genericWrite

// createOnlyMask is what an untrusted SID may hold on an ancestor directory
// above a managed location (C:\ProgramData grants Users this): it can add
// entries, like a sticky /tmp, but every entry halod uses is checked itself.
const createOnlyMask = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes

// testTrustedSID is one more trusted SID. Only the windows tests set it (the
// analogue of trustedUID: their temp dirs belong to the runner's user); no flag
// or environment variable reaches it.
var testTrustedSID string

func trustedSID(sid string) bool {
	return sid == sidSystem || sid == sidAdministrators || sid == trustedInstallerID || (testTrustedSID != "" && sid == testTrustedSID)
}

// checkACEs rejects a DACL that lets anyone but SYSTEM, Administrators or
// TrustedInstaller modify p. strict applies to managed directories, the files
// in them and halod's own directories: no write-type right at all, including
// inheritable ones that would reach the files halod creates there. Ancestors
// above a managed location (strict=false) may grant create-only rights.
// CREATOR OWNER is fine on inherit-only entries (it is a placeholder that
// becomes the creator of each child, and every child is checked itself).
func checkACEs(p string, aces []ace, strict bool) error {
	for _, e := range aces {
		if !e.Allow || trustedSID(e.SID) || e.Mask&writeMask == 0 {
			continue
		}
		if e.SID == sidCreatorOwner && e.InheritOnly {
			continue
		}
		if e.InheritOnly && !strict {
			continue // reaches only new children, which are checked on their own
		}
		allowed := uint32(0)
		if !strict {
			allowed = createOnlyMask
		}
		if bad := e.Mask & writeMask &^ allowed; bad != 0 {
			return fmt.Errorf("%s: ACL grants %s write access (mask %#x); only SYSTEM, Administrators and TrustedInstaller may", p, e.SID, bad)
		}
	}
	return nil
}

// strictWindowsPath reports whether p is inside (or is) a managed directory
// or one of halod's own directories, where checkACEs is strict.
func strictWindowsPath(p string) bool {
	lp := strings.ToLower(p)
	dirs := []string{}
	for _, h := range harnessNames() {
		dirs = append(dirs, managedDirs(h, "windows")...)
	}
	l := layouts["windows"]
	dirs = append(dirs, l.Bin, l.NPM, winDir(l.Config), winDir(l.State))
	for _, d := range dirs {
		ld := strings.ToLower(d)
		if lp == ld || strings.HasPrefix(lp, ld+`\`) {
			return true
		}
	}
	return false
}

func winDir(p string) string {
	if i := strings.LastIndex(p, `\`); i > 0 {
		return p[:i]
	}
	return p
}
