//go:build windows

package signer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// killProcessGroup on Windows keeps exec's default Cancel (kill the signer
// process). Process groups (job objects) are not used; a signer that spawns
// helpers must end them itself.
func killProcessGroup(*exec.Cmd) {}

// checkSignerFile on Windows: Unix mode bits and owners do not apply, and
// ACLs are not inspected; place the signer where only administrators can
// write (documented).
func checkSignerFile(string, os.FileInfo) error { return nil }

// checkSignerDir on Windows: ACLs are not inspected (documented).
func checkSignerDir(string, os.FileInfo) error { return nil }

// reapProcessGroup on Windows: no process groups are used.
func reapProcessGroup(*exec.Cmd) {}

// signerWorkDir on Windows: the signer's own directory.
func signerWorkDir(path string) string { return filepath.Dir(path) }

// isPathVar reports whether name is the search path variable (Windows
// environment names are case-insensitive: "Path" is common).
func isPathVar(name string) bool { return strings.EqualFold(name, "PATH") }

// baseEnvVar is the minimal environment every signer gets besides
// HALOS_SIGNER_* and env= names: the profile directories, and the system
// variables Windows programs (Go's included) need to start and find DLLs.
func baseEnvVar(name string) bool {
	for _, v := range []string{"HOME", "USERPROFILE", "SystemRoot", "SystemDrive", "windir", "TEMP", "TMP", "PATHEXT", "ComSpec"} {
		if strings.EqualFold(name, v) {
			return true
		}
	}
	return false
}
