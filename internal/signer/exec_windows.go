//go:build windows

package signer

import (
	"os"
	"os/exec"
	"path/filepath"
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
