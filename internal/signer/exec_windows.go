//go:build windows

package signer

import (
	"os"
	"os/exec"
)

// killProcessGroup on Windows keeps exec's default Cancel (kill the signer
// process). Process groups (job objects) are not used; a signer that spawns
// helpers must end them itself.
func killProcessGroup(*exec.Cmd) {}

// checkSignerFile on Windows: Unix mode bits and owners do not apply, and
// ACLs are not inspected; place the signer where only administrators can
// write (documented).
func checkSignerFile(string, os.FileInfo) error { return nil }
