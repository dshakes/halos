//go:build halodtest && !windows

package main

import "os"

// Compiled in only with `-tags halodtest` (the e2e suite, test/e2e). Release
// builds never contain this file, so no runtime flag or env var can relax the
// root-ownership checks in production. With the tag, SYD_TEST_TRUST_SELF=1 also
// trusts files owned by the invoking uid so halod can run unprivileged
// against a --root sandbox.
func init() {
	if os.Getenv("SYD_TEST_TRUST_SELF") == "1" {
		trustedUID = uint32(os.Getuid())
	}
}
