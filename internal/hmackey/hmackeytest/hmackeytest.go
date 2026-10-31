// Package hmackeytest lets tests run hmackey's checks as if FIPS mode were
// on or off. Only _test.go files may import it; a test in internal/hmackey
// fails the build of any production file that does.
package hmackeytest

import "github.com/dshakes/halos/internal/hmackey/internal/fipsmode"

// SetFIPS makes hmackey.Check and hmackey.Usable behave as if FIPS mode were
// on (or off) until restore is called. Not safe for parallel tests.
func SetFIPS(on bool) (restore func()) {
	old := fipsmode.Enabled
	fipsmode.Enabled = func() bool { return on }
	return func() { fipsmode.Enabled = old }
}
