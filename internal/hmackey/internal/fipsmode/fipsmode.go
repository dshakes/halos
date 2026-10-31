// Package fipsmode is the FIPS-mode probe internal/hmackey consults. It is
// internal to internal/hmackey so only hmackey and its test helper
// (hmackey/hmackeytest) can replace it; production code elsewhere cannot.
package fipsmode

import "crypto/fips140"

// Enabled reports whether Go's FIPS 140-3 mode is on (GODEBUG fips140=on or
// only; the default in a GOFIPS140 build).
var Enabled = fips140.Enabled
