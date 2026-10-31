// Package hmackey checks operator-supplied HMAC keys (salts, webhook secrets)
// at config load (ADR-0038). Go's FIPS 140-3 module refuses an HMAC key
// shorter than 112 bits by panicking inside hmac.New, which would crash a
// request goroutine or a background worker long after startup. So under
// crypto/fips140.Enabled() a short key refuses to start, naming the flag;
// without FIPS it only warns, so existing deployments keep running. Keys are
// never stretched: receivers such as GitHub compute the HMAC with the raw
// secret.
package hmackey

import (
	"crypto/fips140"
	"fmt"
	"log/slog"
)

// MinFIPS is the shortest HMAC key Go's FIPS 140-3 module accepts: 112 bits.
const MinFIPS = 14

// fipsEnabled is crypto/fips140.Enabled; swapped in tests.
var fipsEnabled = fips140.Enabled

// Check validates one HMAC key named by flag (the config key or CLI flag an
// operator would change). An empty key is the caller's business (feature off,
// or a random key generated later) and passes. In FIPS mode a key under
// MinFIPS bytes is an error; otherwise it is logged as a warning on log (nil:
// slog.Default) and accepted.
func Check(log *slog.Logger, flag string, key []byte) error {
	if len(key) == 0 || len(key) >= MinFIPS {
		return nil
	}
	if fipsEnabled() {
		return fmt.Errorf("%s is %d bytes; FIPS 140-3 mode requires an HMAC key of at least %d bytes (112 bits): use 32 random bytes, e.g. `openssl rand -hex 32`", flag, len(key), MinFIPS)
	}
	if log == nil {
		log = slog.Default()
	}
	log.Warn("HMAC key shorter than 112 bits: a FIPS 140-3 build in fips140=only mode refuses to start with it; use at least 14 (ideally 32) random bytes",
		"setting", flag, "bytes", len(key))
	return nil
}

// Usable reports whether key can be used with HMAC right now without
// panicking: always outside FIPS mode, and only at MinFIPS bytes or more
// inside it. Request-path code uses it as a last guard so a key that slipped
// past Check is a refusal, never a panic.
func Usable(key []byte) bool { return len(key) >= MinFIPS || !fipsEnabled() }

// SetFIPSForTesting makes Check and Usable behave as if FIPS mode were on
// (or off) until restore is called. Tests of the packages that call Check
// use it; production code never does.
func SetFIPSForTesting(on bool) (restore func()) {
	old := fipsEnabled
	fipsEnabled = func() bool { return on }
	return func() { fipsEnabled = old }
}
