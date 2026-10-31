// Package hmackey checks operator-supplied HMAC keys (salts, webhook secrets)
// at config load (ADR-0038). Go's FIPS 140-3 module refuses an HMAC key
// shorter than 112 bits: under GODEBUG=fips140=only it panics inside
// hmac.New, which would crash a request goroutine or a background worker
// long after startup. So in FIPS mode (crypto/fips140.Enabled(): fips140=on
// or only, the default in a FIPS build) a short key refuses to start, naming
// the setting; outside FIPS mode it only warns, so existing deployments keep
// running. Keys are never stretched: receivers such as GitHub compute the
// HMAC with the raw secret.
package hmackey

import (
	"fmt"
	"log/slog"

	"github.com/dshakes/halos/internal/hmackey/internal/fipsmode"
)

// MinFIPS is the shortest HMAC key Go's FIPS 140-3 module accepts: 112 bits.
const MinFIPS = 14

// Check validates one HMAC key named by flag (the config key or CLI flag an
// operator would change). An empty key is the caller's business (feature off,
// or a random key generated later) and passes. In FIPS mode a key under
// MinFIPS bytes is an error; otherwise it is logged as a warning on log (nil:
// slog.Default) and accepted.
func Check(log *slog.Logger, flag string, key []byte) error {
	if len(key) == 0 || len(key) >= MinFIPS {
		return nil
	}
	if fipsmode.Enabled() {
		return fmt.Errorf("%s is %d bytes; in FIPS mode (GODEBUG=fips140=on or only, the default in a FIPS build) Halos requires an HMAC key of at least %d bytes (112 bits; Go's FIPS module panics on shorter keys under fips140=only): use 32 random bytes, e.g. `openssl rand -hex 32`", flag, len(key), MinFIPS)
	}
	if log == nil {
		log = slog.Default()
	}
	log.Warn("HMAC key shorter than 112 bits: a FIPS build, or any build run in FIPS mode (GODEBUG=fips140=on or only), refuses to start with it; use at least 14 (ideally 32) random bytes",
		"setting", flag, "bytes", len(key))
	return nil
}

// Usable reports whether key can be used with HMAC in the current mode
// without risking the module's panic: always outside FIPS mode, and only at
// MinFIPS bytes or more inside it. Request-path code uses it as a last guard
// so a key that slipped past Check is a refusal, never a panic.
func Usable(key []byte) bool { return len(key) >= MinFIPS || !fipsmode.Enabled() }
