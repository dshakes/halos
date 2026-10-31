package cloudagents

import (
	"crypto/fips140"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

// ADR-0038: a GitHub delivery against a secret Go's FIPS module would panic
// on is refused, never a per-request panic (halo-server also refuses such a
// secret at startup). Under make test-fips the probe below runs in real
// fips140=only mode.
func TestVerifySignatureShortSecretFIPS(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("real FIPS run: the short-key HMAC below cannot be computed; TestVerifySignatureShortSecretNoPanic covers it")
	}
	body := []byte(`{"action":"completed"}`)
	good := sign("short", body)
	defer hmackeytest.SetFIPS(true)()
	if err := VerifySignature([]string{"short"}, body, good); err == nil {
		t.Fatal("short secret used in FIPS mode")
	}
	// a long secret next to it still verifies
	long := strings.Repeat("s", 32)
	if err := VerifySignature([]string{"short", long}, body, sign(long, body)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignatureShortSecretNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	_ = VerifySignature([]string{"short"}, []byte("x"), "sha256="+strings.Repeat("0", 64))
}
