package bundle

import (
	"context"
	"crypto/fips140"
	"os"
	"testing"
)

// make test-fips sets HALO_EXPECT_FIPS=1: the run must really be in FIPS
// 140-3 mode, or a green fips140=only job would prove nothing.
func TestFIPSModeWhenExpected(t *testing.T) {
	if os.Getenv("HALO_EXPECT_FIPS") != "1" {
		t.Skip("not a FIPS run (make test-fips)")
	}
	if !fips140.Enabled() {
		t.Fatal("HALO_EXPECT_FIPS=1 but crypto/fips140 is not enabled: is GODEBUG=fips140=only set?")
	}
	// both native algorithms sign and verify inside the module
	ctx := context.Background()
	es, ev := keys(t)
	cs, cv := ecKeys(t)
	for _, p := range []struct {
		s Signer
		v Verifier
	}{{es, ev}, {cs, cv}} {
		sig, err := p.s.Sign(ctx, "sha256:00")
		if err != nil {
			t.Fatalf("%s sign: %v", p.s.Type(), err)
		}
		if err := p.v.Verify(ctx, "sha256:00", sig); err != nil {
			t.Fatalf("%s verify: %v", p.s.Type(), err)
		}
	}
}
