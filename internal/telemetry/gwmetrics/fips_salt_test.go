package gwmetrics

import (
	"crypto/fips140"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

// ADR-0038: a unit salt Go's FIPS module would panic on (on every request)
// refuses to start in FIPS mode, naming the setting; outside FIPS it is
// accepted with a warning so existing deployments keep running.
func TestUnitSaltFIPS(t *testing.T) {
	for _, tc := range []struct {
		name string
		fips bool
		salt string
		ok   bool
	}{
		{"fips short salt refused", true, "short", false},
		{"fips 32-byte salt", true, strings.Repeat("s", 32), true},
		{"fips empty salt is random 32 bytes", true, "", true},
		{"no fips short salt warns", false, "short", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.fips && fips140.Enabled() {
				t.Skip("real FIPS run: a short salt cannot be used at all")
			}
			defer hmackeytest.SetFIPS(tc.fips)()
			e, err := New(Config{OTLPEndpoint: "http://c", UnitSalt: tc.salt})
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "telemetry.unitSalt") {
				t.Fatalf("error does not name the setting: %v", err)
			}
			if e != nil && e.Unit("alice") == "" {
				t.Fatal("no unit")
			}
		})
	}
}
