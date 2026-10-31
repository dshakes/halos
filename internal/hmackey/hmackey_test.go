package hmackey

import (
	"bytes"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/sha256"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

func TestCheck(t *testing.T) {
	short, ok := []byte("0123456789abc"), []byte("0123456789abcd") // 13, 14
	for _, tc := range []struct {
		name     string
		fips     bool
		key      []byte
		wantErr  bool
		wantWarn bool
	}{
		{"empty passes", true, nil, false, false},
		{"fips short refused", true, short, true, false},
		{"fips 14 bytes ok", true, ok, false, false},
		{"no fips short warns", false, short, false, true},
		{"no fips ok silent", false, ok, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer hmackeytest.SetFIPS(tc.fips)()
			var buf bytes.Buffer
			err := Check(slog.New(slog.NewTextHandler(&buf, nil)), "--some-secret-file", tc.key)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "--some-secret-file") {
				t.Fatalf("error does not name the flag: %v", err)
			}
			if got := strings.Contains(buf.String(), "--some-secret-file"); got != tc.wantWarn {
				t.Fatalf("warning %v, want %v: %q", got, tc.wantWarn, buf.String())
			}
			if Usable(tc.key) == (tc.fips && len(tc.key) < MinFIPS) {
				t.Fatalf("Usable(%d bytes) wrong in fips=%v", len(tc.key), tc.fips)
			}
		})
	}
}

// MinFIPS is exactly the module's limit: a key of MinFIPS bytes works in the
// current mode (make test-fips runs this under fips140=only).
func TestMinFIPSAcceptedByModule(t *testing.T) {
	m := hmac.New(sha256.New, make([]byte, MinFIPS))
	m.Write([]byte("x"))
	if len(m.Sum(nil)) != sha256.Size {
		t.Fatal("hmac")
	}
}

// Under a real fips140=only run, one byte less than MinFIPS panics: the
// constant is the module's limit, not a guess.
func TestMinFIPSIsTheModuleLimit(t *testing.T) {
	if !fips140.Enabled() || !strings.Contains(os.Getenv("GODEBUG"), "fips140=only") { // under fips140=on the module accepts short keys (non-approved)
		t.Skip("needs GODEBUG=fips140=only (make test-fips)")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a 13-byte HMAC key did not panic in FIPS mode")
		}
	}()
	hmac.New(sha256.New, make([]byte, MinFIPS-1)).Write([]byte("x"))
}
