package server

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey"
)

// ADR-0038: HMAC secrets Go's FIPS module would panic on (the GitHub cloud
// webhook secret, an audit-export webhook hmacSecret) refuse to start in
// FIPS mode, naming the setting; outside FIPS they only warn.
func TestHMACSecretsFIPS(t *testing.T) {
	newSrv := func(secrets []string, log *slog.Logger) error {
		s, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, Log: log, DevUser: "op@test", CloudWebhookSecrets: secrets})
		if err == nil {
			_ = s.Close()
		}
		return err
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Run("cloud webhook secret", func(t *testing.T) {
		restore := hmackey.SetFIPSForTesting(true)
		err := newSrv([]string{"short"}, quiet)
		if err == nil || !strings.Contains(err.Error(), "--cloud-webhook-secret-file") {
			t.Fatalf("fips short secret: %v", err)
		}
		if err := newSrv([]string{strings.Repeat("w", 32)}, quiet); err != nil {
			t.Fatalf("fips long secret: %v", err)
		}
		restore()
		defer hmackey.SetFIPSForTesting(false)()
		var buf bytes.Buffer
		if err := newSrv([]string{"short"}, slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
			t.Fatalf("no fips: short secret must still start: %v", err)
		}
		if !strings.Contains(buf.String(), "--cloud-webhook-secret-file") {
			t.Fatalf("no warning logged: %q", buf.String())
		}
	})
	t.Run("audit export hmacSecret", func(t *testing.T) {
		sink := AuditSink{Name: "siem", Type: sinkWebhook, URL: "https://siem.example/in", HMACSecret: &SecretRef{Env: "HALO_TEST_AUDIT_HMAC"}}
		for _, tc := range []struct {
			fips   bool
			secret string
			ok     bool
		}{{true, "short", false}, {true, strings.Repeat("a", 32), true}, {false, "short", true}} {
			t.Setenv("HALO_TEST_AUDIT_HMAC", tc.secret)
			restore := hmackey.SetFIPSForTesting(tc.fips)
			_, err := newAuditSender(sink, "h")
			restore()
			if (err == nil) != tc.ok {
				t.Fatalf("fips=%v secret %d bytes: err %v", tc.fips, len(tc.secret), err)
			}
			if err != nil && !strings.Contains(err.Error(), "sinks[siem].hmacSecret") {
				t.Fatalf("error does not name the setting: %v", err)
			}
		}
	})
}
