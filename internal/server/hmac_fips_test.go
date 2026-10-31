package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

// The audit forwarder's send is guarded too: a sink built with a short
// secret returns controller.ErrUnusableKey in FIPS mode, never a panic in
// the forwarder goroutine, and sends nothing.
func TestAuditSinkSendShortSecretGuard(t *testing.T) {
	defer hmackeytest.SetFIPS(true)()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	h := &httpSink{kind: sinkWebhook, url: srv.URL, format: fmtNative, hdr: http.Header{}, secret: []byte("k"), client: srv.Client()}
	if err := h.send(context.Background(), nil); !errors.Is(err, controller.ErrUnusableKey) {
		t.Fatalf("send with a short secret: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("sent with an unusable secret")
	}
}

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
		restore := hmackeytest.SetFIPS(true)
		err := newSrv([]string{"short"}, quiet)
		if err == nil || !strings.Contains(err.Error(), "--cloud-webhook-secret-file") {
			t.Fatalf("fips short secret: %v", err)
		}
		if err := newSrv([]string{strings.Repeat("w", 32)}, quiet); err != nil {
			t.Fatalf("fips long secret: %v", err)
		}
		restore()
		defer hmackeytest.SetFIPS(false)()
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
			restore := hmackeytest.SetFIPS(tc.fips)
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
