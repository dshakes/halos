package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

// A Webhook built directly with a short secret (bypassing NotifyConfig's
// startup check) returns ErrUnusableKey in FIPS mode instead of panicking
// in hmac.New, and sends nothing; Verify refuses rather than matching an
// empty signature. Under make test-fips this also runs in real
// fips140=only, where an unguarded hmac.New would panic.
func TestWebhookShortSecretGuard(t *testing.T) {
	defer hmackeytest.SetFIPS(true)()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	now := time.Unix(1_700_000_000, 0)
	short := []byte("k")

	err := (Webhook{URL: srv.URL, Secret: short, Now: func() time.Time { return now }}).Notify(context.Background(), testEvent())
	if !errors.Is(err, ErrUnusableKey) {
		t.Fatalf("Notify with a short secret: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("an unsigned (or wrongly signed) notification was sent")
	}
	if _, err := SignChecked(short, now.Unix(), []byte("b")); !errors.Is(err, ErrUnusableKey) {
		t.Fatalf("SignChecked: %v", err)
	}
	if s := Sign(short, now.Unix(), []byte("b")); s != "" {
		t.Fatalf("Sign with an unusable key = %q, want \"\"", s)
	}
	// An empty signature header must not match Sign's "" for an unusable key.
	h := http.Header{}
	h.Set(TimestampHeader, strconv.FormatInt(now.Unix(), 10))
	if err := Verify(short, h, []byte("b"), now, WebhookTolerance); !errors.Is(err, ErrUnusableKey) {
		t.Fatalf("Verify with an unusable key and no signature: %v", err)
	}
	// A FIPS-length secret still signs, sends and verifies.
	long := []byte(strings.Repeat("k", 32))
	if err := (Webhook{URL: srv.URL, Secret: long, Now: func() time.Time { return now }}).Notify(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
}
