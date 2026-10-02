package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// hmacKeyEquiv reports whether two keys give the same HMAC-SHA256: keys over
// the 64-byte block are hashed first, and shorter ones are zero-padded, so
// trailing NULs do not change the MAC. (A property of HMAC, not of Halos.)
func hmacKeyEquiv(a, b []byte) bool {
	norm := func(k []byte) []byte {
		if len(k) > 64 {
			s := sha256.Sum256(k)
			k = s[:]
		}
		return bytes.TrimRight(k, "\x00")
	}
	return bytes.Equal(norm(a), norm(b))
}

// FuzzWebhookVerify: a signature is accepted only for the exact body and
// timestamp it was made for, under an equivalent secret, within the window.
func FuzzWebhookVerify(f *testing.F) {
	ev, _ := json.Marshal(testEvent())
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Unix()
	f.Add([]byte("s3cret"), []byte(`{"a":1}`), now, int64(0), []byte(`{"a":1}`), now, []byte("s3cret"), "")
	f.Add([]byte("s3cret"), ev, now, int64(4*time.Minute), ev, now, []byte("s3cret"), "")
	f.Add([]byte("s3cret"), []byte(`{"a":1}`), now, int64(-6*time.Minute), []byte(`{"a":2}`), now-1, []byte("x"), "sha256=00")
	f.Add([]byte(""), []byte(""), int64(-1), int64(1), []byte(""), int64(-1), []byte("\x00"), "+0")
	f.Fuzz(func(t *testing.T, secret, body []byte, ts, skew int64, body2 []byte, ts2 int64, secret2 []byte, tsHdr string) {
		sig := Sign(secret, ts, body)
		hdr := func(tsv string, s string) http.Header {
			h := http.Header{}
			h.Set(TimestampHeader, tsv)
			h.Set(SignatureHeader, s)
			return h
		}
		// Any timestamp header, any clock: never panics; accepted only within the window.
		farNow := time.Unix(now, 0)
		if err := Verify(secret, hdr(strconv.FormatInt(ts, 10), sig), body, farNow, WebhookTolerance); err == nil {
			if d := now - ts; d > int64(WebhookTolerance/time.Second) || d < -int64(WebhookTolerance/time.Second) {
				t.Fatalf("ts %d accepted at %d (outside the window)", ts, now)
			}
		}
		_ = Verify(secret, hdr(tsHdr, sig), body, farNow, WebhookTolerance)

		// Keep the time arithmetic exact for the iff checks below.
		ts = now + ts%(10*365*24*3600)
		skew %= int64(time.Hour)
		sig = Sign(secret, ts, body)
		at := time.Unix(ts, 0).Add(time.Duration(skew))
		inWindow := skew <= int64(WebhookTolerance) && skew >= -int64(WebhookTolerance)
		if err := Verify(secret, hdr(strconv.FormatInt(ts, 10), sig), body, at, WebhookTolerance); (err == nil) != inWindow {
			t.Fatalf("exact request, skew %s: err=%v, want accepted=%v", time.Duration(skew), err, inWindow)
		}
		if !inWindow {
			return
		}
		// Tampering: the signature for (ts, body) under secret is accepted for
		// (ts2, body2) under secret2 only if all three are equivalent.
		ts2 = ts + ts2%int64(WebhookTolerance/time.Second) // keep ts2 inside the window too
		want := ts2 == ts && bytes.Equal(body, body2) && hmacKeyEquiv(secret, secret2)
		if err := Verify(secret2, hdr(strconv.FormatInt(ts2, 10), sig), body2, at, WebhookTolerance); (err == nil) != want {
			t.Fatalf("tampered (ts %d->%d, body %q->%q, secret %q->%q): err=%v, want accepted=%v", ts, ts2, body, body2, secret, secret2, err, want)
		}
		// An arbitrary signature header is accepted only if it is the signature.
		if err := Verify(secret, hdr(strconv.FormatInt(ts, 10), tsHdr), body, at, WebhookTolerance); err == nil && tsHdr != sig {
			t.Fatalf("forged signature %q accepted", tsHdr)
		}
	})
}
