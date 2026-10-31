package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// RetryPolicy bounds how hard one delivery tries before giving up. The zero
// value makes a single attempt (what a bare Slack{} or Webhook{} does). A
// delivery that still fails is not lost: the controller records a notification
// only once a channel accepted it, so the next tick tries again.
//
// Retried: transport errors and timeouts, HTTP 429 and 5xx. Never retried:
// other 4xx (a bad URL, routing key or payload does not heal) and a cancelled
// context.
type RetryPolicy struct {
	Attempts int           // total tries including the first; <= 1: no retry
	Base     time.Duration // wait before the second try; doubles each retry
	MaxWait  time.Duration // cap on one wait; a longer Retry-After ends the retrying
	Budget   time.Duration // cap on the whole delivery, waits included; 0: unbounded

	// Sleep waits d or until ctx ends (default: a real timer); Now is the
	// clock for Retry-After dates and Budget (default time.Now). Both are
	// injectable so tests need no real waiting.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time
}

// DefaultRetry is what the CLI wires: 3 tries, waits of 1s then 2s (or the
// server's Retry-After, up to 15s), at most 30s in all, inside the tick's own
// deadline.
var DefaultRetry = RetryPolicy{Attempts: 3, Base: time.Second, MaxWait: 15 * time.Second, Budget: 30 * time.Second}

func (p RetryPolicy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p RetryPolicy) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// statusError is a non-2xx answer. Its text carries no response body: a
// receiver may echo the request (and with it a routing key) back.
type statusError struct {
	kind       string
	code       int
	retryAfter time.Duration // 0: none sent
}

func (e *statusError) Error() string { return fmt.Sprintf("%s notify: HTTP %d", e.kind, e.code) }

func (e *statusError) retryable() bool { return e.code == http.StatusTooManyRequests || e.code >= 500 }

// parseRetryAfter reads a Retry-After header (delta-seconds or HTTP date).
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return max(0, time.Duration(n)*time.Second)
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(0, t.Sub(now))
	}
	return 0
}

// deliver POSTs body to u, retrying per p. Errors never contain u (it is a
// secret for Slack, Teams and the generic webhook) or the response body.
func deliver(ctx context.Context, p RetryPolicy, hc *http.Client, kind, u string, body []byte, hdr http.Header) error {
	started := p.now()
	attempts := max(p.Attempts, 1)
	var err error
	for i := 1; ; i++ {
		var retryAfter time.Duration
		retryAfter, err = attempt(ctx, hc, kind, u, body, hdr, p.now())
		if err == nil {
			return nil
		}
		var se *statusError
		retryable := ctx.Err() == nil // transport errors: yes unless we were cancelled
		if errors.As(err, &se) {
			retryable = se.retryable()
		}
		if !retryable || i >= attempts {
			break
		}
		wait := p.Base << (i - 1)
		if retryAfter > 0 {
			wait = retryAfter
		}
		if p.MaxWait > 0 && wait > p.MaxWait {
			if retryAfter > 0 {
				break // the receiver asked for longer than we will hold the tick
			}
			wait = p.MaxWait
		}
		if p.Budget > 0 && p.now().Sub(started)+wait > p.Budget {
			break
		}
		if serr := p.sleep(ctx, wait); serr != nil {
			break
		}
	}
	return err
}

// attempt makes one POST. The second result is the receiver's Retry-After.
func attempt(ctx context.Context, hc *http.Client, kind, u string, body []byte, hdr http.Header, now time.Time) (time.Duration, error) {
	if hc == nil {
		hc = defaultClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("%s notify: invalid URL", kind) // err would echo the URL
	}
	req.Header = hdr.Clone()
	if req.Header == nil {
		req.Header = http.Header{}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL
		}
		return 0, fmt.Errorf("%s notify: %w", kind, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) // drain for keep-alive
	if resp.StatusCode/100 != 2 {
		ra := parseRetryAfter(resp.Header.Get("Retry-After"), now)
		return ra, &statusError{kind: kind, code: resp.StatusCode, retryAfter: ra}
	}
	return 0, nil
}
