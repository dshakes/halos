package controller

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/promote"
)

// KillOutcome is the typed result of the kill-switch step of a rollback.
type KillOutcome string

const (
	KillEnforced      KillOutcome = "enforced"             // tripped and enforced by gateways
	KillNotGateway    KillOutcome = "not_gateway_evidence" // evidence not gateway-sourced; human decides
	KillNotConfigured KillOutcome = "not_configured"       // no kill switch wired
	KillRecorded      KillOutcome = "recorded_only"        // written, enforcement not guaranteed (KillCaveat)
	KillFailed        KillOutcome = "failed"               // the kill call errored
)

// Event is what the controller tells humans about a verdict it acted on.
type Event struct {
	// ID is the delivery's idempotency key: the same for every attempt at one
	// notification, by any controller replica, so a receiver can drop a
	// duplicate sent across a leader failover (webhook: X-Halo-Event-Id).
	ID string `json:"id,omitempty"`
	// Rollout is set for rollout events; Experiment is then its backing experiment.
	Rollout     string          `json:"rollout,omitempty"`
	Experiment  string          `json:"experiment"`
	Axis        string          `json:"axis,omitempty"`
	Verdict     promote.Verdict `json:"verdict"`
	Reason      string          `json:"reason"`
	Killed      bool            `json:"killed"` // traffic-plane kill switch is active for the experiment
	KillOutcome KillOutcome     `json:"killOutcome,omitempty"`
	KillError   string          `json:"killError,omitempty"` // detail for every non-enforced outcome
	PRURL       string          `json:"prURL,omitempty"`
	PRError     string          `json:"prError,omitempty"`
	Report      promote.Report  `json:"report"`
	At          time.Time       `json:"at"`
	// Resolved marks the all-clear for an earlier event of the same Verdict:
	// the condition that raised it is over (a human merged the pause or
	// advanced the rollout, or the kill was lifted). Only sinks that opt in
	// with the "resolved" event kind receive it (webhook, PagerDuty).
	Resolved bool `json:"resolved,omitempty"`
}

// Text is a one-paragraph human summary.
func (e Event) Text() string {
	var b strings.Builder
	if e.Resolved {
		kind, name := "experiment", e.Experiment
		if e.Rollout != "" {
			kind, name = "rollout", e.Rollout
		}
		fmt.Fprintf(&b, "Halos %s %s: %s resolved (%s)", kind, name, strings.ToUpper(string(e.Verdict)), e.Reason)
		return b.String()
	}
	if e.Rollout != "" {
		fmt.Fprintf(&b, "Halos rollout %s: %s (%s)", e.Rollout, strings.ToUpper(string(e.Verdict)), e.Reason)
	} else {
		fmt.Fprintf(&b, "Halos experiment %s: %s (%s)", e.Experiment, strings.ToUpper(string(e.Verdict)), e.Reason)
	}
	if e.Verdict == promote.Rollback {
		switch e.KillOutcome {
		case KillEnforced:
			if e.Axis == "client" {
				b.WriteString(". Kill switch tripped (gateway traffic only; client-axis variants stay until the pause PR merges)")
			} else {
				b.WriteString(". Kill switch tripped: gateways route everyone to control")
			}
		case KillNotGateway:
			b.WriteString(". Not auto-killed: rollback decided on non-gateway (CLI or eval) evidence; merge the pause PR")
		case KillNotConfigured:
			b.WriteString(". Kill switch not configured \u2014 merge the pause PR urgently")
		case KillRecorded:
			b.WriteString(". Kill recorded only, not enforced by a gateway (" + e.KillError + "); merge the pause PR urgently")
		case KillFailed:
			b.WriteString(". KILL SWITCH FAILED: " + e.KillError)
		}
	}
	switch {
	case e.PRURL != "":
		b.WriteString(". PR: " + e.PRURL)
	case e.PRError != "":
		b.WriteString(". PR not opened yet (" + e.PRError + "); will retry")
	}
	return b.String()
}

// Notifier delivers events. Implementations must bound their own latency.
type Notifier interface {
	Notify(ctx context.Context, e Event) error
}

// Notifiers fans out to every notifier and joins their errors.
type Notifiers []Notifier

func (ns Notifiers) Notify(ctx context.Context, e Event) error {
	var errs []error
	for _, n := range ns {
		if err := n.Notify(ctx, e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

const notifyTimeout = 10 * time.Second

func defaultClient() *http.Client {
	return &http.Client{Timeout: notifyTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Slack posts to a Slack(-compatible) incoming webhook.
type Slack struct {
	URL    string
	Client *http.Client
	Retry  RetryPolicy // zero: one attempt
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func (s Slack) Notify(ctx context.Context, e Event) error {
	text := slackEscaper.Replace(e.Text())
	body, err := json.Marshal(map[string]any{
		"text":   text,
		"blocks": []any{map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}}},
	})
	if err != nil {
		return fmt.Errorf("slack notify: encode: %w", err)
	}
	return deliver(ctx, s.Retry, s.Client, "slack", s.URL, body, http.Header{})
}

// Webhook authentication. The signature covers the timestamp so a captured
// request cannot be replayed later:
//
//	X-Halo-Timestamp: <unix seconds>
//	X-Halo-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
//
// Receivers must recompute the HMAC over the raw body with the timestamp from
// X-Halo-Timestamp, compare in constant time, and reject timestamps more than
// WebhookTolerance from their clock (Verify does all of this).
const (
	SignatureHeader = "X-Halo-Signature"
	TimestampHeader = "X-Halo-Timestamp"
	// WebhookTolerance is the recommended receiver clock-skew/replay window.
	WebhookTolerance = 5 * time.Minute
)

// Webhook posts the Event JSON, signed with Secret when set.
type Webhook struct {
	URL    string
	Secret []byte
	Client *http.Client
	Now    func() time.Time // default time.Now
	Retry  RetryPolicy      // zero: one attempt
}

// Sign returns the SignatureHeader value for body sent at unix time ts.
func Sign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Verify is the receiver side: it checks the timestamp header is within
// tolerance of now and the signature header matches body.
func Verify(secret []byte, h http.Header, body []byte, now time.Time, tolerance time.Duration) error {
	ts, err := strconv.ParseInt(h.Get(TimestampHeader), 10, 64)
	if err != nil {
		return fmt.Errorf("webhook: bad or missing %s: %w", TimestampHeader, err)
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return fmt.Errorf("webhook: timestamp %d outside %s tolerance (replay?)", ts, tolerance)
	}
	if !hmac.Equal([]byte(h.Get(SignatureHeader)), []byte(Sign(secret, ts, body))) {
		return errors.New("webhook: signature mismatch")
	}
	return nil
}

// EventIDHeader carries Event.ID on webhook deliveries (also in the body).
const EventIDHeader = "X-Halo-Event-Id"

func (w Webhook) Notify(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("webhook notify: encode: %w", err)
	}
	h := http.Header{}
	if e.ID != "" {
		h.Set(EventIDHeader, e.ID)
	}
	if len(w.Secret) > 0 {
		now := time.Now
		if w.Now != nil {
			now = w.Now
		}
		ts := now().Unix()
		h.Set(TimestampHeader, strconv.FormatInt(ts, 10))
		h.Set(SignatureHeader, Sign(w.Secret, ts, body))
	}
	return deliver(ctx, w.Retry, w.Client, "webhook", w.URL, body, h)
}
