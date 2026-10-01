package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/halos-dev/halos/internal/policy"
)

// KillList is the set of experiments halo-server has killed: gateways treat
// them as not running (control routing, no shadow) without waiting for a
// policy PR to merge and a snapshot to ship.
type KillList struct {
	Version     uint64    `json:"version"` // grows with every kill/unkill; informational
	Experiments []string  `json:"experiments"`
	IssuedAt    time.Time `json:"issuedAt"`
}

// KillEnvelope is GET /api/v1/gateway/killswitch: Payload is the JSON
// KillList, Signature is ed25519 over killDomain+Payload.
type KillEnvelope struct {
	Payload   []byte `json:"payload"`   // base64 in JSON
	Signature []byte `json:"signature"` // base64 in JSON
}

// killDomain separates kill-list signatures from anything else the key could sign.
const killDomain = "halo-killswitch-v1\n"

// SignKillList seals l for gateways.
func SignKillList(key ed25519.PrivateKey, l KillList) (KillEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return KillEnvelope{}, errors.New("gateway: killswitch signing key is not an ed25519 private key")
	}
	if l.Experiments == nil {
		l.Experiments = []string{}
	}
	p, err := json.Marshal(l)
	if err != nil {
		return KillEnvelope{}, fmt.Errorf("gateway: encode kill list: %w", err)
	}
	return KillEnvelope{Payload: p, Signature: ed25519.Sign(key, append([]byte(killDomain), p...))}, nil
}

// VerifyKillList checks the signature and freshness (IssuedAt within maxAge
// of now, at most a minute in the future) and returns the list.
func VerifyKillList(pub ed25519.PublicKey, env KillEnvelope, now time.Time, maxAge time.Duration) (KillList, error) {
	if len(pub) != ed25519.PublicKeySize {
		return KillList{}, errors.New("gateway: killswitch public key is not ed25519")
	}
	if !ed25519.Verify(pub, append([]byte(killDomain), env.Payload...), env.Signature) {
		return KillList{}, errors.New("gateway: kill list signature invalid")
	}
	var l KillList
	if err := json.Unmarshal(env.Payload, &l); err != nil {
		return KillList{}, fmt.Errorf("gateway: decode kill list: %w", err)
	}
	if age := now.Sub(l.IssuedAt); age > maxAge || age < -time.Minute {
		return KillList{}, fmt.Errorf("gateway: kill list issued at %s is stale or from the future (now %s)", l.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return l, nil
}

// Kill-switch poller defaults.
const (
	DefaultKillInterval = 10 * time.Second
	DefaultKillMaxAge   = 10 * time.Minute
	maxKillBody         = 1 << 20
)

// KillSwitch polls halo-server for the signed kill list.
//
// Failure policy: a fetch or verification failure keeps the last accepted
// list (a kill never silently lapses because the control plane is down); if
// no list was ever accepted the set is empty and the policy snapshot's
// statuses alone decide. A list is accepted only if it is strictly newer
// (IssuedAt) than the current one, so a replayed older envelope cannot undo
// a kill. A nil *KillSwitch is valid and kills nothing.
type KillSwitch struct {
	URL      string
	Token    string
	PubKey   ed25519.PublicKey
	Interval time.Duration // default DefaultKillInterval
	MaxAge   time.Duration // default DefaultKillMaxAge
	Client   *http.Client  // default: 10s timeout, no redirects
	Log      *slog.Logger
	Now      func() time.Time

	mu      sync.RWMutex
	list    KillList
	killed  map[string]bool
	failing bool
}

// checkKillURL requires https: the bearer token travels on this request. Plain
// http is accepted only to a loopback host or when allowInsecureInCluster is set
// (an in-cluster Service URL on a trusted pod network).
func checkKillURL(raw string, allowInsecureInCluster bool) error {
	scheme, host, _, _, err := Target(raw)
	if err != nil {
		return err
	}
	if scheme == "https" {
		return nil
	}
	if scheme != "http" {
		return fmt.Errorf("unsupported scheme %q", scheme)
	}
	if allowInsecureInCluster {
		return nil
	}
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("plain http to %q would send the gateway token in clear; use https (or allowInsecureInCluster for a trusted in-cluster URL)", host)
}

// NewKillSwitch validates the config (see bundle.ParseEd25519Verifier for PEM
// keys). allowInsecureInCluster permits plain http to a non-loopback host.
func NewKillSwitch(url, token string, pub ed25519.PublicKey, interval time.Duration, log *slog.Logger, allowInsecureInCluster bool) (*KillSwitch, error) {
	if url == "" || token == "" || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("gateway: killswitch needs url, token and an ed25519 public key")
	}
	if err := checkKillURL(url, allowInsecureInCluster); err != nil {
		return nil, fmt.Errorf("gateway: killswitch url: %w", err)
	}
	return &KillSwitch{URL: url, Token: token, PubKey: pub, Interval: interval, Log: log}, nil
}

func (k *KillSwitch) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

func (k *KillSwitch) log() *slog.Logger {
	if k.Log != nil {
		return k.Log
	}
	return slog.Default()
}

// Refresh fetches and verifies the list once; on error the previous list stays.
func (k *KillSwitch) Refresh(ctx context.Context) error {
	err := k.refresh(ctx)
	k.mu.Lock()
	was := k.failing
	k.failing = err != nil
	k.mu.Unlock()
	switch { // log transitions only: a down control plane must not flood logs every interval
	case err != nil && !was:
		k.log().Warn("killswitch refresh failed; keeping last-known list", "err", err)
	case err == nil && was:
		k.log().Info("killswitch refresh recovered")
	}
	return err
}

func (k *KillSwitch) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL, nil)
	if err != nil {
		return fmt.Errorf("gateway: killswitch request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+k.Token)
	hc := k.Client
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: killswitch fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: killswitch fetch: HTTP %d", resp.StatusCode)
	}
	var env KillEnvelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxKillBody)).Decode(&env); err != nil {
		return fmt.Errorf("gateway: killswitch decode: %w", err)
	}
	maxAge := k.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultKillMaxAge
	}
	l, err := VerifyKillList(k.PubKey, env, k.now(), maxAge)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !l.IssuedAt.After(k.list.IssuedAt) {
		return fmt.Errorf("gateway: kill list issued at %s is not newer than the current one (%s); replay?", l.IssuedAt.Format(time.RFC3339Nano), k.list.IssuedAt.Format(time.RFC3339Nano))
	}
	if l.Version != k.list.Version {
		k.log().Info("killswitch updated", "version", l.Version, "experiments", l.Experiments)
	}
	k.list = l
	k.killed = make(map[string]bool, len(l.Experiments))
	for _, e := range l.Experiments {
		k.killed[e] = true
	}
	return nil
}

// Run refreshes immediately and then every Interval until ctx ends.
func (k *KillSwitch) Run(ctx context.Context) {
	iv := k.Interval
	if iv <= 0 {
		iv = DefaultKillInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		_ = k.Refresh(ctx) // logged in Refresh; last-known list stays in force
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Restore seeds a last-known list persisted by the caller (halod keeps it in
// its state file) so kills survive a restart and envelopes issued before it
// are refused as replays. It is a no-op unless l is newer than the current
// list. The list is trusted as given: pass only one that was verified.
func (k *KillSwitch) Restore(l KillList) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !l.IssuedAt.After(k.list.IssuedAt) {
		return
	}
	k.list = l
	k.list.Experiments = slices.Clone(l.Experiments)
	k.killed = make(map[string]bool, len(l.Experiments))
	for _, e := range l.Experiments {
		k.killed[e] = true
	}
}

// Killed returns the current list (a copy).
func (k *KillSwitch) Killed() KillList {
	if k == nil {
		return KillList{}
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	l := k.list
	l.Experiments = slices.Clone(l.Experiments)
	return l
}

// Apply returns org with every killed experiment's status forced to
// "paused", so Decide routes its users to default (control) and mirrors
// nothing. org itself is never mutated; it is returned as-is when nothing
// applies.
// ponytail: copies per request while a kill is active; cache by (org, version) if it shows in profiles.
func (k *KillSwitch) Apply(org *policy.Org) *policy.Org {
	if k == nil || org == nil {
		return org
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if len(k.killed) == 0 || !slices.ContainsFunc(org.Experiments, func(e *policy.Experiment) bool { return k.killed[e.Name] }) {
		return org
	}
	out := *org
	out.Experiments = make([]*policy.Experiment, len(org.Experiments))
	for i, e := range org.Experiments {
		if k.killed[e.Name] {
			c := *e
			c.Status = "paused"
			e = &c
		}
		out.Experiments[i] = e
	}
	return &out
}
