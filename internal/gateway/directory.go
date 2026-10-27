package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// DirectoryEntry is halo-server's SCIM directory answer for one subject (GET
// /api/v1/gateway/directory). Inactive covers deactivated, deleted and never
// provisioned users alike.
type DirectoryEntry struct {
	Active bool     `json:"active"`
	Groups []string `json:"groups,omitempty"`
}

// Directory defaults.
const (
	DefaultDirectoryTTL   = time.Minute     // an entry is reused this long before halo-server is asked again
	DefaultDirectoryGrace = 5 * time.Minute // a cached entry outlives an unreachable halo-server this long
	maxDirectoryEntries   = 100_000
	maxDirectoryBody      = 64 << 10
)

// DirectoryClient makes halo-server's SCIM directory authoritative for a
// verified subject (ADR-0022): the subject's groups are the directory's, and a
// subject the directory does not list as active is refused (ErrNotProvisioned).
// Groups never come from the request.
type DirectoryClient struct {
	URL, Token string
	TTL, Grace time.Duration
	Client     *http.Client
	Now        func() time.Time
	Log        *slog.Logger
	// FailClosed: refuse (ErrDirectoryUnavailable) instead of failing open
	// when the directory cannot be asked (DirectoryFailClosed).
	FailClosed bool
	// Observe, when set, is told every Resolve outcome of a looked-up subject:
	// ok, stale (cached entry served through an outage), failopen,
	// unavailable (FailClosed) or not_provisioned. For metrics.
	Observe func(outcome string)

	mu    sync.Mutex
	cache map[string]directoryEntry
}

type directoryEntry struct {
	e  DirectoryEntry
	at time.Time
}

// NewDirectoryClient validates the config (https unless loopback or allowInsecureInCluster).
func NewDirectoryClient(url, token string, ttl, grace time.Duration, log *slog.Logger, allowInsecureInCluster bool) (*DirectoryClient, error) {
	if url == "" || token == "" {
		return nil, errors.New("gateway: directory needs url and token")
	}
	if err := checkKillURL(url, allowInsecureInCluster); err != nil {
		return nil, fmt.Errorf("gateway: directory url: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultDirectoryTTL
	}
	if grace <= 0 {
		grace = DefaultDirectoryGrace
	}
	return &DirectoryClient{URL: url, Token: token, TTL: ttl, Grace: grace, Log: log}, nil
}

func (c *DirectoryClient) observe(outcome string) {
	if c.Observe != nil {
		c.Observe(outcome)
	}
}

// FailOpenSubject is sub kept with no groups, as Resolve answers when the
// directory cannot be asked under the open fail mode. Kind and Delegation
// stay: a delegated agent keeps its chain, so the agent policy still applies.
func FailOpenSubject(sub *policy.Subject) *policy.Subject {
	if sub == nil {
		return nil
	}
	return &policy.Subject{ID: sub.ID, Kind: sub.Kind, Delegation: sub.Delegation}
}

func (c *DirectoryClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ErrNotProvisioned is Resolve's answer for a verified subject the directory
// does not list as active (deactivated, deleted or never provisioned). Callers
// refuse the request (RejectNotProvisioned): demoting it to an anonymous
// caller would skip the posture gate and per-user budgets.
var ErrNotProvisioned = errors.New("gateway: subject is deactivated or not provisioned in the directory")

// RejectNotProvisioned is the 403, in the caller's protocol, for ErrNotProvisioned.
func RejectNotProvisioned(path string) *Rejection {
	return &Rejection{Status: http.StatusForbidden, Protocol: protocolOrPrefix(path), Code: "user_not_provisioned",
		Message: "your identity is deactivated or not provisioned in the Halos directory; ask your administrator"}
}

// ErrDirectoryUnavailable is Resolve's answer under FailClosed when halo-server
// cannot be asked and no entry younger than Grace is cached. Callers answer
// RejectDirectoryUnavailable.
var ErrDirectoryUnavailable = errors.New("gateway: directory unavailable")

// RejectDirectoryUnavailable is the 503, in the caller's protocol, for ErrDirectoryUnavailable.
func RejectDirectoryUnavailable(path string) *Rejection {
	return &Rejection{Status: http.StatusServiceUnavailable, Protocol: protocolOrPrefix(path), Code: "directory_unavailable", RetryAfter: 30 * time.Second,
		Message: "halos: your identity cannot be checked right now (the Halos directory is unreachable). Retry shortly."}
}

// Directory fail modes (directory.failMode): what Resolve does when the
// directory cannot be asked and no entry younger than Grace is cached.
const (
	// DirectoryFailOpen (default) keeps the verified subject with no groups:
	// default routing, no experiments, and still the posture gate and per-user
	// budgets. A deactivated user is never demoted to an anonymous caller.
	DirectoryFailOpen = "open"
	// DirectoryFailClosed refuses the request (ErrDirectoryUnavailable, a 503).
	DirectoryFailClosed = "closed"
)

// CheckDirectoryFailMode validates a directory.failMode value ("" = open).
func CheckDirectoryFailMode(m string) error {
	if m != "" && m != DirectoryFailOpen && m != DirectoryFailClosed {
		return fmt.Errorf("directory.failMode %q must be open or closed", m)
	}
	return nil
}

// Resolve returns sub with the directory's groups. It returns nil, nil
// (unknown caller) only when sub is nil, and ErrNotProvisioned when the
// directory does not list sub as active, when halo-server answers the lookup
// with a non-200 status below 500, or when the last cached answer for sub was
// inactive, however old. When halo-server cannot be asked (transport error or
// 5xx) and no entry younger than Grace is cached it returns sub with no groups
// (fail open), or ErrDirectoryUnavailable under FailClosed: never nil, which
// would let an outage turn a deactivated user into an anonymous caller that
// skips the posture gate and per-user budgets. Workload subjects (ADR-0023)
// are not in SCIM: they are returned unchanged without a lookup. Kind and
// Delegation always come from the verified credential, never from the
// directory: a delegated agent (ADR-0024) is looked up as its root principal,
// so an agent acting for a deprovisioned user is refused like the user, and
// keeps its chain (and the agent policy) on every path, fail open included.
// ponytail: concurrent misses for one subject each call halo-server, as PostureClient.Check does.
func (c *DirectoryClient) Resolve(ctx context.Context, sub *policy.Subject) (*policy.Subject, error) {
	if sub == nil || sub.ID == "" {
		return nil, nil
	}
	if sub.Kind == policy.SubjectWorkload {
		return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), sub.Groups...), Kind: sub.Kind, Delegation: sub.Delegation}, nil
	}
	now := c.now()
	c.mu.Lock()
	ce, ok := c.cache[sub.ID]
	c.mu.Unlock()
	e, outcome := ce.e, "ok"
	if !ok || now.Sub(ce.at) >= c.TTL {
		got, err := c.fetch(ctx, sub.ID)
		switch {
		case err == nil:
			e = got
			c.store(sub.ID, got, now)
		case errors.Is(err, errDirectoryRefused):
			// halo-server answered and did not list sub: never an outage, so
			// never fail open. Not cached: a misconfigured token heals at once.
			if c.Log != nil {
				c.Log.Warn("directory refused the lookup; caller refused as not provisioned", "err", err)
			}
			c.observe("not_provisioned")
			return nil, ErrNotProvisioned
		case ok && !ce.e.Active:
			// The last answer was inactive: an outage, however long, never
			// re-admits a deactivated user (fail open included).
			c.observe("not_provisioned")
			return nil, ErrNotProvisioned
		case ok && now.Sub(ce.at) < c.Grace:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; serving cached entry", "err", err)
			}
			outcome = "stale"
		case c.FailClosed:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; request refused (failMode closed)", "err", err)
			}
			c.observe("unavailable")
			return nil, fmt.Errorf("%w: %w", ErrDirectoryUnavailable, err)
		default:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; caller keeps their identity with no groups", "err", err)
			}
			c.observe("failopen")
			return FailOpenSubject(sub), nil
		}
	}
	if !e.Active {
		c.observe("not_provisioned")
		return nil, ErrNotProvisioned
	}
	c.observe(outcome)
	return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), e.Groups...), Kind: sub.Kind, Delegation: sub.Delegation}, nil
}

func (c *DirectoryClient) store(subject string, e DirectoryEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]directoryEntry{}
	}
	if _, known := c.cache[subject]; !known && len(c.cache) >= maxDirectoryEntries {
		// Only active entries are evicted: a cached inactive answer is what keeps
		// a deactivated user refused through an outage (Resolve), so it is never
		// forgotten to make room. Active entries past Grace go first, then all.
		// ponytail: O(n) sweep when full, as PostureClient; an LRU if 100k subjects is routine
		for k, old := range c.cache {
			if old.e.Active && now.Sub(old.at) >= c.Grace {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxDirectoryEntries {
			for k, old := range c.cache {
				if old.e.Active {
					delete(c.cache, k)
				}
			}
		}
		if len(c.cache) >= maxDirectoryEntries {
			// Every entry is inactive (100k deprovisioned subjects with IdP-signed
			// tokens): this answer is not cached rather than forget one of them.
			return
		}
	}
	c.cache[subject] = directoryEntry{e: e, at: now}
}

// errDirectoryRefused: halo-server answered a lookup with a non-200 status
// below 500 (a subject it will not look up, a rejected token, a redirect).
// Only transport errors and 5xx are an outage that may fail open; anything
// else is refused as not provisioned, so a request halo-server rejects can
// never be turned into a fail-open admission.
var errDirectoryRefused = errors.New("directory: lookup refused")

func (c *DirectoryClient) fetch(ctx context.Context, subject string) (DirectoryEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"?"+url.Values{"subject": {subject}}.Encode(), nil)
	if err != nil {
		return DirectoryEntry{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.Client
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return DirectoryEntry{}, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	switch {
	case resp.StatusCode >= 500:
		return DirectoryEntry{}, fmt.Errorf("directory: HTTP %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return DirectoryEntry{}, fmt.Errorf("%w: HTTP %d", errDirectoryRefused, resp.StatusCode)
	}
	var e DirectoryEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDirectoryBody)).Decode(&e); err != nil {
		return DirectoryEntry{}, fmt.Errorf("directory: decode: %w", err)
	}
	return e, nil
}
