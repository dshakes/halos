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
	// DefaultRevocationTTL is how long the revocation list (ADR-0026) is
	// used before halo-server is asked again: with halo-server reachable, a
	// revocation reaches the gateway within this (plus one fetch).
	DefaultRevocationTTL = 30 * time.Second
	maxDirectoryEntries  = 100_000
	maxDirectoryBody     = 64 << 10
	maxRevocationBody    = 4 << 20
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
	// RevocationTTL: the revocation list is refetched once it is older
	// (0 = DefaultRevocationTTL). It is fetched only for callers holding a
	// halo-server credential (workload or delegated agent).
	RevocationTTL time.Duration

	mu    sync.Mutex
	cache map[string]directoryEntry

	revMu    sync.Mutex // guards rev and revAt
	rev      *RevocationList
	revAt    time.Time
	revFetch sync.Mutex // one revocation fetch at a time
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
// A caller holding a halo-server credential (workload or delegated agent)
// is first checked against the revocation list (ADR-0026, see revocations):
// a revoked credential is ErrCredentialRevoked, workload-rooted chains
// included.
// ponytail: concurrent misses for one subject each call halo-server, as PostureClient.Check does.
func (c *DirectoryClient) Resolve(ctx context.Context, sub *policy.Subject) (*policy.Subject, error) {
	if sub == nil || sub.ID == "" {
		return nil, nil
	}
	if sub.Credential != nil {
		l, err := c.revocations(ctx)
		if err != nil {
			return nil, err
		}
		if err := l.Check(sub); err != nil {
			return nil, err
		}
	}
	if sub.Kind == policy.SubjectWorkload {
		return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), sub.Groups...), Kind: sub.Kind, Delegation: sub.Delegation, Credential: sub.Credential}, nil
	}
	now := c.now()
	c.mu.Lock()
	ce, ok := c.cache[sub.ID]
	c.mu.Unlock()
	e := ce.e
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
			return nil, ErrNotProvisioned
		case ok && !ce.e.Active:
			// The last answer was inactive: an outage, however long, never
			// re-admits a deactivated user (fail open included).
			return nil, ErrNotProvisioned
		case ok && now.Sub(ce.at) < c.Grace:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; serving cached entry", "err", err)
			}
		case c.FailClosed:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; request refused (failMode closed)", "err", err)
			}
			return nil, fmt.Errorf("%w: %w", ErrDirectoryUnavailable, err)
		default:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; caller keeps their identity with no groups", "err", err)
			}
			return &policy.Subject{ID: sub.ID, Kind: sub.Kind, Delegation: sub.Delegation, Credential: sub.Credential}, nil
		}
	}
	if !e.Active {
		return nil, ErrNotProvisioned
	}
	return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), e.Groups...), Kind: sub.Kind, Delegation: sub.Delegation, Credential: sub.Credential}, nil
}

// revocations returns the revocation list, refetched once older than
// RevocationTTL. One caller fetches at a time; meanwhile the others keep a
// list younger than Grace. When halo-server cannot be asked, the directory's
// fail mode applies: a list younger than Grace keeps serving; past it, fail
// closed refuses (ErrDirectoryUnavailable) and fail open keeps the last list,
// however old, so an outage never forgets a revocation the gateway has seen.
// Any answer but 200 is an outage here: an old halo-server without the list
// answers 400, and the fail mode decides.
func (c *DirectoryClient) revocations(ctx context.Context) (*RevocationList, error) {
	ttl := c.RevocationTTL
	if ttl <= 0 {
		ttl = DefaultRevocationTTL
	}
	cur := func() (*RevocationList, time.Duration) {
		c.revMu.Lock()
		defer c.revMu.Unlock()
		return c.rev, c.now().Sub(c.revAt)
	}
	l, age := cur()
	if l != nil && age < ttl {
		return l, nil
	}
	if !c.revFetch.TryLock() {
		if l != nil && age < c.Grace {
			return l, nil
		}
		c.revFetch.Lock()
	}
	defer c.revFetch.Unlock()
	if l, age = cur(); l != nil && age < ttl { // refreshed while this caller waited
		return l, nil
	}
	got, err := c.fetchRevocations(ctx)
	if err == nil {
		c.revMu.Lock()
		c.rev, c.revAt = got, c.now()
		c.revMu.Unlock()
		return got, nil
	}
	switch {
	case l != nil && age < c.Grace:
		c.warn("revocation list refresh failed; serving the cached list", err)
		return l, nil
	case c.FailClosed:
		c.warn("revocation list unavailable; credential refused (failMode closed)", err)
		return nil, fmt.Errorf("%w: revocations: %w", ErrDirectoryUnavailable, err)
	}
	c.warn("revocation list unavailable; checking against the last list seen (failMode open)", err)
	return l, nil
}

func (c *DirectoryClient) warn(msg string, err error) {
	if c.Log != nil {
		c.Log.Warn(msg, "err", err)
	}
}

func (c *DirectoryClient) fetchRevocations(ctx context.Context) (*RevocationList, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"?revocations=1", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.Client
	if hc == nil {
		hc = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocations: HTTP %d", resp.StatusCode)
	}
	var l RevocationList
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRevocationBody)).Decode(&l); err != nil {
		return nil, fmt.Errorf("revocations: decode: %w", err)
	}
	return &l, nil
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
