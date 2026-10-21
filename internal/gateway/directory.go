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

// Resolve returns sub with the directory's groups. It returns nil, nil
// (unknown caller) when sub is nil, or when halo-server cannot be asked and no
// entry younger than Grace is cached; and ErrNotProvisioned when the directory
// does not list sub as active. Workload subjects (ADR-0023) are not in SCIM:
// they are returned unchanged without a lookup. Kind always comes from the
// verified credential, never from the directory.
// ponytail: concurrent misses for one subject each call halo-server, as PostureClient.Check does.
func (c *DirectoryClient) Resolve(ctx context.Context, sub *policy.Subject) (*policy.Subject, error) {
	if sub == nil || sub.ID == "" {
		return nil, nil
	}
	if sub.Kind == policy.SubjectWorkload {
		return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), sub.Groups...), Kind: sub.Kind}, nil
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
		case ok && now.Sub(ce.at) < c.Grace:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; serving cached entry", "err", err)
			}
		default:
			if c.Log != nil {
				c.Log.Warn("directory lookup failed; caller treated as unknown", "err", err)
			}
			return nil, nil
		}
	}
	if !e.Active {
		return nil, ErrNotProvisioned
	}
	return &policy.Subject{ID: sub.ID, Groups: append([]string(nil), e.Groups...), Kind: sub.Kind}, nil
}

func (c *DirectoryClient) store(subject string, e DirectoryEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]directoryEntry{}
	}
	if len(c.cache) >= maxDirectoryEntries {
		for k, old := range c.cache { // ponytail: O(n) sweep when full, as PostureClient; an LRU if 100k subjects is routine
			if now.Sub(old.at) >= c.Grace {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxDirectoryEntries {
			clear(c.cache)
		}
	}
	c.cache[subject] = directoryEntry{e: e, at: now}
}

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
	if resp.StatusCode != http.StatusOK {
		return DirectoryEntry{}, fmt.Errorf("directory: HTTP %d", resp.StatusCode)
	}
	var e DirectoryEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDirectoryBody)).Decode(&e); err != nil {
		return DirectoryEntry{}, fmt.Errorf("directory: decode: %w", err)
	}
	return e, nil
}
