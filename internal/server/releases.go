package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
)

const (
	releaseCacheTTL   = 30 * time.Second
	releaseFetchLimit = 15 * time.Second
	// ExpiryWarning is how close to expiry a ring pointer is flagged.
	ExpiryWarning = 48 * time.Hour
)

// pointerFetch reads and signature-verifies one ring's pointer; found=false means none published.
type pointerFetch func(ctx context.Context, ring string) (p bundle.Pointer, found bool, err error)

// channelsFetch returns the experiment channels the (verified) release p names
// routes p.Ring's devices to.
type channelsFetch func(ctx context.Context, p bundle.Pointer) ([]string, error)

type cachedPointer struct {
	p     bundle.Pointer
	found bool
	at    time.Time
}

// releaseCache keeps the last verified pointer per ring/channel. Only verified,
// org-matching, non-regressing state is ever stored, so the console never shows
// anything unverified or replayed.
type releaseCache struct {
	mu    sync.Mutex // held across fetches: one registry round-trip at a time
	byKey map[string]cachedPointer
	// chans: "<ring>@<release digest>" -> channels. Releases are immutable, so
	// entries never expire. ponytail: grows by one entry per ring x release seen.
	chans map[string][]string
}

func (s *Server) registry() (oras.ReadOnlyTarget, bundle.Verifier, error) {
	pt := s.cfg.Portal
	if pt.Registry == "" || pt.PubKeyPEM == "" {
		return nil, nil, errors.New("registry or public key not configured in portal config")
	}
	v, err := bundle.ParseEd25519Verifier([]byte(pt.PubKeyPEM))
	if err != nil {
		return nil, nil, err
	}
	repo, err := bundle.Repository(pt.Registry, pt.RegistryPlainHTTP)
	if err != nil {
		return nil, nil, err
	}
	return repo, v, nil
}

// registryFetch is the production pointerFetch: read-only, ed25519-verified.
func (s *Server) registryFetch(ctx context.Context, ring string) (bundle.Pointer, bool, error) {
	repo, v, err := s.registry()
	if err != nil {
		return bundle.Pointer{}, false, err
	}
	return bundle.ReadPointer(ctx, repo, ring, v)
}

// registryChannels is the production channelsFetch (downloads and verifies the release).
func (s *Server) registryChannels(ctx context.Context, p bundle.Pointer) ([]string, error) {
	repo, v, err := s.registry()
	if err != nil {
		return nil, err
	}
	return bundle.PointerChannels(ctx, repo, v, p)
}

// pointerView is one ring/channel pointer as the console shows it.
type pointerView struct {
	p                        bundle.Pointer
	found, stale, suspicious bool
	err                      string
}

// lookup returns name's pointer, refetched once the cached copy is older than
// releaseCacheTTL. A fetch that fails, is for another org, or regresses (lower
// seq, same seq naming another digest, or vanished) never replaces the last
// good pointer: that one keeps being shown, flagged stale (and suspicious for
// the org/regression cases, which smell of a registry replay).
func (s *Server) lookup(ctx context.Context, name, org string, now time.Time) pointerView {
	c := s.relCache
	cp, have := c.byKey[name]
	var v pointerView
	if !have || now.Sub(cp.at) >= releaseCacheTTL {
		p, found, err := s.relFetch(ctx, name)
		last := have && cp.found
		if err == nil {
			v.suspicious = true
			switch {
			case found && p.Org != org:
				err = fmt.Errorf("pointer for %s is signed for org %q, not %q", name, p.Org, org)
			case last && !found:
				err = fmt.Errorf("pointer for %s disappeared (last seen seq %d)", name, cp.p.Seq)
			case last && p.Seq < cp.p.Seq:
				err = fmt.Errorf("pointer for %s regressed to seq %d (last seen %d): replay?", name, p.Seq, cp.p.Seq)
			case last && p.Seq == cp.p.Seq && p.Digest != cp.p.Digest:
				err = fmt.Errorf("pointer for %s reuses seq %d for another digest", name, p.Seq)
			default:
				v.suspicious = false
			}
		}
		if err == nil {
			cp, have = cachedPointer{p: p, found: found, at: now}, true
			c.byKey[name] = cp
		} else {
			s.cfg.Log.Warn("ring pointer unavailable", "ring", name, "suspicious", v.suspicious, "err", err)
			v.err, v.stale = err.Error(), have
		}
	}
	v.p, v.found = cp.p, have && cp.found
	return v
}

// channels returns the channels ring pointer p's release routes to (cached per release).
func (s *Server) channels(ctx context.Context, p bundle.Pointer) ([]string, error) {
	c := s.relCache
	k := p.Ring + "@" + p.Digest
	if ch, ok := c.chans[k]; ok {
		return ch, nil
	}
	ch, err := s.relChannels(ctx, p)
	if err != nil {
		return nil, err
	}
	c.chans[k] = ch
	return ch, nil
}

// ConvergenceView counts a ring's devices on the ring's current digest vs others.
type ConvergenceView struct {
	Total    int            `json:"total"`
	OnDigest int            `json:"onDigest"`
	Other    int            `json:"other"`
	Digests  map[string]int `json:"digests"`
}

// RingRelease is one ring's row in GET /api/v1/releases.
type RingRelease struct {
	Ring         string           `json:"ring"`
	Published    bool             `json:"published"` // a verified pointer exists
	Org          string           `json:"org,omitempty"`
	Digest       string           `json:"digest,omitempty"`
	Seq          uint64           `json:"seq,omitempty"`
	IssuedAt     *time.Time       `json:"issuedAt,omitempty"`
	ExpiresAt    *time.Time       `json:"expiresAt,omitempty"`
	ExpiresInSec int64            `json:"expiresInSeconds,omitempty"`
	Expired      bool             `json:"expired"`
	ExpiringSoon bool             `json:"expiringSoon"` // <48h left (and not yet expired)
	Stale        bool             `json:"stale"`
	Suspicious   bool             `json:"suspicious"` // registry served a foreign-org or regressed pointer; last good shown
	Error        string           `json:"error,omitempty"`
	Channels     []ChannelRelease `json:"channels"`    // client-axis experiment channels the ring's release routes to
	Convergence  ConvergenceView  `json:"convergence"` // hosts on the ring digest or one of its channels' digests are converged
	Drift        int              `json:"driftHosts"`
}

// ChannelRelease is one experiment channel of a ring's current release.
type ChannelRelease struct {
	Channel    string     `json:"channel"`
	Published  bool       `json:"published"`
	Digest     string     `json:"digest,omitempty"`
	Seq        uint64     `json:"seq,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Expired    bool       `json:"expired"`
	Stale      bool       `json:"stale"`
	Suspicious bool       `json:"suspicious"`
	Error      string     `json:"error,omitempty"`
	Devices    int        `json:"devices"` // ring hosts reporting this channel's digest
}

// ReleasesResponse is GET /api/v1/releases.
type ReleasesResponse struct {
	Rings    []RingRelease `json:"rings"`
	Stale    bool          `json:"stale"` // some ring shows cached state because the registry could not be read
	Registry string        `json:"registry"`
}

func (s *Server) getReleases(w http.ResponseWriter, r *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	var names []string
	for _, rg := range org.Rings {
		names = append(names, rg.Name)
	}
	stats := map[string]RingStats{}
	for _, rs := range Aggregate(s.cfg.Store.All(), names) {
		stats[rs.Ring] = rs
	}
	now := s.cfg.Now()
	resp := ReleasesResponse{Rings: make([]RingRelease, 0, len(names)), Registry: s.cfg.Portal.Registry}

	s.relCache.mu.Lock()
	defer s.relCache.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), releaseFetchLimit)
	defer cancel()
	for _, name := range names {
		row := RingRelease{Ring: name, Channels: []ChannelRelease{}}
		pv := s.lookup(ctx, name, org.Name, now)
		row.Error, row.Stale, row.Suspicious = pv.err, pv.stale, pv.suspicious
		if pv.found {
			p := pv.p
			row.Published, row.Org, row.Digest, row.Seq = true, p.Org, p.Digest, p.Seq
			row.IssuedAt, row.ExpiresAt = &p.IssuedAt, &p.ExpiresAt
			left := p.ExpiresAt.Sub(now)
			row.Expired, row.ExpiringSoon, row.ExpiresInSec = left <= 0, left > 0 && left < ExpiryWarning, int64(left.Seconds())
			chans, err := s.channels(ctx, p)
			if err != nil {
				s.cfg.Log.Warn("ring release channels unavailable", "ring", name, "err", err)
				row.Error = strings.TrimPrefix(row.Error+"; channels: "+err.Error(), "; ")
			}
			for _, ch := range chans {
				cv := s.lookup(ctx, ch, org.Name, now)
				cr := ChannelRelease{Channel: ch, Stale: cv.stale, Suspicious: cv.suspicious, Error: cv.err}
				if cv.found {
					cr.Published, cr.Digest, cr.Seq, cr.ExpiresAt = true, cv.p.Digest, cv.p.Seq, &cv.p.ExpiresAt
					cr.Expired = !now.Before(cv.p.ExpiresAt)
				}
				row.Stale, row.Suspicious = row.Stale || cr.Stale, row.Suspicious || cr.Suspicious
				row.Channels = append(row.Channels, cr)
			}
		}
		row.Convergence = ConvergenceView{Digests: map[string]int{}}
		if rs, ok := stats[name]; ok {
			row.Convergence = ConvergenceView{Total: rs.Hosts, Digests: rs.Digests}
			counted := map[string]bool{}
			if row.Published {
				row.Convergence.OnDigest, counted[row.Digest] = rs.Digests[row.Digest], true
			}
			for i := range row.Channels {
				ch := &row.Channels[i]
				if ch.Published {
					ch.Devices = rs.Digests[ch.Digest]
					if !counted[ch.Digest] {
						row.Convergence.OnDigest, counted[ch.Digest] = row.Convergence.OnDigest+ch.Devices, true
					}
				}
			}
			row.Convergence.Other = rs.Hosts - row.Convergence.OnDigest
			row.Drift = rs.Drift
		}
		resp.Stale = resp.Stale || row.Stale
		resp.Rings = append(resp.Rings, row)
	}
	writeJSON(w, http.StatusOK, resp)
}
