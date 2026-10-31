package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Device is the server-side binding of a device token. Only the SHA-256 of the
// token is ever stored; the token itself is shown once, in the enrollment response.
type Device struct {
	ID        string    `json:"id"` // uuid
	Hash      string    `json:"hash,omitempty"`
	UserID    string    `json:"userID"`
	Groups    []string  `json:"groups,omitempty"` // IdP groups at enrollment; ring is otherwise resolved live
	CreatedAt time.Time `json:"createdAt"`
	LastSeen  time.Time `json:"lastSeen"`
	// LastAuth is when the user last authenticated for this device (enrollment);
	// Groups date from then. The token stops working at ExpiresAt: re-enroll.
	LastAuth  time.Time `json:"lastAuth,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	Revoked   bool      `json:"revoked"`
}

var (
	errNoDevice      = errors.New("device not found")
	errDeviceExpired = errors.New("device enrollment expired: re-enroll")
)

// DefaultDeviceTTL is how long a device token works after enrollment.
const DefaultDeviceTTL = 90 * 24 * time.Hour

// lastSeenPersist bounds how often lastSeen touches disk.
const lastSeenPersist = 10 * time.Minute

// deviceStore is an in-memory index over an append-only JSONL log (last line per id wins).
// ponytail: never compacted beyond open; rotate if devices x lastSeen writes grow.
func (d *deviceStore) close() error { return storage.CloseLog(&d.wmu, d.log) }

// deviceStore locking: wmu serializes the log (Append and Catchup, whose replay
// callback runs inside them) and the read-modify-write sequences built on it;
// mu guards the maps and the Device records in them. mu is only ever held for
// memory work, never across log I/O (an fsync, a database round trip), so a
// slow write does not queue every device authentication behind it. Order: wmu
// before mu.
type deviceStore struct {
	wmu    sync.Mutex
	mu     sync.Mutex
	byHash map[string]*Device
	byID   map[string]*Device
	log    storage.Log // nil = memory only
	saved  map[string]time.Time
	// revPending: revoked in memory, not yet durably logged (a write failed); retried by revokeUser.
	revPending map[string]bool
	ttl        time.Duration     // for devices persisted without ExpiresAt
	cc         storage.Coalescer // shared log: one catch-up serves concurrent lookups
	shared     bool              // the log has other writers (Postgres): see lookup
	// afterMint, when set, runs after a device is minted (test seam: models a
	// deprovisioning racing an enrollment).
	afterMint func()
}

func openDeviceStore(o storage.Opener, ttl time.Duration) (*deviceStore, error) {
	if ttl <= 0 {
		ttl = DefaultDeviceTTL
	}
	d := &deviceStore{byHash: map[string]*Device{}, byID: map[string]*Device{}, saved: map[string]time.Time{}, revPending: map[string]bool{}, ttl: ttl}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, "devices", func(line []byte) {
		var v Device
		if json.Unmarshal(line, &v) == nil && v.ID != "" && v.Hash != "" { // torn line: skip
			d.mu.Lock() // replay also runs from Append/Catchup, beside authentications
			d.index(&v)
			d.mu.Unlock()
		}
	})
	if err != nil {
		return nil, err
	}
	d.log = log
	d.shared = log != nil && !storage.SingleWriter(log)
	return d, nil
}

// index makes v the device's current record. Revocation is sticky: a later
// record still saying not revoked (a lastSeen update another replica wrote
// before it saw the revocation) cannot bring a device back. Caller holds mu.
func (d *deviceStore) index(v *Device) {
	if old := d.byID[v.ID]; old != nil {
		v.Revoked = v.Revoked || old.Revoked
		delete(d.byHash, old.Hash)
	}
	d.byID[v.ID], d.byHash[v.Hash] = v, v
	d.saved[v.ID] = v.LastSeen
}

// persist appends v (caller holds wmu, not mu, and owns v: pass a copy of a
// record other requests can see). A revocation is keyed apart from the
// device's other records, so a shared log compacting by key never drops it.
func (d *deviceStore) persist(v *Device) error {
	if d.log == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	key := v.ID
	if v.Revoked {
		key = "revoked:" + v.ID
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return d.log.Append(ctx, key, b)
}

// catchup applies other replicas' device records (caller holds wmu).
func (d *deviceStore) catchup() error {
	if d.log == nil {
		return nil
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	if err := d.log.Catchup(ctx); err != nil {
		return fmt.Errorf("%w: devices: %w", storage.ErrUnavailable, err)
	}
	return nil
}

// sharedCatchup is catchup for the per-request path: concurrent device
// authentications share one database round trip (storage.Coalescer) and the
// maps are locked only while records are applied (caller holds neither lock).
func (d *deviceStore) sharedCatchup() error {
	if d.log == nil || storage.SingleWriter(d.log) { // nobody else appends: nothing to apply, nothing to wait for
		return nil
	}
	return d.cc.Do(func() error {
		d.wmu.Lock()
		defer d.wmu.Unlock()
		return d.catchup()
	})
}

func hashDeviceToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable (same as randB64)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// mint creates a device for p and returns the plaintext token.
func (d *deviceStore) mint(p Principal, now time.Time) (string, Device, error) {
	tok := randB64(32)
	v := &Device{ID: newUUID(), Hash: hashDeviceToken(tok), UserID: p.ID, Groups: append([]string(nil), p.Groups...),
		CreatedAt: now, LastSeen: now, LastAuth: now, ExpiresAt: now.Add(d.ttl)}
	d.wmu.Lock()
	if err := d.persist(v); err != nil {
		d.wmu.Unlock()
		return "", Device{}, err
	}
	d.mu.Lock()
	d.index(v)
	out := *v
	d.mu.Unlock()
	d.wmu.Unlock()
	if d.afterMint != nil {
		d.afterMint() // after the locks are released
	}
	return tok, out, nil
}

// lookup resolves a token by hash (a map lookup on a SHA-256 leaks nothing useful about the token).
// Revoked devices are errNoDevice, expired ones errDeviceExpired. lastSeen is
// updated in memory and persisted at most every 10 minutes.
func (d *deviceStore) lookup(tok string, now time.Time) (Device, error) {
	if tok == "" {
		return Device{}, errNoDevice
	}
	if err := d.sharedCatchup(); err != nil { // a revocation on another replica must count: fail closed
		return Device{}, err
	}
	if d.shared {
		// Postgres is the contended resource: a write in flight (an enrollment
		// transaction) is let finish before more requests join the database
		// queue behind it. Measured (make load-fleet, 5000 devices enrolling in
		// a minute, two paired runs): without this wait the enrollment rush was
		// slower on Postgres (enroll mean 14 and 27 ms against 8 and 9 ms),
		// since every ring, report and kill-list request then ran beside it. A
		// local file has no such queue, so its requests never wait here.
		d.wmu.Lock()
		d.wmu.Unlock() //nolint:staticcheck // SA2001: the wait is the point
	}
	d.mu.Lock()
	v := d.byHash[hashDeviceToken(tok)]
	if v == nil || v.Revoked {
		d.mu.Unlock()
		return Device{}, errNoDevice
	}
	exp := v.ExpiresAt
	if exp.IsZero() {
		exp = v.CreatedAt.Add(d.ttl)
	}
	if !now.Before(exp) {
		d.mu.Unlock()
		return Device{}, errDeviceExpired
	}
	v.LastSeen = now
	out, id := *v, v.ID
	stale := now.Sub(d.saved[id]) > lastSeenPersist
	d.mu.Unlock()
	if stale {
		d.persistLastSeen(id, now)
	}
	return out, nil
}

// persistLastSeen appends the device's record with its lastSeen, unless another
// request did within lastSeenPersist (it re-checks once it holds the log).
func (d *deviceStore) persistLastSeen(id string, now time.Time) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	d.mu.Lock()
	v := d.byID[id]
	if v == nil || now.Sub(d.saved[id]) <= lastSeenPersist {
		d.mu.Unlock()
		return
	}
	c := *v
	d.mu.Unlock()
	if d.persist(&c) == nil {
		d.mu.Lock()
		d.saved[id] = now
		d.mu.Unlock()
	}
}

func (d *deviceStore) revoke(id string) (Device, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if err := d.catchup(); err != nil {
		return Device{}, err
	}
	d.mu.Lock()
	v := d.byID[id]
	if v == nil {
		d.mu.Unlock()
		return Device{}, errNoDevice
	}
	v.Revoked = true
	d.revPending[id] = true
	c := *v
	d.mu.Unlock()
	// A failed write does not undo the revocation in memory: the log may hold
	// it anyway (written, then the sync failed), a replay may have replaced the
	// record, and a revoked device that works until a restart is the unsafe
	// outcome. The caller answers 500 and the revocation is retried.
	if err := d.persist(&c); err != nil {
		return Device{}, err
	}
	d.mu.Lock()
	delete(d.revPending, id)
	d.mu.Unlock()
	return c, nil
}

func (d *deviceStore) list() []Device {
	if d.log != nil && !storage.SingleWriter(d.log) {
		d.wmu.Lock()
		_ = d.catchup() // display only: serve the last view (the error is counted by the backend)
		d.wmu.Unlock()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Device, 0, len(d.byID))
	for _, v := range d.byID {
		c := *v
		c.Hash = "" // never expose, even hashed
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// ---- failed-auth rate limiting (per remote IP) ----

const (
	authFailBurst = 10
	authFailEvery = 6 * time.Second // sustained: 10 failures/min/IP
	maxLimiters   = 10000
	// sharedFailWindow is the window of the cross-replica failure count: an
	// IP (or IPv6 /64) with authFailBurst failures in it on any replicas is
	// blocked on the replica that sees the count reach it, for this long.
	sharedFailWindow = time.Minute
)

// authLimiter is one endpoint class's failed-auth budget per client address.
// Addresses are keyed by limiterKey (IPv6 by /64). With a shared Backend
// (ADR-0021, amended 2026-10-27) every failure is also counted in the
// Backend, so N replicas grant one budget, not N: the replica whose failure
// brings the shared count to authFailBurst blocks the address for
// sharedFailWindow, and every other replica does at its next failure from it.
// Only failures touch the Backend, and never from an address this replica
// already blocks, so a flood costs at most authFailBurst+N writes a window.
type authLimiter struct {
	mu     sync.Mutex
	m      map[string]*limiterEntry
	class  string         // endpoint class: the shared counter's key prefix
	shared failureCounter // nil = this replica's memory only
	log    *slog.Logger
}

type limiterEntry struct {
	l     *rate.Limiter
	until time.Time // blocked until then by the shared count (zero = not)
}

// failureCounter counts failed authentications across replicas (Backend).
type failureCounter interface {
	// CountAuthFailure adds one failure to key's count in the current window
	// (judged on the store's clock) and returns the count.
	CountAuthFailure(ctx context.Context, key string, window time.Duration) (int64, error)
}

// limiterKey is the address a failure is charged to: an IPv4 address, or
// the /64 of an IPv6 one. A single IPv6 host usually controls its whole /64,
// so keying per /128 would hand it 2^64 fresh budgets.
func limiterKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if a = a.Unmap(); a.Is4() {
		return a.String()
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

// clientIP is the rate-limit key. X-Forwarded-For is honoured only when the
// direct peer is a configured trusted proxy, and is walked right to left,
// skipping trusted hops: the first untrusted address is the client (anything
// further left is client-controlled).
func (s *Server) clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(h)
	if err != nil || !s.trustedProxy(peer) {
		return h
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage from here on is client-supplied; fall back to the last trusted hop
		}
		if !s.trustedProxy(a) {
			return a.Unmap().String()
		}
		peer = a
	}
	return peer.Unmap().String()
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (e *limiterEntry) blocking(now time.Time) bool { return e.l.Tokens() < 1 || now.Before(e.until) }

// get returns key's entry, allocating it (caller holds mu).
func (a *authLimiter) get(key string, now time.Time) *limiterEntry {
	if a.m == nil {
		a.m = map[string]*limiterEntry{}
	}
	if len(a.m) >= maxLimiters && a.m[key] == nil {
		// Bound memory without forgiving everyone: drop limiters that have fully
		// refilled (they hold no penalty), then ones not currently blocking, and
		// only if every IP is blocked, arbitrary ones.
		// ponytail: O(n) scans when full; an LRU list if 10k penalised IPs is routine.
		for k, e := range a.m {
			if e.l.Tokens() >= authFailBurst && !now.Before(e.until) {
				delete(a.m, k)
			}
		}
		for _, blockedToo := range []bool{false, true} {
			for k, e := range a.m {
				if len(a.m) < maxLimiters {
					break
				}
				if blockedToo || !e.blocking(now) {
					delete(a.m, k)
				}
			}
		}
	}
	e := a.m[key]
	if e == nil {
		e = &limiterEntry{l: rate.NewLimiter(rate.Every(authFailEvery), authFailBurst)}
		a.m[key] = e
	}
	return e
}

// blocked reports whether ip has exhausted its failure budget.
// Unknown IPs are not blocked and get no limiter (only failures allocate).
func (a *authLimiter) blocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.m[limiterKey(ip)]
	return e != nil && e.blocking(time.Now())
}

// fail charges one failed authentication to ip, here and, with a shared
// Backend, across replicas. A shared-store error leaves the local budget in
// force (logged): the limiter never fails open further than one replica's.
func (a *authLimiter) fail(ip string) {
	key, now := limiterKey(ip), time.Now()
	a.mu.Lock()
	a.get(key, now).l.Allow()
	a.mu.Unlock()
	if a.shared == nil {
		return
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	n, err := a.shared.CountAuthFailure(ctx, a.class+"/"+key, sharedFailWindow)
	if err != nil {
		orDefault(a.log).Warn("shared failed-auth count unavailable; this replica's budget still applies", "class", a.class, "err", err)
		return
	}
	if n >= authFailBurst {
		a.mu.Lock()
		a.get(key, now).until = now.Add(sharedFailWindow)
		a.mu.Unlock()
	}
}

// ---- handlers ----

func bearer(r *http.Request) string {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return t
}

// deviceAuth authenticates a device token, writing the 401/429 itself on failure.
func (s *Server) deviceAuth(w http.ResponseWriter, r *http.Request) (Device, bool) {
	ip := s.clientIP(r)
	if s.authFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return Device{}, false
	}
	dev, err := s.devices.lookup(bearer(r), s.cfg.Now())
	if errors.Is(err, storage.ErrUnavailable) { // not the client's fault: no rate-limit penalty
		s.cfg.Log.Error("device lookup", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return Device{}, false
	}
	if errors.Is(err, errDeviceExpired) { // a real token, just old: not a guessing attempt
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		apiErr(w, http.StatusUnauthorized, err.Error())
		return Device{}, false
	}
	if err != nil {
		s.authFails.fail(ip)
		w.Header().Set("WWW-Authenticate", "Bearer")
		apiErr(w, http.StatusUnauthorized, "unauthorized")
		return Device{}, false
	}
	g, ok := s.directoryGroups(dev.UserID, dev.Groups) // SCIM-authoritative groups; an unprovisioned user's device is refused
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		apiErr(w, http.StatusUnauthorized, "user is deactivated or not provisioned")
		return Device{}, false
	}
	dev.Groups = g
	return dev, true
}

func (s *Server) getFleetRing(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.deviceAuth(w, r)
	if !ok {
		return
	}
	org, _, _ := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded")
		return
	}
	ring := org.ResolveRing(policy.Subject{ID: dev.UserID, Groups: dev.Groups})
	if ring == nil {
		apiErr(w, http.StatusConflict, "no ring assigned")
		return
	}
	// subject is the device's bound user id, the same id the gateway hashes:
	// halod needs it to pick the device's client-axis experiment variant.
	// groups (from enrollment) let halod evaluate group-targeted feature toggles.
	writeJSON(w, http.StatusOK, map[string]any{"ring": ring.Name, "subject": dev.UserID, "groups": dev.Groups})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, p Principal) {
	all := s.devices.list()
	if f := newReadFilter(p, permRead); !f.all {
		org, err := s.reqPolicy(r)
		all = slices.DeleteFunc(all, func(d Device) bool {
			if err != nil {
				return true
			}
			return !f.ok(s.deviceResource(org, d))
		})
	}
	writeJSON(w, http.StatusOK, all)
}

// visibleHosts is the fleet reports p may read (ADR-0037): all of them with a
// global read grant; else the hosts reporting with a device token whose
// owner's ring and unit a read grant covers. A fleet-token report has no
// owner the server can place, so only global readers see it.
func (s *Server) visibleHosts(p Principal, hosts []Host) []Host {
	f := newReadFilter(p, permRead)
	if f.all {
		return hosts
	}
	org, err := s.org()
	if err != nil {
		return []Host{}
	}
	out := []Host{}
	for _, h := range hosts {
		if h.Device == "" {
			continue
		}
		d, ok := s.devices.get(h.Device)
		if ok && f.ok(s.deviceResource(org, d)) {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, p Principal) {
	dev, err := s.devices.revoke(r.PathValue("id"))
	if err != nil {
		if errors.Is(err, errNoDevice) {
			apiErr(w, http.StatusNotFound, err.Error())
		} else {
			s.cfg.Log.Error("persist revoke", "err", err)
			apiErr(w, http.StatusInternalServerError, "store failed")
		}
		return
	}
	s.cfg.Log.Info("device revoked", "device", dev.ID, "user", dev.UserID, "by", p.ID)
	if err := s.AuditStrict(r.Context(), p.ID, "device.revoke", dev.ID, map[string]string{"user": dev.UserID}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed) // revocation itself is in force
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
