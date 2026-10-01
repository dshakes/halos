package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
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
type deviceStore struct {
	mu     sync.Mutex
	byHash map[string]*Device
	byID   map[string]*Device
	f      *os.File // nil = memory only
	saved  map[string]time.Time
	ttl    time.Duration // for devices persisted without ExpiresAt
}

func openDeviceStore(dir string, ttl time.Duration) (*deviceStore, error) {
	if ttl <= 0 {
		ttl = DefaultDeviceTTL
	}
	d := &deviceStore{byHash: map[string]*Device{}, byID: map[string]*Device{}, saved: map[string]time.Time{}, ttl: ttl}
	if dir == "" {
		return d, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := fsutil.OpenJSONL(filepath.Join(dir, "devices.jsonl"), func(line []byte) {
		var v Device
		if json.Unmarshal(line, &v) == nil && v.ID != "" && v.Hash != "" { // torn line: skip
			d.index(&v)
		}
	})
	if err != nil {
		return nil, err
	}
	d.f = f
	return d, nil
}

func (d *deviceStore) index(v *Device) {
	if old := d.byID[v.ID]; old != nil {
		delete(d.byHash, old.Hash)
	}
	d.byID[v.ID], d.byHash[v.Hash] = v, v
	d.saved[v.ID] = v.LastSeen
}

func (d *deviceStore) persist(v *Device) error {
	if d.f == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.f.Write(append(b, '\n'))
	return err
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
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.persist(v); err != nil {
		return "", Device{}, err
	}
	d.index(v)
	return tok, *v, nil
}

// lookup resolves a token by hash (a map lookup on a SHA-256 leaks nothing useful about the token).
// Revoked devices are errNoDevice, expired ones errDeviceExpired. lastSeen is
// updated in memory and persisted at most every 10 minutes.
func (d *deviceStore) lookup(tok string, now time.Time) (Device, error) {
	if tok == "" {
		return Device{}, errNoDevice
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.byHash[hashDeviceToken(tok)]
	if v == nil || v.Revoked {
		return Device{}, errNoDevice
	}
	exp := v.ExpiresAt
	if exp.IsZero() {
		exp = v.CreatedAt.Add(d.ttl)
	}
	if !now.Before(exp) {
		return Device{}, errDeviceExpired
	}
	v.LastSeen = now
	if now.Sub(d.saved[v.ID]) > lastSeenPersist {
		if d.persist(v) == nil {
			d.saved[v.ID] = now
		}
	}
	return *v, nil
}

func (d *deviceStore) revoke(id string) (Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := d.byID[id]
	if v == nil {
		return Device{}, errNoDevice
	}
	was := v.Revoked
	v.Revoked = true
	if err := d.persist(v); err != nil {
		v.Revoked = was
		return Device{}, err
	}
	return *v, nil
}

func (d *deviceStore) list() []Device {
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
)

type authLimiter struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
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

func (a *authLimiter) get(ip string) *rate.Limiter {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]*rate.Limiter{}
	}
	if len(a.m) >= maxLimiters && a.m[ip] == nil {
		// Bound memory without forgiving everyone: drop limiters that have fully
		// refilled (they hold no penalty), then ones not currently blocking, and
		// only if every IP is blocked, arbitrary ones.
		// ponytail: O(n) scans when full; an LRU list if 10k penalised IPs is routine.
		for k, l := range a.m {
			if l.Tokens() >= authFailBurst {
				delete(a.m, k)
			}
		}
		for _, blockedToo := range []bool{false, true} {
			for k, l := range a.m {
				if len(a.m) < maxLimiters {
					break
				}
				if blockedToo || l.Tokens() >= 1 {
					delete(a.m, k)
				}
			}
		}
	}
	l := a.m[ip]
	if l == nil {
		l = rate.NewLimiter(rate.Every(authFailEvery), authFailBurst)
		a.m[ip] = l
	}
	return l
}

// blocked reports whether ip has exhausted its failure budget.
// Unknown IPs are not blocked and get no limiter (only failures allocate).
func (a *authLimiter) blocked(ip string) bool {
	a.mu.Lock()
	l := a.m[ip]
	a.mu.Unlock()
	return l != nil && l.Tokens() < 1
}
func (a *authLimiter) fail(ip string) { a.get(ip).Allow() }

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
	writeJSON(w, http.StatusOK, map[string]string{"ring": ring.Name, "subject": dev.UserID})
}

func (s *Server) listDevices(w http.ResponseWriter, _ *http.Request, _ Principal) {
	writeJSON(w, http.StatusOK, s.devices.list())
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
