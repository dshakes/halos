package server

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Break-glass (ADR-0036): one sealed local admin account for when the IdP is
// down or misconfigured. It is configured by a password hash, refused unless
// explicitly enabled, every login and every request it makes is a
// high-severity audit entry, and its session is short and never slides.

const (
	// BreakGlassSessionTTL is the fixed lifetime of a break-glass session.
	BreakGlassSessionTTL = 30 * time.Minute
	// BreakGlassMinPassword is the shortest password HashBreakGlassPassword accepts.
	BreakGlassMinPassword = 16
	// BreakGlassIterations is the PBKDF2-HMAC-SHA256 work factor of new hashes
	// (OWASP 2023); a configured hash below breakGlassMinIterations is refused.
	BreakGlassIterations    = 600_000
	breakGlassMinIterations = 600_000
	breakGlassMaxIterations = 10_000_000
	breakGlassHashPrefix    = "pbkdf2-sha256"
	breakGlassSubPrefix     = "breakglass:"
	// breakGlassVerifiers bounds concurrent PBKDF2 verifications: each costs
	// about a CPU-tenth of a second, so the endpoint cannot be used to burn CPU.
	breakGlassVerifiers = 2
)

// BreakGlass configures the break-glass account. Hash is a
// HashBreakGlassPassword string; it is sealed (logins answer 404) unless
// Enabled. User defaults to "breakglass". AllowedCIDRs, when set, are the only
// client addresses (after TrustedProxies) that may use it: login from
// elsewhere answers 404 as if sealed, and a session used from elsewhere is
// refused, so attackers outside them can neither guess nor exhaust it.
type BreakGlass struct {
	Enabled      bool
	User         string
	Hash         string
	AllowedCIDRs []netip.Prefix
}

// Global failed-login lockout (all addresses together, all replicas): past
// breakGlassGlobalFails failures within breakGlassLockWindow, every
// break-glass login is refused for breakGlassLockWindow. Only allowed
// addresses can fail (others get 404 before the password is read), which is
// why AllowedCIDRs is mandatory: otherwise anyone could hold the lock. The
// lock is one KV entry (shared across replicas with a Backend), so every
// replica locks at once, the replica whose write created it audits it once,
// and an SSO admin lifts it with POST /api/v1/breakglass/unlock.
const (
	breakGlassLockWindow = 15 * time.Minute
	kvBreakGlass         = "breakglass-lock"
	breakGlassLockKey    = "global"
	breakGlassFailKey    = "breakglass/global" // the shared failure count (pgstore auth-fail namespace)
	kvAuthFailNS         = "auth-fail"
)

// breakGlassGlobalFails is the global failure budget (a var so tests can lower it).
var breakGlassGlobalFails = int64(20)

// breakGlassLockout counts failures in process (single replica, no Backend).
type breakGlassLockout struct {
	mu    sync.Mutex
	fails []time.Time
}

// count records one failure and returns this window's count.
func (l *breakGlassLockout) count(now time.Time) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.fails[:0]
	for _, t := range l.fails {
		if now.Sub(t) < breakGlassLockWindow {
			keep = append(keep, t)
		}
	}
	l.fails = append(keep, now)
	return int64(len(l.fails))
}

func (l *breakGlassLockout) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails = nil
}

// breakGlassLocked reports whether the global lock is held, on any replica. A
// store error does not lock: the password check still stands, and refusing
// would hand an outage the recovery path too.
func (s *Server) breakGlassLocked() bool {
	ctx, cancel := storage.Ctx()
	defer cancel()
	_, ok, err := s.kv.Get(ctx, kvBreakGlass, breakGlassLockKey)
	if err != nil {
		s.cfg.Log.Warn("break-glass lock unreadable; not treating it as locked", "err", err)
	}
	return ok
}

// breakGlassFailed counts a failed login and takes the lock past the budget.
// It reports whether this call created the lock (exactly one caller, on any
// replica, does), so the lockout is audited once.
func (s *Server) breakGlassFailed() bool {
	ctx, cancel := storage.Ctx()
	defer cancel()
	n := s.bgLock.count(s.cfg.Now())
	if b := s.cfg.Backend; b != nil { // one budget across replicas
		shared, err := b.CountAuthFailure(ctx, breakGlassFailKey, breakGlassLockWindow)
		if err != nil {
			s.cfg.Log.Warn("shared break-glass failure count unavailable; this replica's count still applies", "err", err)
		} else {
			n = shared // the shared count is the budget (and what unlock resets)
		}
	}
	if n < breakGlassGlobalFails {
		return false
	}
	added, err := s.kv.Add(ctx, kvBreakGlass, breakGlassLockKey, nil, s.cfg.Now().Add(breakGlassLockWindow))
	if err != nil {
		s.cfg.Log.Error("break-glass lock not stored", "err", err)
	}
	return added
}

// broadBreakGlassCIDRs returns the allowed ranges broad enough to re-open
// the lockout DoS: IPv4 shorter than /8, IPv6 shorter than /32 (0.0.0.0/0
// and ::/0 included).
func broadBreakGlassCIDRs(cidrs []netip.Prefix) []string {
	var out []string
	for _, p := range cidrs {
		if (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 32) {
			out = append(out, p.String())
		}
	}
	return out
}

// breakGlassUnlock (admin, a person): POST /api/v1/breakglass/unlock lifts
// the global break-glass lockout on every replica and resets its failure
// count, from a normal SSO admin session: the locked path is never needed to
// unlock it. Audited at high severity before it acts.
func (s *Server) breakGlassUnlock(w http.ResponseWriter, r *http.Request, p Principal) {
	if !s.requireHuman(w, r, p, "POST /api/v1/breakglass/unlock") {
		return
	}
	if s.bg == nil {
		apiErr(w, http.StatusNotFound, "break-glass is not configured")
		return
	}
	was := s.breakGlassLocked()
	if err := s.AuditStrict(r.Context(), p.ID, "breakglass.unlock", "", map[string]string{"severity": "high", "wasLocked": strconv.FormatBool(was)}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	err := s.kv.Delete(ctx, kvBreakGlass, breakGlassLockKey)
	if err == nil && s.cfg.Backend != nil {
		err = s.kv.Delete(ctx, kvAuthFailNS, breakGlassFailKey)
	}
	if err != nil {
		s.cfg.Log.Error("break-glass unlock", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	s.bgLock.reset()
	s.cfg.Log.Warn("break-glass lockout lifted", "by", p.ID, "wasLocked", was)
	writeJSON(w, http.StatusOK, map[string]bool{"wasLocked": was})
}

// breakGlassFrom reports whether r's client may use break-glass.
func (s *Server) breakGlassFrom(r *http.Request) bool {
	cidrs := s.cfg.BreakGlass.AllowedCIDRs
	if len(cidrs) == 0 {
		return true
	}
	a, err := netip.ParseAddr(s.clientIP(r))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return slices.ContainsFunc(cidrs, func(p netip.Prefix) bool { return p.Contains(a) })
}

type breakGlassHash struct {
	iter      int
	salt, key []byte
	print     string // fingerprint of the configured hash: sessions die when it changes
}

// parseBreakGlassHash parses pbkdf2-sha256$<iterations>$<salt>$<key> (salt and
// key unpadded base64url; salt >= 16 bytes, key 32 bytes).
func parseBreakGlassHash(s string) (breakGlassHash, error) {
	parts := strings.Split(strings.TrimSpace(s), "$")
	if len(parts) != 4 || parts[0] != breakGlassHashPrefix {
		return breakGlassHash{}, fmt.Errorf("break-glass hash must be %s$<iterations>$<salt>$<key> (halo-server breakglass-hash)", breakGlassHashPrefix)
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < breakGlassMinIterations || iter > breakGlassMaxIterations {
		return breakGlassHash{}, fmt.Errorf("break-glass hash: iterations must be %d..%d", breakGlassMinIterations, breakGlassMaxIterations)
	}
	salt, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	key, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 16 || len(key) != sha256.Size {
		return breakGlassHash{}, errors.New("break-glass hash: salt must be >= 16 bytes and key 32 bytes, unpadded base64url")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return breakGlassHash{iter: iter, salt: salt, key: key, print: hex.EncodeToString(sum[:8])}, nil
}

// HashBreakGlassPassword returns the configuration string for password.
func HashBreakGlassPassword(password string) (string, error) {
	if len(password) < BreakGlassMinPassword {
		return "", fmt.Errorf("break-glass password must be at least %d characters", BreakGlassMinPassword)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("break-glass salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, BreakGlassIterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("break-glass hash: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s", breakGlassHashPrefix, BreakGlassIterations, base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key)), nil
}

// verify reports whether password matches, in constant time over the key.
func (h breakGlassHash) verify(password string) bool {
	k, err := pbkdf2.Key(sha256.New, password, h.salt, h.iter, len(h.key))
	return err == nil && subtle.ConstantTimeCompare(k, h.key) == 1
}

// newBreakGlass validates cfg; a zero BreakGlass is off.
func newBreakGlass(cfg BreakGlass, devUser string) (*breakGlassHash, BreakGlass, error) {
	if cfg.Hash == "" {
		if cfg.Enabled {
			return nil, cfg, errors.New("server: break-glass is enabled but no hash is configured")
		}
		return nil, cfg, nil
	}
	if cfg.User == "" {
		cfg.User = "breakglass"
	}
	if !policy.ValidName(cfg.User) {
		return nil, cfg, fmt.Errorf("server: break-glass user %q must be a lowercase name", cfg.User)
	}
	if cfg.Enabled && len(cfg.AllowedCIDRs) == 0 {
		// Without a range anyone can spend the global failure budget and keep
		// the recovery path locked during the outage it exists for.
		return nil, cfg, errors.New("server: break-glass is enabled without allowed CIDRs: set --breakglass-allowed-cidrs (Helm server.breakGlass.allowedCIDRs) to the VPN or bastion range")
	}
	if devUser != "" && cfg.Enabled {
		return nil, cfg, errors.New("server: break-glass and --dev-insecure-user are exclusive")
	}
	h, err := parseBreakGlassHash(cfg.Hash)
	if err != nil {
		return nil, cfg, fmt.Errorf("server: %w", err)
	}
	return &h, cfg, nil
}

// breakGlassLive refuses a break-glass session once break-glass is disabled
// or its credential rotated.
func (s *Server) breakGlassLive(c cookiePayload) error {
	h := s.bg
	if h == nil || !s.cfg.BreakGlass.Enabled || subtle.ConstantTimeCompare([]byte(c.BG), []byte(h.print)) != 1 ||
		c.Sub != breakGlassSubPrefix+s.cfg.BreakGlass.User {
		return errors.New("break-glass disabled or rotated")
	}
	return nil
}

// BreakGlassLogin is POST /auth/breakglass.
type BreakGlassLogin struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// breakGlassLogin (public): POST /auth/breakglass. 404 unless enabled. Failed
// attempts share the OIDC callback's per-IP budget; every attempt while
// enabled is audited at high severity, and a login whose audit entry cannot be
// written is refused: break-glass is never used unrecorded.
func (s *Server) breakGlassLogin(w http.ResponseWriter, r *http.Request) {
	if s.bg == nil || !s.cfg.BreakGlass.Enabled || !s.breakGlassFrom(r) {
		apiErr(w, http.StatusNotFound, "not found")
		return
	}
	if !sameOrigin(r) {
		apiErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	ip := s.clientIP(r)
	if s.loginFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed logins")
		return
	}
	if s.breakGlassLocked() {
		w.Header().Set("Retry-After", strconv.Itoa(int(breakGlassLockWindow.Seconds())))
		apiErr(w, http.StatusTooManyRequests, "break-glass is locked after too many failed logins; see the audit log")
		return
	}
	var in BreakGlassLogin
	if err := decodeBody(w, r, 4096, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	select {
	case s.bgSem <- struct{}{}:
		defer func() { <-s.bgSem }()
	default:
		w.Header().Set("Retry-After", "5")
		apiErr(w, http.StatusTooManyRequests, "break-glass login busy")
		return
	}
	cfg := s.cfg.BreakGlass
	// Run the KDF whatever the user name, so timing does not tell whether it matched.
	userOK := subtle.ConstantTimeCompare([]byte(in.User), []byte(cfg.User)) == 1
	passOK := s.bg.verify(in.Password)
	sub := breakGlassSubPrefix + cfg.User
	if !userOK || !passOK {
		s.metrics.authFailure("breakglass", "bad_credentials")
		s.loginFails.fail(ip)
		s.cfg.Log.Warn("break-glass login failed", "remote", ip)
		s.Audit(r.Context(), sub, "breakglass.login.failed", "", map[string]string{"severity": "high"})
		if s.breakGlassFailed() { // this replica created the shared lock: the one lockout entry
			s.cfg.Log.Error("BREAK-GLASS LOCKED after repeated failed logins; an SSO admin can lift it with POST /api/v1/breakglass/unlock", "window", breakGlassLockWindow)
			if err := s.AuditStrict(r.Context(), sub, "breakglass.lockout", "", map[string]string{"severity": "high", "window": breakGlassLockWindow.String()}); err != nil {
				s.cfg.Log.Error("break-glass lockout not audited", "err", err) // the lockout holds either way
			}
		}
		apiErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	now := s.cfg.Now()
	iat, ok := s.revoked.issueAt(sub, now)
	if !ok {
		apiErr(w, http.StatusServiceUnavailable, "login unavailable")
		return
	}
	exp := now.Add(BreakGlassSessionTTL)
	if err := s.AuditStrict(r.Context(), sub, "breakglass.login", "", map[string]string{"severity": "high", "expires": exp.UTC().Format(time.RFC3339)}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed) // never usable unrecorded
		return
	}
	s.cfg.Log.Warn("BREAK-GLASS LOGIN: rotate the break-glass password after the incident", "user", sub, "remote", ip, "expires", exp)
	s.setCookie(w, sessionCookie, s.seal(cookiePayload{Sub: sub, BG: s.bg.print, Iat: iat, Seen: now.Unix(), Exp: exp.Unix()}), "/", BreakGlassSessionTTL)
	writeJSON(w, http.StatusOK, map[string]string{"user": sub, "expires": exp.UTC().Format(time.RFC3339)})
}
