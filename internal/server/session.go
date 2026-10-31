package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Session policy (ADR-0036): an absolute lifetime fixed at login and an idle
// timeout that slides with use. Both are enforced from the signed cookie, so
// every replica agrees without shared state.
const (
	DefaultSessionTTL  = 12 * time.Hour
	DefaultSessionIdle = time.Hour
	MinSessionTTL      = 5 * time.Minute
	MaxSessionTTL      = 7 * 24 * time.Hour
	MinSessionIdle     = time.Minute
	// sessionTTL is the default absolute lifetime (kept under its old name).
	sessionTTL = DefaultSessionTTL
)

// SessionPolicy bounds console sessions. TTL 0 = DefaultSessionTTL. Idle 0 =
// DefaultSessionIdle (capped at TTL); a negative Idle turns the idle timeout off.
type SessionPolicy struct {
	TTL  time.Duration
	Idle time.Duration
}

// normalize applies defaults and validates p.
func (p SessionPolicy) normalize() (SessionPolicy, error) {
	if p.TTL == 0 {
		p.TTL = DefaultSessionTTL
	}
	if p.TTL < MinSessionTTL || p.TTL > MaxSessionTTL {
		return p, fmt.Errorf("server: session TTL %s out of range [%s, %s]", p.TTL, MinSessionTTL, MaxSessionTTL)
	}
	switch {
	case p.Idle == 0:
		p.Idle = min(DefaultSessionIdle, p.TTL)
	case p.Idle < 0:
		p.Idle = 0 // off
	case p.Idle < MinSessionIdle:
		return p, fmt.Errorf("server: session idle timeout %s is under %s", p.Idle, MinSessionIdle)
	case p.Idle > p.TTL:
		return p, fmt.Errorf("server: session idle timeout %s exceeds the session TTL %s", p.Idle, p.TTL)
	}
	return p, nil
}

// slideEvery is how stale a cookie's last-seen time may get before it is
// re-issued: a tenth of the idle timeout, so a session never ends more than
// that much earlier than idle-after-last-request, and an active console does
// not get a Set-Cookie on every call.
func (p SessionPolicy) slideEvery() time.Duration { return p.Idle / 10 }

// lastSeen is the cookie's last activity: Seen, else (cookies issued before
// the idle timeout existed) the issue time. 0 means neither: such a cookie
// was never minted by a login, which always sets both.
func (c cookiePayload) lastSeen() int64 {
	if c.Seen != 0 {
		return c.Seen
	}
	return c.Iat / int64(time.Second)
}

var errSessionIdle = errors.New("session idle timeout")

// sessionLive applies the checks a sealed, unexpired session cookie must pass
// beyond its signature and expiry: the idle timeout, and for a break-glass
// session that break-glass is still enabled with the same credential.
func (s *Server) sessionLive(c cookiePayload) error {
	if c.BG != "" {
		return s.breakGlassLive(c)
	}
	if idle := s.session.Idle; idle > 0 {
		if last := c.lastSeen(); last != 0 && s.cfg.Now().Unix()-last > int64(idle/time.Second) {
			return errSessionIdle
		}
	}
	return nil
}

// sessionDeadline is when c stops being usable if nothing slides it: its
// absolute expiry, or sooner its idle deadline. Credentials delegated from a
// session (ADR-0024) never outlive it, and every credential delegated from
// those is bounded by its parent's expiry, so a whole chain dies with the
// idle session rather than living to the absolute TTL.
func (s *Server) sessionDeadline(c cookiePayload) time.Time {
	exp := time.Unix(c.Exp, 0)
	if idle := s.session.Idle; idle > 0 {
		if last := c.lastSeen(); last != 0 {
			if d := time.Unix(last, 0).Add(idle); d.Before(exp) {
				exp = d
			}
		}
	}
	return exp
}

// slide re-issues c with a fresh last-seen time when the idle timeout is on
// and the cookie's is older than slideEvery. The absolute expiry never moves.
// Break-glass sessions do not slide: their lifetime is fixed.
func (s *Server) slide(w http.ResponseWriter, c cookiePayload) {
	if s.session.Idle <= 0 || c.BG != "" || c.Sub == "" {
		return
	}
	now := s.cfg.Now()
	if now.Unix()-c.lastSeen() < int64(s.session.slideEvery()/time.Second) {
		return
	}
	left := time.Unix(c.Exp, 0).Sub(now)
	if left <= 0 {
		return
	}
	c.Seen = now.Unix()
	s.setCookie(w, sessionCookie, s.seal(c), "/", left)
}
