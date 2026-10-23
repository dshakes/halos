package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// sessionRevocations is the per-user session epoch: a session cookie issued at
// or before a user's revocation time is dead. Logout and the admin revoke
// endpoint bump it; it is an append-only JSONL log in DataDir so a restart does
// not resurrect sessions. Users are keyed by canonicalUser: an IdP that
// provisions "Alice@Corp.com" must still revoke the session of "alice@corp.com".
type sessionRevocations struct {
	mu     sync.Mutex
	before map[string]int64 // canonicalUser(user) -> unix nanos
	log    storage.Log      // nil = memory only
	cc     storage.Coalescer
}

type revocation struct {
	User string `json:"user"`
	At   int64  `json:"at"`
}

// canonicalUser is policy.CanonicalUser, the one form in which halo-server
// compares or keys a human user id (sessions, devices, enrollments, posture,
// SCIM userName, access-request self-approval, the whoami self check) and in
// which per-user budgets are keyed. Never strings.EqualFold or
// strings.ToLower: both fold lookalikes such as the Kelvin sign into ASCII
// letters, which would let "Kelly" share kelly's sessions and budget.
func canonicalUser(id string) string { return policy.CanonicalUser(id) }

// sameUser reports whether a and b name the same user (canonicalUser).
func sameUser(a, b string) bool { return canonicalUser(a) == canonicalUser(b) }

func (r *sessionRevocations) close() error { return storage.CloseLog(&r.mu, r.log) }

func openSessionRevocations(o storage.Opener) (*sessionRevocations, error) {
	r := &sessionRevocations{before: map[string]int64{}}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, "session-revocations", func(line []byte) {
		var v revocation
		if json.Unmarshal(line, &v) != nil || v.User == "" { // torn line: skip
			return
		}
		if k := canonicalUser(v.User); v.At > r.before[k] { // lines written before keys were canonical, too
			r.before[k] = v.At
		}
	})
	if err != nil {
		return nil, err
	}
	r.log = log
	return r, nil
}

// revocationSkew pads every revocation epoch. Replicas compare a cookie's
// issue time (one replica's clock) with the epoch (another's): without the
// pad, a session minted on a replica whose clock runs behind the revoking one
// would outlive the revocation. A login after a revocation stamps its cookie
// past the epoch instead (issueAt), so the pad never locks anyone out.
const revocationSkew = time.Minute

// revoke kills every session of user issued up to now (+revocationSkew).
func (r *sessionRevocations) revoke(user string, now time.Time) error {
	if user == "" {
		return errors.New("empty user")
	}
	user = canonicalUser(user)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.log != nil {
		ctx, cancel := storage.Ctx()
		defer cancel()
		if err := r.log.Catchup(ctx); err != nil {
			return err
		}
	}
	at := max(now.Add(revocationSkew).UnixNano(), r.before[user])
	if r.log != nil {
		b, _ := json.Marshal(revocation{user, at}) // plain struct: cannot fail
		ctx, cancel := storage.Ctx()
		defer cancel()
		if err := r.log.Append(ctx, "", b); err != nil {
			return err
		}
	}
	r.before[user] = max(at, r.before[user]) // a foreign revocation replayed by Append may be later
	return nil
}

// catchup applies other replicas' revocations. Concurrent callers share one
// database round trip (storage.Coalescer) and r.mu is held only while
// records are applied, not while every request waits for its own query.
func (r *sessionRevocations) catchup() error {
	if r.log == nil {
		return nil
	}
	return r.cc.Do(func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		ctx, cancel := storage.Ctx()
		defer cancel()
		return r.log.Catchup(ctx)
	})
}

func (r *sessionRevocations) valid(user string, issuedAt int64) bool {
	if r.catchup() != nil { // another replica may have revoked: fail closed if we cannot tell
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.before[canonicalUser(user)]
	return !ok || issuedAt > b
}

// issueAt is the issue time to stamp on a new session for user: now, or the
// first whole second past user's revocation epoch when that is later (a fresh
// login right after a padded revocation must not be born dead). Whole second:
// delegated credentials carry the root's auth_time in OIDC seconds (the
// session's iat rounded down), and liveHumanRoot compares that with the
// nanosecond epoch, so the rounded-down stamp must itself be past the epoch.
// ok=false: the store is unreadable, so the epoch is unknown.
func (r *sessionRevocations) issueAt(user string, now time.Time) (int64, bool) {
	if r.catchup() != nil {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.before[canonicalUser(user)]
	if !ok {
		return now.UnixNano(), true
	}
	const sec = int64(time.Second)
	return max(now.UnixNano(), (b/sec+1)*sec), true
}

// revokeSessions (admin): POST /api/v1/users/{id}/revoke-sessions logs the user out everywhere.
func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request, p Principal) {
	user := r.PathValue("id")
	if err := s.revoked.revoke(user, s.cfg.Now()); err != nil {
		s.cfg.Log.Error("persist session revocation", "user", user, "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	s.cfg.Log.Info("sessions revoked", "user", user, "by", p.ID)
	if err := s.AuditStrict(r.Context(), p.ID, "session.revoke", user, nil); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed) // revocation itself is in force
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
