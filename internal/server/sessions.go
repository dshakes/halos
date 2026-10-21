package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

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
}

type revocation struct {
	User string `json:"user"`
	At   int64  `json:"at"`
}

// canonicalUser is the one form in which halo-server compares or keys a
// human user id: sessions, devices, enrollments, posture, SCIM userName,
// access-request self-approval and the whoami self check. It lowercases and
// trims surrounding space. Not strings.EqualFold: map keys need a canonical
// string, and EqualFold's Unicode folding (the Kelvin sign K matches k, long
// s matches s) is not what ToLower produces, so a fold-equal pair could match
// in one place and miss in another.
func canonicalUser(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

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

// revoke kills every session of user issued up to now.
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
	at := max(now.UnixNano(), r.before[user])
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

func (r *sessionRevocations) valid(user string, issuedAt int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.log != nil { // another replica may have revoked: fail closed if we cannot tell
		ctx, cancel := storage.Ctx()
		defer cancel()
		if r.log.Catchup(ctx) != nil {
			return false
		}
	}
	b, ok := r.before[canonicalUser(user)]
	return !ok || issuedAt > b
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
