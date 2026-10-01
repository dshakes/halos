package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/halos-dev/halos/internal/fsutil"
)

// sessionRevocations is the per-user session epoch: a session cookie issued at
// or before a user's revocation time is dead. Logout and the admin revoke
// endpoint bump it; it is an append-only JSONL log in DataDir so a restart does
// not resurrect sessions.
type sessionRevocations struct {
	mu     sync.Mutex
	before map[string]int64 // user -> unix nanos
	f      *os.File         // nil = memory only
}

type revocation struct {
	User string `json:"user"`
	At   int64  `json:"at"`
}

func openSessionRevocations(dir string) (*sessionRevocations, error) {
	r := &sessionRevocations{before: map[string]int64{}}
	if dir == "" {
		return r, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := fsutil.OpenJSONL(filepath.Join(dir, "session-revocations.jsonl"), func(line []byte) {
		var v revocation
		if json.Unmarshal(line, &v) == nil && v.User != "" && v.At > r.before[v.User] { // torn line: skip
			r.before[v.User] = v.At
		}
	})
	if err != nil {
		return nil, err
	}
	r.f = f
	return r, nil
}

// revoke kills every session of user issued up to now.
func (r *sessionRevocations) revoke(user string, now time.Time) error {
	if user == "" {
		return errors.New("empty user")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	at := max(now.UnixNano(), r.before[user])
	if r.f != nil {
		b, _ := json.Marshal(revocation{user, at}) // plain struct: cannot fail
		if _, err := r.f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	r.before[user] = at
	return nil
}

func (r *sessionRevocations) valid(user string, issuedAt int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.before[user]
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
