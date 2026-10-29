package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Per-credential revocation (ADR-0026). An admin revokes one credential by
// jti, or a subject (an agent, a workload, a human root) by epoch: every
// credential issued at or before the epoch for it, or with it anywhere in
// its delegation chain, is dead. halo-server checks the shared store on every
// exchange and egress decision; gateways check the list they fetch with the
// directory (gateway.DirectoryClient).

const (
	revokeJTI     = "jti"
	revokeSubject = "subject"
	// revocationLife is how long a row lives past its epoch (subject) or its
	// creation (jti): no credential issued before either outlives it, so a
	// row past it can match nothing and is dropped.
	revocationLife = policy.MaxWorkloadTTL + revocationSkew
	// maxActiveRevocations caps the live rows, which bounds the list every
	// gateway fetches. Past it, revoke a subject or rotate the workload key.
	maxActiveRevocations = 10000
	maxRevokeReason      = 1000
	maxRevokeJTI         = 128
	// revocationLogName is the single-replica log (DataDir/<name>.jsonl).
	revocationLogName = "credential-revocations"
)

// revocationStore is where revocations live: the Backend (shared across
// replicas), or revocationLog on a single replica.
type revocationStore interface {
	// PutRevocation records r; a live row's epoch and expiry only move forward.
	PutRevocation(ctx context.Context, r pgstore.Revocation) error
	// Revocations lists every live revocation.
	Revocations(ctx context.Context) ([]pgstore.Revocation, error)
	// RevocationsFor lists the live revocations of these jtis and subjects.
	RevocationsFor(ctx context.Context, jtis, subjects []string) ([]pgstore.Revocation, error)
}

// revocationLog is the single-replica revocationStore: in memory, and a JSONL
// log under DataDir (none without one) so a restart keeps every revocation.
// ponytail: the file is never compacted (expired rows are skipped on replay);
// rewrite it on start if revocation volume ever makes it large.
type revocationLog struct {
	mu  sync.Mutex
	m   map[[2]string]pgstore.Revocation
	log storage.Log
	now func() time.Time
}

func openRevocationLog(o storage.Opener, now func() time.Time) (*revocationLog, error) {
	l := &revocationLog{m: map[[2]string]pgstore.Revocation{}, now: now}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, revocationLogName, func(line []byte) {
		var r pgstore.Revocation
		if json.Unmarshal(line, &r) == nil && r.Key != "" { // torn line: skip
			l.merge(r)
		}
	})
	if err != nil {
		return nil, err
	}
	l.log = log
	return l, nil
}

func (l *revocationLog) close() error { return storage.CloseLog(&l.mu, l.log) }

// merge applies r with PutRevocation's semantics (caller holds mu, or replays).
func (l *revocationLog) merge(r pgstore.Revocation) {
	k := [2]string{r.Kind, r.Key}
	if cur, ok := l.m[k]; ok && cur.Expires.After(l.now()) {
		if cur.Epoch > r.Epoch {
			r.Epoch, r.Record = cur.Epoch, cur.Record
		}
		if cur.Expires.After(r.Expires) {
			r.Expires = cur.Expires
		}
	}
	l.m[k] = r
}

func (l *revocationLog) PutRevocation(ctx context.Context, r pgstore.Revocation) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.log != nil {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("encode revocation: %w", err)
		}
		if err := l.log.Append(ctx, "", b); err != nil {
			return err
		}
	}
	l.merge(r)
	return nil
}

func (l *revocationLog) Revocations(context.Context) ([]pgstore.Revocation, error) {
	return l.filter(func(pgstore.Revocation) bool { return true }), nil
}

func (l *revocationLog) RevocationsFor(_ context.Context, jtis, subjects []string) ([]pgstore.Revocation, error) {
	return l.filter(func(r pgstore.Revocation) bool {
		return (r.Kind == revokeJTI && slices.Contains(jtis, r.Key)) || (r.Kind == revokeSubject && slices.Contains(subjects, r.Key))
	}), nil
}

// filter returns the live rows keep accepts, sorted, dropping expired ones.
func (l *revocationLog) filter(keep func(pgstore.Revocation) bool) []pgstore.Revocation {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var out []pgstore.Revocation
	for k, r := range l.m {
		if !r.Expires.After(now) {
			delete(l.m, k)
			continue
		}
		if keep(r) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b pgstore.Revocation) int { return strings.Compare(a.Kind+"\x00"+a.Key, b.Kind+"\x00"+b.Key) })
	return out
}

// revocationRecord is pgstore.Revocation.Record: who revoked, why, when.
type revocationRecord struct {
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// RevokeRequest is POST /api/v1/revocations: exactly one of JTI and Subject,
// and a Reason (recorded in the audit log).
type RevokeRequest struct {
	JTI     string `json:"jti,omitempty"`
	Subject string `json:"subject,omitempty"`
	Reason  string `json:"reason"`
}

// Revocation is one active revocation (GET /api/v1/revocations, and the
// answer to POST).
type Revocation struct {
	JTI     string `json:"jti,omitempty"`
	Subject string `json:"subject,omitempty"`
	// RevokedBefore: a subject's credentials issued at or before it are dead.
	RevokedBefore *time.Time `json:"revokedBefore,omitempty"`
	Expires       time.Time  `json:"expires"` // the row is dropped then: nothing it matches can still be valid
	By            string     `json:"by"`
	Reason        string     `json:"reason"`
	At            time.Time  `json:"at"`
}

// RevocationsResponse is GET /api/v1/revocations.
type RevocationsResponse struct {
	Revocations []Revocation `json:"revocations"`
}

func revocationView(r pgstore.Revocation) Revocation {
	var rec revocationRecord
	_ = json.Unmarshal(r.Record, &rec) // written by this package; garbage shows as empty fields
	v := Revocation{Expires: r.Expires.UTC(), By: rec.By, Reason: rec.Reason, At: rec.At.UTC()}
	if r.Kind == revokeJTI {
		v.JTI = r.Key
	} else {
		v.Subject = r.Key
		t := time.Unix(r.Epoch, 0).UTC()
		v.RevokedBefore = &t
	}
	return v
}

// revocationList is rows as the gateway list (and the check) sees them.
func revocationList(rows []pgstore.Revocation) *gateway.RevocationList {
	l := &gateway.RevocationList{JTIs: map[string]int64{}, Subjects: map[string]int64{}}
	for _, r := range rows {
		if r.Kind == revokeJTI {
			l.JTIs[r.Key] = r.Expires.Unix()
		} else {
			l.Subjects[r.Key] = r.Epoch
		}
	}
	return l
}

// errRevocationsUnavailable: the store could not be read, so the credential
// is refused (fail closed, like a session check): 503, never a pass.
var errRevocationsUnavailable = errors.New("revocations unavailable")

// checkRevoked refuses sub's halo-server credential when it is revoked
// (gateway.ErrCredentialRevoked) or the store cannot tell
// (errRevocationsUnavailable). One indexed query on the shared store, so a
// revocation made on any replica holds on every replica at once.
func (s *Server) checkRevoked(ctx context.Context, sub policy.Subject) error {
	if sub.Credential == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, storage.OpTimeout)
	defer cancel()
	rows, err := s.revs.RevocationsFor(ctx, sub.Credential.IDs, gateway.RevocationSubjects(&sub))
	if err != nil {
		s.cfg.Log.Error("read revocations", "err", err)
		return fmt.Errorf("%w: %w", errRevocationsUnavailable, err)
	}
	return revocationList(rows).Check(&sub)
}

// validRevokeSubject reports why s cannot be revoked ("" when it can).
func validRevokeSubject(s string) string {
	switch {
	case s == "" || len(s) > 256:
		return "subject must be 1-256 characters"
	case strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0:
		return "subject must not contain spaces or control characters"
	}
	if name, ok := strings.CutPrefix(s, policy.AgentSubjectPrefix); ok && !policy.ValidName(name) {
		return "agent subject must be agent:<agents.actors name>"
	}
	return ""
}

func validJTI(j string) bool {
	return j != "" && len(j) <= maxRevokeJTI && strings.Trim(j, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

// postRevocation (admin): POST /api/v1/revocations revokes one credential by
// jti, or a subject by epoch. Revoking a human root also revokes their
// sessions, and its epoch is the session epoch, so a fresh login can delegate
// again at once. An agent or workload epoch is padded by revocationSkew (as
// session epochs are), so credentials for it are refused for that long. The
// revocation is in force before it is audited (AuditStrict: a failed audit
// is a 500, and the revocation still holds).
func (s *Server) postRevocation(w http.ResponseWriter, r *http.Request, p Principal) {
	var in RevokeRequest
	if err := decodeBody(w, r, 4096, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case (in.JTI == "") == (in.Subject == ""):
		apiErr(w, http.StatusBadRequest, "exactly one of jti and subject is required")
		return
	case in.Reason == "" || len(in.Reason) > maxRevokeReason:
		apiErr(w, http.StatusBadRequest, "reason required (<=1000 chars)")
		return
	case in.JTI != "" && !validJTI(in.JTI):
		apiErr(w, http.StatusBadRequest, "jti must be 1-128 characters of A-Z a-z 0-9 - _")
		return
	case in.Subject != "":
		if why := validRevokeSubject(in.Subject); why != "" {
			apiErr(w, http.StatusBadRequest, why)
			return
		}
	}
	now := s.cfg.Now()
	rec, _ := json.Marshal(revocationRecord{By: p.ID, Reason: in.Reason, At: now.UTC()}) // plain struct: cannot fail
	row := pgstore.Revocation{Kind: revokeJTI, Key: in.JTI, Expires: now.Add(revocationLife), Record: rec}
	if in.Subject != "" {
		row.Kind, row.Key = revokeSubject, policy.CanonicalUser(in.Subject)
		row.Epoch = now.Add(revocationSkew).Unix()
		if human := !strings.HasPrefix(row.Key, policy.AgentSubjectPrefix) && !strings.HasPrefix(row.Key, policy.WorkloadSubjectPrefix); human {
			if err := s.revoked.revoke(in.Subject, now); err != nil {
				s.cfg.Log.Error("persist session revocation", "user", in.Subject, "err", err)
				apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
				return
			}
			row.Epoch = s.revoked.epoch(in.Subject) / int64(time.Second)
		}
		row.Expires = time.Unix(row.Epoch, 0).Add(revocationLife)
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	cur, err := s.revs.Revocations(ctx)
	if err == nil && len(cur) >= maxActiveRevocations && !slices.ContainsFunc(cur, func(x pgstore.Revocation) bool { return x.Kind == row.Kind && x.Key == row.Key }) {
		apiErr(w, http.StatusConflict, fmt.Sprintf("%d revocations are active (the limit): revoke the subject instead, or rotate the workload key", len(cur)))
		return
	}
	if err == nil {
		err = s.revs.PutRevocation(ctx, row)
	}
	if err != nil {
		s.cfg.Log.Error("persist revocation", "kind", row.Kind, "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	v := revocationView(row)
	d := map[string]string{"kind": row.Kind, "reason": in.Reason, "expires": v.Expires.Format(time.RFC3339)}
	if v.RevokedBefore != nil {
		d["revokedBefore"] = v.RevokedBefore.Format(time.RFC3339)
	}
	s.cfg.Log.Info("credential revoked", "kind", row.Kind, "key", row.Key, "by", p.ID)
	if err := s.AuditStrict(r.Context(), p.ID, "credential.revoke", row.Key, d); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed) // the revocation itself is in force
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// listRevocations (admin): GET /api/v1/revocations lists the active ones.
func (s *Server) listRevocations(w http.ResponseWriter, r *http.Request, _ Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	rows, err := s.revs.Revocations(ctx)
	if err != nil {
		s.cfg.Log.Error("read revocations", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	out := RevocationsResponse{Revocations: make([]Revocation, 0, len(rows))}
	for _, x := range rows {
		out.Revocations = append(out.Revocations, revocationView(x))
	}
	writeJSON(w, http.StatusOK, out)
}

// writeGatewayRevocations answers GET /api/v1/gateway/directory?revocations=1
// (gateway token, authenticated by the caller): the list gateways check
// workload and agent credentials against. A store error is a 503, so the
// gateway's directory fail mode decides.
func (s *Server) writeGatewayRevocations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	rows, err := s.revs.Revocations(ctx)
	if err != nil {
		s.metrics.lookup("revocations", "error")
		s.cfg.Log.Error("read revocations", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	s.metrics.lookup("revocations", "ok")
	writeJSON(w, http.StatusOK, revocationList(rows))
}
