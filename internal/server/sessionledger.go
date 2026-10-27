package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/ledger"
)

// Agent session ledger (ADR-0031). A session record is an audit entry with
// action session.record: the canonical record JSON in details["record"]. So
// the records share the audit log's hash chain (tamper evidence, `halo audit
// verify`), its SIEM export (ADR-0016) and its Postgres backend (ADR-0021)
// without a second chain, cursor or table.
const (
	actionSessionRecord = "session.record"
	ledgerMaxBatch      = 1000
	ledgerMaxBody       = 16 << 20
	ledgerDefaultLimit  = 100
	ledgerMaxLimit      = 5000
)

// SessionsResponse is GET /api/v1/sessions.
type SessionsResponse struct {
	Sessions    []ledger.Stored `json:"sessions"`
	Total       int             `json:"total"` // matching sessions before limit
	Verified    bool            `json:"verified"`
	VerifyError string          `json:"verifyError,omitempty"`
	Head        string          `json:"head"`
}

// SessionsIngest is the body of POST /api/v1/sessions and its answer (the
// records as stored, Who.User set from the directory).
type SessionsIngest struct {
	Records []ledger.Record `json:"records"`
}

// lookupIdentity resolves a vendor identity to a Halos identity through the
// SCIM directory: an active user whose userName matches. Without a directory
// nothing resolves; a session then stays attributed to its vendor identity only.
func (s *Server) lookupIdentity(vendorUser string) (string, bool) {
	if s.scim == nil {
		return "", false
	}
	u, _, ok := s.scim.store.Lookup(vendorUser)
	if !ok || !u.Active {
		return "", false
	}
	return u.UserName, true
}

// postSessions stores normalized session records (admin). Every record is
// validated before any is written: one record with prose, an unhashed path
// or a forged id refuses the whole batch. Who.User is replaced from the
// directory, never taken from the body.
func (s *Server) postSessions(w http.ResponseWriter, r *http.Request, p Principal) {
	var in SessionsIngest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, ledgerMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		apiErr(w, http.StatusBadRequest, "trailing data after JSON body")
		return
	}
	if len(in.Records) == 0 || len(in.Records) > ledgerMaxBatch {
		apiErr(w, http.StatusBadRequest, fmt.Sprintf("records: want 1..%d", ledgerMaxBatch))
		return
	}
	recs := in.Records
	for i := range recs {
		if err := recs[i].Validate(); err != nil {
			apiErr(w, http.StatusBadRequest, fmt.Sprintf("record %d: %v; nothing stored", i, err))
			return
		}
	}
	ledger.Join(recs, s.lookupIdentity)
	for i, rec := range recs {
		b, err := json.Marshal(rec)
		if err != nil {
			apiErr(w, http.StatusInternalServerError, "encode record")
			return
		}
		if err := s.AuditStrict(r.Context(), p.ID, actionSessionRecord, rec.ID, map[string]string{"record": string(b)}); err != nil {
			apiErr(w, http.StatusInternalServerError, fmt.Sprintf("%s; %d of %d records stored", errAuditFailed, i, len(recs)))
			return
		}
	}
	writeJSON(w, http.StatusOK, SessionsIngest{Records: recs})
}

// sessionFilter parses the list query.
func sessionFilter(r *http.Request) (ledger.Filter, int, error) {
	q := r.URL.Query()
	f := ledger.Filter{User: q.Get("user"), Harness: q.Get("harness"), Ring: q.Get("ring"), Tool: q.Get("tool")}
	var err error
	for _, t := range []struct {
		name string
		dst  *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(t.name); v != "" {
			if *t.dst, err = time.Parse(time.RFC3339, v); err != nil {
				return f, 0, fmt.Errorf("%s must be RFC 3339", t.name)
			}
		}
	}
	limit := ledgerDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > ledgerMaxLimit {
			return f, 0, fmt.Errorf("limit must be 1..%d", ledgerMaxLimit)
		}
		limit = n
	}
	return f, limit, nil
}

// latestSessions streams the audit log and keeps the newest stored version
// of every session keep accepts, with the chain's verification state.
// ponytail: a full scan per read, O(log) time and O(matching sessions)
// memory; query the ClickHouse copy (halo_session_ledger) for analytics.
func (s *Server) latestSessions(keep func(*ledger.Record) bool) (map[string]ledger.Stored, chainCheck, error) {
	snap, err := s.auditLog.snapshot()
	if err != nil {
		return nil, chainCheck{}, err
	}
	defer snap.close()
	c, err := s.auditLog.verify(snap)
	if err != nil {
		return nil, c, err
	}
	out := map[string]ledger.Stored{}
	err = snap.from(1, func(_ []byte, e AuditEntry) bool {
		if e.Action != actionSessionRecord {
			return true
		}
		var rec ledger.Record
		if json.Unmarshal([]byte(e.Details["record"]), &rec) != nil || rec.Validate() != nil {
			return true // not a ledger record we wrote; the chain check covers tampering
		}
		if keep(&rec) {
			out[rec.ID] = ledger.Stored{Record: rec, AuditSeq: e.Seq, AuditHash: e.Hash}
		} else {
			delete(out, rec.ID) // a newer version no longer matches
		}
		return true
	})
	return out, c, err
}

func sessionsResponse(c chainCheck) SessionsResponse {
	resp := SessionsResponse{Sessions: []ledger.Stored{}, Verified: c.err == nil, Head: c.last}
	if c.err != nil {
		resp.VerifyError = c.err.Error()
	}
	return resp
}

// getSessions lists sessions (audit permission: the ledger is per-person
// activity, read under the same separation of duties as the audit log),
// newest start first. Filters: user, harness, ring, tool, since, until.
func (s *Server) getSessions(w http.ResponseWriter, r *http.Request, _ Principal) {
	f, limit, err := sessionFilter(r)
	if err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	got, c, err := s.latestSessions(f.Match)
	if err != nil {
		s.cfg.Log.Error("read session ledger", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	resp := sessionsResponse(c)
	for _, st := range got {
		resp.Sessions = append(resp.Sessions, st)
	}
	slices.SortFunc(resp.Sessions, func(a, b ledger.Stored) int {
		if c := b.Start.Compare(a.Start); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	resp.Total = len(resp.Sessions)
	resp.Sessions = resp.Sessions[:min(limit, len(resp.Sessions))]
	writeJSON(w, http.StatusOK, resp)
}

// getSession returns one session by ledger id or harness session id.
func (s *Server) getSession(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	got, c, err := s.latestSessions(func(rec *ledger.Record) bool { return rec.ID == id || rec.SessionID == id })
	if err != nil {
		s.cfg.Log.Error("read session ledger", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	resp := sessionsResponse(c)
	for _, st := range got {
		resp.Sessions = append(resp.Sessions, st)
	}
	if len(resp.Sessions) == 0 {
		apiErr(w, http.StatusNotFound, "no such session")
		return
	}
	slices.SortFunc(resp.Sessions, func(a, b ledger.Stored) int { return strings.Compare(a.ID, b.ID) })
	resp.Total = len(resp.Sessions)
	writeJSON(w, http.StatusOK, resp)
}
