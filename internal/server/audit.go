package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
)

// AuditEntry is one privileged action. Hash covers every other field, Prev is
// the previous entry's Hash (empty for the first), so editing, reordering or
// removing any entry but the newest breaks the chain from that point on.
type AuditEntry struct {
	Seq       uint64            `json:"seq"`
	Time      time.Time         `json:"time"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Target    string            `json:"target,omitempty"`
	IP        string            `json:"ip,omitempty"`
	RequestID string            `json:"requestId,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Prev      string            `json:"prev"`
	Hash      string            `json:"hash"`
}

func (e AuditEntry) sum() string {
	e.Hash = ""
	b, _ := json.Marshal(e) // plain struct: cannot fail; map keys are sorted, so stable
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// VerifyAuditChain checks seq continuity, prev links and every entry hash.
// ponytail: truncating the newest entries is undetectable from the log alone;
// pin AuditResponse.Head externally if that matters.
func VerifyAuditChain(entries []AuditEntry) error {
	prev := ""
	for i, e := range entries {
		switch {
		case e.Seq != uint64(i)+1: //nolint:gosec // i is a non-negative slice index
			return fmt.Errorf("entry %d: seq %d out of order (entry removed or reordered)", i+1, e.Seq)
		case e.Prev != prev:
			return fmt.Errorf("seq %d: prev hash does not match the preceding entry", e.Seq)
		case e.Hash != e.sum():
			return fmt.Errorf("seq %d: entry was modified (hash mismatch)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// auditLog is an append-only, hash-chained JSONL log (memory only when dir is "").
// ponytail: verification and reads rescan the file; add an index/rotation if it gets big.
type auditLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	mem  []AuditEntry // only when f == nil
	seq  uint64
	head string
}

func openAuditLog(dir string) (*auditLog, error) {
	l := &auditLog{}
	if dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l.path = filepath.Join(dir, "audit.jsonl")
	f, err := fsutil.OpenJSONL(l.path, func(line []byte) {
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil && e.Hash != "" { // torn line: skip
			l.seq, l.head = e.Seq, e.Hash
		}
	})
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *auditLog) close() error { return closeFile(&l.mu, l.f) }

// validUTF8 makes every string valid UTF-8. JSON writes an invalid byte as
// � but re-encodes the decoded U+FFFD raw, so without this the hash of an
// entry carrying, say, a percent-decoded path segment would not survive a
// re-read and the chain would never verify again.
func (e AuditEntry) validUTF8() AuditEntry {
	fix := func(s string) string { return strings.ToValidUTF8(s, "�") }
	e.Actor, e.Action, e.Target, e.IP, e.RequestID = fix(e.Actor), fix(e.Action), fix(e.Target), fix(e.IP), fix(e.RequestID)
	if e.Details != nil {
		d := make(map[string]string, len(e.Details))
		for k, v := range e.Details {
			d[fix(k)] = fix(v)
		}
		e.Details = d
	}
	return e
}

func (l *auditLog) append(e AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e = e.validUTF8()
	e.Seq, e.Prev = l.seq+1, l.head
	e.Hash = e.sum()
	if l.f != nil {
		b, _ := json.Marshal(e) // plain struct: cannot fail
		if _, err := l.f.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("audit: write %s: %w", l.path, err)
		}
		if err := l.f.Sync(); err != nil { // durable before the action is acknowledged
			return fmt.Errorf("audit: sync %s: %w", l.path, err)
		}
	} else {
		l.mem = append(l.mem, e)
	}
	l.seq, l.head = e.Seq, e.Hash
	return nil
}

// all returns every entry as stored (re-read from disk, so on-disk tampering shows up).
func (l *auditLog) all() ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return append([]AuditEntry(nil), l.mem...), nil
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		return nil, err
	}
	var out []AuditEntry
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var e AuditEntry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil { // garbage line: skipped, so the chain breaks there
			out = append(out, e)
		}
	}
	return out, nil
}

// ---- request metadata (set by the logging middleware) ----

type reqMeta struct{ ip, id string }

type reqMetaKey struct{}

func withReqMeta(ctx context.Context, m reqMeta) context.Context {
	return context.WithValue(ctx, reqMetaKey{}, m)
}

// AuditStrict records a privileged action and returns the append error. Call
// it for actions that must not go unrecorded and fail the request on error.
func (s *Server) AuditStrict(ctx context.Context, actor, action, target string, details map[string]string) error {
	m, _ := ctx.Value(reqMetaKey{}).(reqMeta)
	e := AuditEntry{Time: s.cfg.Now().UTC(), Actor: actor, Action: action, Target: target, IP: m.ip, RequestID: m.id, Details: details}
	if err := s.auditLog.append(e); err != nil {
		s.cfg.Log.Error("audit append failed", "action", action, "actor", actor, "err", err)
		return err
	}
	return nil
}

// Audit is the best-effort form (login/logout): failures are logged, not
// returned. ctx carries the remote IP and request id when it derives from an
// HTTP request.
func (s *Server) Audit(ctx context.Context, actor, action, target string, details map[string]string) {
	_ = s.AuditStrict(ctx, actor, action, target, details) // logged inside
}

// errAuditFailed is what privileged handlers answer when the audit append fails.
const errAuditFailed = "audit log unavailable; action not recorded"

// AppendAuditOffline appends one entry to <dir>/audit.jsonl using the server's
// hash chain, for tools that act on the data dir without a running server
// (halo controller run). Single-writer: the chain head is read from disk on
// open, so it must not run while halo-server is appending to the same dir
// (the server caches seq/head in memory and the chain would fork). Run the
// standalone controller only against a stopped server, or a separate data dir.
func AppendAuditOffline(dir, actor, action, target string, details map[string]string, now time.Time) error {
	l, err := openAuditLog(dir)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = l.f.Close() }()
	return l.append(AuditEntry{Time: now.UTC(), Actor: actor, Action: action, Target: target, Details: details})
}

// AuditResponse is GET /api/v1/audit.
type AuditResponse struct {
	Entries     []AuditEntry `json:"entries"`
	Next        uint64       `json:"next"` // pass as ?since= to get entries after these
	Total       int          `json:"total"`
	Verified    bool         `json:"verified"` // whole chain, not just this page
	VerifyError string       `json:"verifyError,omitempty"`
	Head        string       `json:"head"`
}

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 500
)

// getAudit: ?since=<seq|RFC3339> returns matching entries after that point,
// oldest first; without since, the newest `limit` entries. ?actor= and ?action=
// filter exactly. Pages chain via `next`.
func (s *Server) getAudit(w http.ResponseWriter, r *http.Request, _ Principal) {
	q := r.URL.Query()
	limit := auditDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > auditMaxLimit {
			apiErr(w, http.StatusBadRequest, "limit must be 1.."+strconv.Itoa(auditMaxLimit))
			return
		}
		limit = n
	}
	var sinceSeq uint64
	var sinceTime time.Time
	hasSince := q.Get("since") != ""
	if v := q.Get("since"); hasSince {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			sinceSeq = n
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			sinceTime = t
		} else {
			apiErr(w, http.StatusBadRequest, "since must be a sequence number or RFC3339 time")
			return
		}
	}
	all, err := s.auditLog.all()
	if err != nil {
		s.cfg.Log.Error("read audit log", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	resp := AuditResponse{Entries: []AuditEntry{}, Total: len(all), Verified: true}
	if verr := VerifyAuditChain(all); verr != nil {
		resp.Verified, resp.VerifyError = false, verr.Error()
	}
	if len(all) > 0 {
		resp.Head = all[len(all)-1].Hash
	}
	var match []AuditEntry
	for _, e := range all {
		if (q.Get("actor") != "" && e.Actor != q.Get("actor")) || (q.Get("action") != "" && e.Action != q.Get("action")) ||
			e.Seq <= sinceSeq || e.Time.Before(sinceTime) {
			continue
		}
		match = append(match, e)
	}
	if hasSince {
		match = match[:min(len(match), limit)]
	} else if len(match) > limit {
		match = match[len(match)-limit:]
	}
	resp.Entries = append(resp.Entries, match...)
	resp.Next = sinceSeq
	if n := len(match); n > 0 {
		resp.Next = match[n-1].Seq
	}
	writeJSON(w, http.StatusOK, resp)
}
