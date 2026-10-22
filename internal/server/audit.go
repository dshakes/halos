package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/storage"
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
// pin AuditResponse.Head externally (an export sink does) if that matters.
func VerifyAuditChain(entries []AuditEntry) error {
	var c chainCheck
	for _, e := range entries {
		c.add(e)
	}
	return c.err
}

// chainCheck verifies a chain one entry at a time, so a log of any size is
// checked in constant memory. err is the first break; total and last keep
// counting past it (GET /api/v1/audit reports them as total and head).
type chainCheck struct {
	total uint64
	last  string
	err   error
}

func (c *chainCheck) add(e AuditEntry) {
	prev := c.last
	c.total++
	c.last = e.Hash
	if c.err != nil {
		return
	}
	switch {
	case e.Seq != c.total:
		c.err = fmt.Errorf("entry %d: seq %d out of order (entry removed or reordered)", c.total, e.Seq)
	case e.Prev != prev:
		c.err = fmt.Errorf("seq %d: prev hash does not match the preceding entry", e.Seq)
	case e.Hash != e.sum():
		c.err = fmt.Errorf("seq %d: entry was modified (hash mismatch)", e.Seq)
	}
}

// AuditRotation bounds the active segment (<data-dir>/audit.jsonl). When the
// next append would take it past MaxBytes, or its first entry is
// MaxAgeSeconds old, it is renamed to audit-<first seq, 20 digits>.jsonl and a
// new one is started. The chain does not restart: the first entry of the new
// segment links to the last of the previous one. Zero disables either bound.
type AuditRotation struct {
	MaxBytes      int64 `json:"maxBytes,omitempty"`
	MaxAgeSeconds int64 `json:"maxAgeSeconds,omitempty"`
}

const (
	auditActive    = "audit.jsonl"
	auditSegPrefix = "audit-"
	auditSegSuffix = ".jsonl"
	auditMaxLine   = 1 << 20 // the cap fsutil.OpenJSONL replays with
)

func auditSegName(first uint64) string {
	return fmt.Sprintf("%s%020d%s", auditSegPrefix, first, auditSegSuffix)
}

// auditSeg is a rotated, immutable segment.
type auditSeg struct {
	first uint64
	path  string
}

// listAuditSegs returns dir's rotated segments, oldest first. Names are
// zero-padded, so the lexical order Glob returns is seq order.
func listAuditSegs(dir string) ([]auditSeg, error) {
	paths, err := filepath.Glob(filepath.Join(dir, auditSegPrefix+"*"+auditSegSuffix))
	if err != nil {
		return nil, err
	}
	var out []auditSeg
	for _, p := range paths {
		n := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), auditSegPrefix), auditSegSuffix)
		if first, err := strconv.ParseUint(n, 10, 64); err == nil && len(n) == 20 {
			out = append(out, auditSeg{first: first, path: p})
		}
	}
	return out, nil
}

// auditLog is an append-only, hash-chained JSONL log split into segments
// (memory only when dir is ""). Reads stream; nothing loads the whole log.
type auditLog struct {
	mu    sync.Mutex
	dir   string
	path  string // active segment
	f     *os.File
	mem   []AuditEntry // only when f == nil
	seq   uint64
	head  string
	rot   AuditRotation
	log   *slog.Logger
	size  int64     // bytes in the active segment
	first uint64    // seq of its first entry (0: none yet)
	start time.Time // time of that entry
	wake  chan struct{}

	// shared: the chain lives in the HA backend (ADR-0021), one table whose
	// head-row lock orders appends across replicas; segments and rotation do
	// not apply. vcache then holds the verified prefix (see verifyShared).
	shared Backend

	rotateErrs atomic.Uint64

	vmu    sync.Mutex // guards vcache
	vcache struct {
		key string
		c   chainCheck
	}
}

func openAuditLog(dir string) (*auditLog, error) {
	l := &auditLog{dir: dir}
	if dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l.path = filepath.Join(dir, auditActive)
	f, err := fsutil.OpenJSONL(l.path, func(line []byte) {
		var e AuditEntry
		if json.Unmarshal(line, &e) == nil && e.Hash != "" { // torn line: skip
			l.seq, l.head = e.Seq, e.Hash
			if l.first == 0 {
				l.first, l.start = e.Seq, e.Time
			}
		}
	})
	if err != nil {
		return nil, err
	}
	l.f = f
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: stat %s: %w", l.path, err)
	}
	l.size = st.Size()
	if l.first == 0 { // empty active segment (fresh, or a crash right after rotating): the head is in the last segment
		segs, err := listAuditSegs(dir)
		if err == nil && len(segs) > 0 {
			err = eachAuditFile(segs[len(segs)-1].path, func(_ []byte, e AuditEntry) bool {
				if e.Hash != "" {
					l.seq, l.head = e.Seq, e.Hash
				}
				return true
			})
		}
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: read last segment in %s: %w", dir, err)
		}
	}
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

// ChainAuditEntry returns e as the entry after (seq, head): UTF-8 repaired,
// Seq, Prev and Hash set. Every backend chains through it.
func ChainAuditEntry(e AuditEntry, seq uint64, head string) AuditEntry {
	e = e.validUTF8()
	e.Seq, e.Prev = seq+1, head
	e.Hash = e.sum()
	return e
}

func (l *auditLog) append(e AuditEntry) error {
	if l.shared != nil {
		ctx, cancel := storage.Ctx() // not the request's: a client hanging up must not drop the record
		defer cancel()
		if err := l.shared.AppendAudit(ctx, e); err != nil {
			return fmt.Errorf("audit: append: %w", err)
		}
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e = ChainAuditEntry(e, l.seq, l.head)
	if l.f != nil {
		b, _ := json.Marshal(e) // plain struct: cannot fail
		b = append(b, '\n')
		if l.rotateDue(e.Time, len(b)) {
			// A failed rotation is not an audit failure: the entry still goes to
			// the active segment (or the write below fails closed) and the next
			// append retries. On Windows a reader holding the file open is enough.
			if err := l.rotate(); err != nil {
				l.rotateErrs.Add(1)
				orDefault(l.log).Error("audit rotation failed; appending to the active segment", "err", err)
			}
		}
		if _, err := l.f.Write(b); err != nil {
			return fmt.Errorf("audit: write %s: %w", l.path, err)
		}
		if err := l.f.Sync(); err != nil { // durable before the action is acknowledged
			return fmt.Errorf("audit: sync %s: %w", l.path, err)
		}
		l.size += int64(len(b))
		if l.first == 0 {
			l.first, l.start = e.Seq, e.Time
		}
	} else {
		l.mem = append(l.mem, e)
	}
	l.seq, l.head = e.Seq, e.Hash
	if l.wake != nil { // wake export forwarders: close-and-replace broadcasts to all of them
		close(l.wake)
		l.wake = nil
	}
	return nil
}

// changed returns a channel the next append closes.
func (l *auditLog) changed() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wake == nil {
		l.wake = make(chan struct{})
	}
	return l.wake
}

// headSeq is the seq of the newest entry. A shared head that cannot be read
// is an error, never 0: a 0 would make every forwarder's cursor look "ahead
// of the log" and report a restored database that never happened.
func (l *auditLog) headSeq() (uint64, error) {
	if l.shared != nil {
		ctx, cancel := storage.Ctx()
		defer cancel()
		seq, _, err := l.shared.AuditHead(ctx)
		if err != nil {
			return 0, fmt.Errorf("audit: read head: %w", err)
		}
		return seq, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, nil
}

func (l *auditLog) rotateDue(t time.Time, n int) bool {
	if l.first == 0 { // never rotate an empty segment: every segment holds at least one entry
		return false
	}
	return (l.rot.MaxBytes > 0 && l.size+int64(n) > l.rot.MaxBytes) ||
		(l.rot.MaxAgeSeconds > 0 && t.Sub(l.start) >= time.Duration(l.rot.MaxAgeSeconds)*time.Second)
}

// rotate renames the active segment to its rotated name and opens a new one;
// l.mu is held. If the rename fails the old active is reopened; if no active
// can be opened l.f stays closed, so appends fail closed.
func (l *auditLog) rotate() error {
	seg := filepath.Join(l.dir, auditSegName(l.first))
	if _, err := os.Lstat(seg); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("audit: rotate: refusing to overwrite segment %s (lstat: %v)", seg, err)
	}
	if err := l.f.Close(); err != nil { // Windows cannot rename an open file
		return fmt.Errorf("audit: rotate: close %s: %w", l.path, err)
	}
	renameErr := os.Rename(l.path, seg)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return errors.Join(renameErr, fmt.Errorf("audit: rotate: open %s: %w", l.path, err))
	}
	l.f = f
	if renameErr != nil {
		return fmt.Errorf("audit: rotate %s: %w", l.path, renameErr)
	}
	l.size, l.first = 0, 0
	if err := fsutil.RestrictToOwner(l.path); err != nil {
		return fmt.Errorf("audit: rotate: %w", err)
	}
	return fsutil.SyncDir(l.dir)
}

// eachAuditLine streams r line by line into fn with the raw line (valid only
// during the call) and its decoded entry. Lines that do not decode are
// skipped, so the chain breaks there. fn returns false to stop.
func eachAuditLine(r io.Reader, fn func(raw []byte, e AuditEntry) bool) (bool, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), auditMaxLine)
	for sc.Scan() {
		var e AuditEntry
		if len(sc.Bytes()) > 0 && json.Unmarshal(sc.Bytes(), &e) == nil {
			if !fn(sc.Bytes(), e) {
				return false, nil
			}
		}
	}
	return true, sc.Err()
}

func eachAuditFile(path string, fn func(raw []byte, e AuditEntry) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only
	if _, err := eachAuditLine(f, fn); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

// auditSnap is a consistent read view: the rotated segments present and the
// active segment's own handle and length at snapshot time, so a rotation or
// append mid-read neither hides nor repeats entries. Rotated segments are
// immutable, so they are opened lazily by name.
type auditSnap struct {
	segs        []auditSeg
	active      *os.File
	size        int64
	activeFirst uint64
	mem         []AuditEntry
	shared      Backend // HA: one table, read by seq; no segments
}

func (l *auditLog) snapshot() (*auditSnap, error) {
	if l.shared != nil {
		return &auditSnap{shared: l.shared}, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return &auditSnap{mem: append([]AuditEntry(nil), l.mem...)}, nil
	}
	segs, err := listAuditSegs(l.dir)
	if err != nil {
		return nil, fmt.Errorf("audit: list segments in %s: %w", l.dir, err)
	}
	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", l.path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: stat %s: %w", l.path, err)
	}
	return &auditSnap{segs: segs, active: f, size: st.Size(), activeFirst: l.first}, nil
}

func (s *auditSnap) close() {
	if s.active != nil {
		_ = s.active.Close() // read-only
	}
}

// segment streams segment i (len(s.segs) is the active one) into fn.
func (s *auditSnap) segment(i int, fn func(raw []byte, e AuditEntry) bool) (bool, error) {
	if i < len(s.segs) {
		cont := true
		err := eachAuditFile(s.segs[i].path, func(raw []byte, e AuditEntry) bool { cont = fn(raw, e); return cont })
		return cont, err
	}
	if s.shared != nil {
		return s.sharedFrom(1, fn)
	}
	if s.active == nil {
		for _, e := range s.mem {
			raw, _ := json.Marshal(e) // plain struct: cannot fail
			if !fn(raw, e) {
				return false, nil
			}
		}
		return true, nil
	}
	cont, err := eachAuditLine(io.NewSectionReader(s.active, 0, s.size), fn)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", s.active.Name(), err)
	}
	return cont, nil
}

// from streams entries oldest first, starting at the segment that can hold
// seq, until fn returns false. Callers filter on e.Seq themselves.
func (s *auditSnap) from(seq uint64, fn func(raw []byte, e AuditEntry) bool) error {
	if s.shared != nil {
		_, err := s.sharedFrom(seq, fn)
		return err
	}
	start := 0
	if s.activeFirst != 0 && seq >= s.activeFirst {
		start = len(s.segs)
	} else {
		for i, sg := range s.segs {
			if sg.first <= seq {
				start = i
			}
		}
	}
	for i := start; i <= len(s.segs); i++ {
		if cont, err := s.segment(i, fn); err != nil || !cont {
			return err
		}
	}
	return nil
}

// tail returns the newest n entries matching match, oldest first, reading
// segments newest first and holding at most 2n entries.
func (s *auditSnap) tail(n int, match func(AuditEntry) bool) ([]AuditEntry, error) {
	var out []AuditEntry
	if s.shared != nil { // newest first, paged by seq: reads only what it returns (plus filtered-out rows)
		ctx, cancel := context.WithTimeout(context.Background(), auditReadTimeout)
		defer cancel()
		err := s.shared.EachAuditDesc(ctx, func(_ []byte, e AuditEntry) bool {
			if match(e) {
				out = append(out, e)
			}
			return len(out) < n
		})
		if err != nil {
			return nil, fmt.Errorf("audit: read: %w", err)
		}
		slices.Reverse(out)
		return out, nil
	}
	for i := len(s.segs); i >= 0 && len(out) < n; i-- {
		var ring []AuditEntry
		if _, err := s.segment(i, func(_ []byte, e AuditEntry) bool {
			if match(e) {
				if ring = append(ring, e); len(ring) >= 2*n {
					ring = append(ring[:0], ring[len(ring)-n:]...)
				}
			}
			return true
		}); err != nil {
			return nil, err
		}
		ring = ring[max(0, len(ring)-(n-len(out))):]
		out = append(ring, out...)
	}
	return out, nil
}

// verify checks the whole chain across segments. The state after the rotated
// segments is cached by their names, sizes and mtimes, so a request re-reads
// only the active segment. ponytail: an edit that keeps a rotated segment's
// size and mtime is caught by `halo audit verify`, which never caches.
func (l *auditLog) verify(s *auditSnap) (chainCheck, error) {
	if s.shared != nil {
		return l.verifyShared(s)
	}
	var c chainCheck
	add := func(_ []byte, e AuditEntry) bool { c.add(e); return true }
	if len(s.segs) > 0 {
		var key strings.Builder
		for _, sg := range s.segs {
			st, err := os.Stat(sg.path)
			if err != nil {
				return c, fmt.Errorf("audit: stat %s: %w", sg.path, err)
			}
			fmt.Fprintf(&key, "%s:%d:%d;", sg.path, st.Size(), st.ModTime().UnixNano())
		}
		l.vmu.Lock()
		hit := l.vcache.key == key.String()
		if hit {
			c = l.vcache.c
		}
		l.vmu.Unlock()
		if !hit {
			for i := range s.segs {
				if _, err := s.segment(i, add); err != nil {
					return c, err
				}
			}
			l.vmu.Lock()
			l.vcache.key, l.vcache.c = key.String(), c
			l.vmu.Unlock()
		}
	}
	_, err := s.segment(len(s.segs), add)
	return c, err
}

// auditReadTimeout bounds one streamed read of the shared chain.
const auditReadTimeout = time.Minute

// sharedFrom streams the shared chain from seq on, oldest first.
func (s *auditSnap) sharedFrom(seq uint64, fn func(raw []byte, e AuditEntry) bool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditReadTimeout)
	defer cancel()
	cont := true
	err := s.shared.EachAudit(ctx, seq, func(raw []byte, e AuditEntry) bool { cont = fn(raw, e); return cont })
	if err != nil {
		return false, fmt.Errorf("audit: read: %w", err)
	}
	return cont, nil
}

// verifyShared verifies the shared chain. A verified prefix is cached and
// reused only while its last entry still reads back with the same hash, so a
// request reads just the entries appended since. ponytail: an edit to an
// older row that keeps that last hash is caught by `halo audit verify
// --database-url-file`, which never caches (as the file backend's segment cache).
func (l *auditLog) verifyShared(s *auditSnap) (chainCheck, error) {
	l.vmu.Lock()
	c := l.vcache.c
	l.vmu.Unlock()
	if c.err != nil || c.total == 0 {
		c = chainCheck{}
	} else {
		same := false
		if _, err := s.sharedFrom(c.total, func(_ []byte, e AuditEntry) bool { same = e.Seq == c.total && e.Hash == c.last; return false }); err != nil {
			return c, err
		}
		if !same {
			c = chainCheck{}
		}
	}
	if _, err := s.sharedFrom(c.total+1, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
		return c, err
	}
	if c.err == nil {
		l.vmu.Lock()
		l.vcache.c = c
		l.vmu.Unlock()
	}
	return c, nil
}

// VerifyAuditBackend verifies the whole shared chain, streaming and uncached
// (`halo audit verify --database-url-file`). Segments is 0: there are none.
func VerifyAuditBackend(ctx context.Context, b Backend) (AuditVerifyResult, error) {
	var c chainCheck
	if err := b.EachAudit(ctx, 1, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
		return AuditVerifyResult{}, fmt.Errorf("verify audit log: %w", err)
	}
	r := AuditVerifyResult{Entries: c.total, Head: c.last}
	if c.err != nil {
		r.Error = c.err.Error()
	}
	return r, nil
}

// AuditVerifyResult is what VerifyAuditDir reports.
type AuditVerifyResult struct {
	Entries  uint64 `json:"entries"`
	Segments int    `json:"segments"` // files read, the active one included
	Head     string `json:"head"`
	Error    string `json:"error,omitempty"`
}

// VerifyAuditDir verifies the chain across every segment in dir (rotated
// segments oldest first, then audit.jsonl), streaming and uncached. It only
// reads, so it is safe against a live server's data dir. err is an I/O error;
// a broken chain is AuditVerifyResult.Error.
func VerifyAuditDir(dir string) (AuditVerifyResult, error) {
	segs, err := listAuditSegs(dir)
	if err != nil {
		return AuditVerifyResult{}, fmt.Errorf("list audit segments in %s: %w", dir, err)
	}
	paths := make([]string, 0, len(segs)+1)
	for _, sg := range segs {
		paths = append(paths, sg.path)
	}
	active := filepath.Join(dir, auditActive)
	if _, err := os.Stat(active); err == nil || len(segs) == 0 { // a crash between rotate and reopen leaves none
		paths = append(paths, active)
	}
	var c chainCheck
	for _, p := range paths {
		if err := eachAuditFile(p, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
			return AuditVerifyResult{}, fmt.Errorf("verify audit log: %w", err)
		}
	}
	r := AuditVerifyResult{Entries: c.total, Segments: len(paths), Head: c.last}
	if c.err != nil {
		r.Error = c.err.Error()
	}
	return r, nil
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
		s.auditFails.Add(1)
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
// It never rotates; the server rotates on its next append.
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
	Verified    bool         `json:"verified"` // whole chain, every segment, not just this page
	VerifyError string       `json:"verifyError,omitempty"`
	Head        string       `json:"head"`
}

const (
	auditDefaultLimit = 100
	auditMaxLimit     = 500
)

// getAudit: ?since=<seq|RFC3339> returns matching entries after that point,
// oldest first; without since, the newest `limit` entries. ?actor= and ?action=
// filter exactly. Pages chain via `next`. Reads stream: memory is O(limit).
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
	unreadable := func(err error) {
		s.cfg.Log.Error("read audit log", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
	}
	snap, err := s.auditLog.snapshot()
	if err != nil {
		unreadable(err)
		return
	}
	defer snap.close()
	c, err := s.auditLog.verify(snap)
	if err != nil {
		unreadable(err)
		return
	}
	resp := AuditResponse{Entries: []AuditEntry{}, Total: int(c.total), Verified: c.err == nil, Head: c.last} //nolint:gosec // entry count fits an int
	if c.err != nil {
		resp.VerifyError = c.err.Error()
	}
	match := func(e AuditEntry) bool {
		return (q.Get("actor") == "" || e.Actor == q.Get("actor")) && (q.Get("action") == "" || e.Action == q.Get("action")) &&
			e.Seq > sinceSeq && !e.Time.Before(sinceTime)
	}
	var page []AuditEntry
	if hasSince {
		err = snap.from(sinceSeq+1, func(_ []byte, e AuditEntry) bool {
			if match(e) {
				page = append(page, e)
			}
			return len(page) < limit
		})
	} else {
		page, err = snap.tail(limit, match)
	}
	if err != nil {
		unreadable(err)
		return
	}
	resp.Entries = append(resp.Entries, page...)
	resp.Next = sinceSeq
	if n := len(page); n > 0 {
		resp.Next = page[n-1].Seq
	}
	writeJSON(w, http.StatusOK, resp)
}
