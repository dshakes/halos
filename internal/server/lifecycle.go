package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// Data lifecycle (ADR-0040: retention and erasure) and signed audit
// checkpoints (ADR-0041).

// ---- retention config ----

// Retention bounds how long halo-server keeps each unbounded store; a zero
// field keeps that store forever (the default, and the behaviour before
// ADR-0040). Ages are measured from the newest activity of a record.
type Retention struct {
	FleetReports time.Duration // reporters not seen for this long, with their history
	Requests     time.Duration // decided access requests, from the decision
	Devices      time.Duration // revoked devices from their last use, expired ones from expiry
	Audit        time.Duration // audit entries; whole rotated segments on the file backend
	Interval     time.Duration // how often the sweep runs; 0 = DefaultRetentionInterval
}

// DefaultRetentionInterval is how often the retention sweep runs.
const DefaultRetentionInterval = time.Hour

// MinAuditRetention is the shortest audit retention accepted: entries must
// outlive their export to the SIEM by a wide margin.
const MinAuditRetention = 30 * 24 * time.Hour

// DefaultCheckpointInterval is how often a signed audit checkpoint is
// appended when new entries arrived (ADR-0041).
const DefaultCheckpointInterval = 5 * time.Minute

func (r Retention) enabled() bool {
	return r.FleetReports > 0 || r.Requests > 0 || r.Devices > 0 || r.Audit > 0
}

func (r Retention) validate() error {
	for name, d := range map[string]time.Duration{"fleet reports": r.FleetReports, "requests": r.Requests, "devices": r.Devices, "interval": r.Interval} {
		if d != 0 && d < time.Hour {
			return fmt.Errorf("server: retention of %s must be 0 (keep forever) or at least 1h", name)
		}
	}
	if r.Audit != 0 && r.Audit < MinAuditRetention {
		return fmt.Errorf("server: audit retention must be 0 (keep forever) or at least %s", MinAuditRetention)
	}
	return nil
}

// ---- journal removal ----

// tombstone is the record a journal store appends when it deletes records,
// so every replica's replay drops them too (and never takes them back).
type tombstone struct {
	Erase []string `json:"erase"`
}

// tombstoneIDs returns the ids a tombstone record deletes, or nil when rec
// is not one.
func tombstoneIDs(rec []byte) []string {
	if !strings.Contains(string(rec), `"erase"`) {
		return nil
	}
	var t tombstone
	if json.Unmarshal(rec, &t) != nil || len(t.Erase) == 0 {
		return nil
	}
	return t.Erase
}

// tombstoneBatch caps the ids in one tombstone record.
const tombstoneBatch = 500

// journalGC removes deleted records from a store's log. The store appends
// tombstones first (so other replicas converge), drops the records from
// memory, then compacts. Ids whose compaction failed stay in retry and are
// compacted by the next removal. The caller holds the store's log lock.
type journalGC struct{ retry map[string]bool }

func (g *journalGC) tombstone(l storage.Log, ids []string) error {
	if l == nil || len(ids) == 0 {
		return nil
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	for chunk := range slices.Chunk(ids, tombstoneBatch) {
		b, _ := json.Marshal(tombstone{Erase: chunk}) // plain struct: cannot fail
		if err := l.Append(ctx, "", b); err != nil {
			return fmt.Errorf("append tombstone: %w", err)
		}
	}
	if g.retry == nil {
		g.retry = map[string]bool{}
	}
	for _, id := range ids {
		g.retry[id] = true
	}
	return nil
}

// compact drops every record of a tombstoned id, and every record extra
// selects; tombstones themselves stay (they hold only ids).
func (g *journalGC) compact(l storage.Log, extra func([]byte) bool) error {
	if l == nil || (len(g.retry) == 0 && extra == nil) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := storage.Compact(ctx, l, func(rec []byte) bool {
		var r struct {
			ID string `json:"id"`
		}
		return (json.Unmarshal(rec, &r) == nil && g.retry[r.ID]) || (extra != nil && extra(rec))
	})
	if err != nil {
		return fmt.Errorf("compact: %w", err)
	}
	clear(g.retry)
	return nil
}

// ---- subject matching ----

// subjectMatcher recognises a data subject's identifiers: the user id and
// any aliases (an OS user or hostname a fleet-token report carries), compared
// as canonicalUser, alone or after a "kind:" prefix ("user:alice@x").
type subjectMatcher map[string]bool

func newSubjectMatcher(ids ...string) subjectMatcher {
	m := subjectMatcher{}
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			m[canonicalUser(id)] = true
		}
	}
	return m
}

func (m subjectMatcher) match(s string) bool {
	if s == "" {
		return false
	}
	if m[canonicalUser(s)] {
		return true
	}
	i := strings.LastIndexByte(s, ':')
	return i >= 0 && m[canonicalUser(s[i+1:])]
}

// identityKeys are the audit detail keys that hold a person's id; erasure
// pseudonymises those and nothing else, so it can never rewrite a seq, a
// hash, a count or a status that happens to equal an alias (ADR-0040).
var identityKeys = map[string]bool{
	"user": true, "by": true, "onBehalfOf": true, "approver": true, "subject": true, "requester": true,
	"owner": true, "createdBy": true, "principal": true, "decidedBy": true, "vendorUser": true, "email": true,
}

// ledgerIdentityKeys are the identity fields inside a session.record's
// details["record"] (internal/ledger Who): user, vendorUser, agents.
var ledgerIdentityKeys = map[string]bool{"user": true, "vendorUser": true, "agents": true}

// chainActions are the entries the chain itself interprets: never redacted.
var chainActions = map[string]bool{actionCheckpoint: true, actionRetention: true, actionErase: true, actionSigningEnabled: true}

// redact returns e with its identity fields that name the subject (actor,
// target, identityKeys details, the identity fields of a ledger record)
// replaced by pseudo, the client IP of the subject's own actions dropped,
// and marked Redacted; ok is false when there is nothing to redact. Seq, Prev
// and Hash stay. Checkpoint, retention and erasure entries are never touched.
func (m subjectMatcher) redact(e AuditEntry, pseudo string) (AuditEntry, bool) {
	if chainActions[e.Action] {
		return e, false
	}
	changed := false
	fix := func(s *string) {
		if m.match(*s) {
			*s, changed = pseudo, true
		}
	}
	if m.match(e.Actor) && e.IP != "" {
		e.IP = ""
		changed = true
	}
	fix(&e.Actor)
	fix(&e.Target)
	if len(e.Details) > 0 {
		d := make(map[string]string, len(e.Details))
		for k, v := range e.Details {
			switch {
			case identityKeys[k]:
				fix(&v)
			case k == "record":
				if r, ok := m.redactRecord(v, pseudo); ok {
					v, changed = r, true
				}
			}
			d[k] = v
		}
		e.Details = d
	}
	if !changed {
		return e, false
	}
	e.Redacted = true
	return e, true
}

// redactRecord pseudonymises the identity fields of a ledger record JSON.
func (m subjectMatcher) redactRecord(rec, pseudo string) (string, bool) {
	var v map[string]any
	if json.Unmarshal([]byte(rec), &v) != nil {
		return rec, false
	}
	changed := false
	var walk func(map[string]any)
	walk = func(o map[string]any) {
		for k, x := range o {
			switch y := x.(type) {
			case string:
				if ledgerIdentityKeys[k] && m.match(y) {
					o[k], changed = pseudo, true
				}
			case []any:
				for i, s := range y {
					if str, ok := s.(string); ok && ledgerIdentityKeys[k] && m.match(str) {
						y[i], changed = pseudo, true
					}
				}
			case map[string]any:
				walk(y)
			}
		}
	}
	walk(v)
	if !changed {
		return rec, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return rec, false
	}
	return string(b), true
}

var rfc3339ish = regexp.MustCompile(`(?i)^\d{4}-\d{2}(-\d{2})?([T ]|$)|^\d{2}:\d{2}`)

// checkSubjectID refuses an id an erasure must not match on: what the chain
// or the store writes itself (the system actor, pseudonyms, numbers, times)
// and words that name a ring, role or request status rather than a person.
func checkSubjectID(id string, org *policy.Org) error {
	c := canonicalUser(id)
	words := []string{canonicalUser(systemActor), StatusPending, StatusApproving, StatusApproved, StatusDenied}
	words = append(words, Roles...)
	if org != nil {
		for _, r := range org.Rings {
			words = append(words, canonicalUser(r.Name))
		}
	}
	switch {
	case len(c) < 3 || len(id) > 256:
		return fmt.Errorf("%q: 3 to 256 characters", id)
	case strings.HasPrefix(c, "erased-"):
		return fmt.Errorf("%q is an erasure pseudonym", id)
	case strings.Trim(c, "0123456789") == "":
		return fmt.Errorf("%q is a number", id)
	case rfc3339ish.MatchString(c):
		return fmt.Errorf("%q looks like a time", id)
	case slices.Contains(words, c):
		return fmt.Errorf("%q names the system, a role, a ring or a status, not a person", id)
	}
	return nil
}

// ---- audit chain maintenance ----

// auditMaintainer is the shared Backend's half of audit retention and
// erasure (PGBackend, through pgstore.DB).
type auditMaintainer interface {
	PruneAudit(ctx context.Context, through uint64) (int64, error)
	RedactAudit(ctx context.Context, bodies map[uint64][2][]byte) error // seq -> {stored body, redacted body}
}

// errChainUnverified: the server signs nothing over an audit chain that does
// not verify (a checkpoint, an erasure's vouch, a retention cut): signing
// would launder whatever was tampered with.
var errChainUnverified = errors.New("audit chain does not verify; refusing to sign over it")

// verifiedChain verifies the whole chain (incrementally, from the cached
// verified prefix) before anything is signed over it, and refuses, loudly,
// when it does not verify or does not match the signing record (checkSigning).
func (s *Server) verifiedChain(what string) (chainCheck, error) {
	l := s.auditLog
	snap, err := l.snapshot()
	if err != nil {
		return chainCheck{}, err
	}
	defer snap.close()
	c, err := l.verify(snap)
	if err != nil {
		return c, err
	}
	s.checkSigning(&c)
	if c.err != nil {
		s.signRefused.Add(1)
		s.cfg.Log.Error("audit chain does not verify: refusing to sign", "what", what, "err", c.err)
		return c, fmt.Errorf("%w (%s): %w", errChainUnverified, what, c.err)
	}
	return c, nil
}

// errSigningNotEnabled: an audit key is configured over a chain that holds
// entries but was never signed, and --audit-signing-enable was not given.
var errSigningNotEnabled = errors.New("audit signing is not enabled on this log: start halo-server once with --audit-signing-enable=<head seq> (first-ever enable only)")

// signingChain is verifiedChain for a signer. A chain never signed gets the
// signed audit.signing.enabled marker first, with a fresh log id and the seq
// every later signed entry binds as since (ADR-0041); but over a chain that
// already holds entries only when the operator asked for it this start
// (--audit-signing-enable). Without that, a log whose signed entries and
// signing record were deleted would simply be signed again from scratch:
// the server refuses instead, loudly, and keeps running unsigned.
func (s *Server) signingChain(ctx context.Context, what string) (chainCheck, error) {
	c, err := s.verifiedChain(what)
	if err != nil || s.auditLog.key == nil || c.since > 0 {
		return c, err
	}
	if c.total > 0 {
		if err := s.takeSigningEnable(c.total); err != nil {
			s.signRefused.Add(1)
			s.cfg.Log.Error("audit key configured over an unsigned, non-empty log: refusing to sign", "what", what, "head", c.total, "err", err)
			return c, fmt.Errorf("%w (%s): %w", errChainUnverified, what, err)
		}
	}
	logID := make([]byte, 16)
	if _, err := rand.Read(logID); err != nil {
		return c, err
	}
	since := c.total + 1
	m := AuditEntry{Time: s.cfg.Now().UTC(), Actor: systemActor, Action: actionSigningEnabled,
		Details: map[string]string{"since": strconv.FormatUint(since, 10), "log": hex.EncodeToString(logID)}}
	m.Seq, m.Prev = since, c.last // what signingMsg binds; the append must land exactly there
	if err := s.auditLog.signDetails(ctx, signingMsg(m), m.Details); err != nil {
		return c, err
	}
	m.Seq, m.Prev = 0, ""
	if err := s.auditLog.append(m); err != nil {
		s.auditFails.Add(1)
		return c, err
	}
	if err := s.auditLog.writeSigningRecord(signingRecord{Since: since, Log: m.Details["log"]}); err != nil {
		return c, fmt.Errorf("write the signing record: %w", err)
	}
	return s.verifiedChain(what)
}

// warnSigningState logs, at start, states an operator must act on: a signed
// log served without its audit key (no erasure or retention cut can be
// signed: they are refused), and --audit-signing-enable left set over a log
// that already has a signing record.
func (s *Server) warnSigningState() {
	rec, err := s.auditLog.readSigningRecord()
	if err != nil {
		s.cfg.Log.Error("audit: cannot read the signing record", "err", err)
		return
	}
	if rec.Since > 0 && s.auditLog.key == nil {
		s.cfg.Log.Error("audit: this log is signed (signing record present) but no --audit-signing-key-uri is set: erasures and audit retention cuts are refused until the key is restored", "since", rec.Since)
	}
	if rec.Since > 0 && (s.enableHead > 0 || s.enableAny) {
		s.cfg.Log.Error("audit: --audit-signing-enable is set but the log already has a signing record: remove the flag; it is for the first-ever enable or a lost record only", "since", rec.Since)
	}
}

// errSignedNoKey: an erasure or retention cut on a signed log without the
// audit key would write an unsigned vouch and break signed verification.
var errSignedNoKey = errors.New("this audit log is signed but halo-server has no --audit-signing-key-uri: restore the key before erasing or cutting (an unsigned vouch would break signed verification)")

// requireKeyIfSigned refuses vouching work on a signed log without the key.
func (s *Server) requireKeyIfSigned() error {
	if s.auditLog.key != nil {
		return nil
	}
	rec, err := s.auditLog.readSigningRecord()
	if err != nil {
		return err
	}
	if rec.Since > 0 {
		return errSignedNoKey
	}
	return nil
}

// takeSigningEnable consumes the one-shot --audit-signing-enable for a log
// whose head is at head: allowed only when the value names that head (a
// stale value, set for an earlier state, is refused), and only once per
// process (it is cleared on use).
func (s *Server) takeSigningEnable(head uint64) error {
	s.enableMu.Lock()
	defer s.enableMu.Unlock()
	switch {
	case s.enableAny:
		s.enableAny = false
		return nil
	case s.enableHead == 0:
		return errSigningNotEnabled
	case s.enableHead != head:
		return fmt.Errorf("--audit-signing-enable=%d is stale: the log's head is at seq %d (set it to the current head, after checking the log against your SIEM copy)", s.enableHead, head)
	}
	s.enableHead = 0
	return nil
}

// noteSigned re-verifies after this server signed an entry, so the signing
// record (and memory) learn at once that the current key has signed: from
// then on a tail rewritten by a previous key is refused. A failure is logged
// and counted by verifiedChain; the next signing re-checks.
func (s *Server) noteSigned() {
	if s.auditLog.key != nil {
		_, _ = s.verifiedChain("record the signing key")
	}
}

// kindAuditSigning names the document, or the data-dir file, recording how
// this log is signed.
const kindAuditSigning = "audit-signing"

// signingRecord is kept outside the chain: the seq signing was enabled at,
// the log id, and the newest key that has signed (with the seq it was first
// seen at). A long-lived replica also keeps since and the key in memory.
type signingRecord struct {
	Since   uint64 `json:"since"`
	Log     string `json:"log,omitempty"`
	Key     string `json:"key,omitempty"`     // key id of the newest key that has signed
	KeyFrom uint64 `json:"keyFrom,omitempty"` // a seq it had signed by (informational)
}

type docStore interface {
	GetDoc(ctx context.Context, kind, name string) ([]byte, bool, error)
	PutDoc(ctx context.Context, kind, name string, body []byte) error
}

// checkSigning holds a verified chain to the signing record and to what
// this process saw. It fails the chain when:
//   - the record (or memory) says signing was enabled but no signed entry is
//     left (the signed tail was deleted);
//   - the chain is signed but the record is missing (deleted with evidence),
//     unless this start was given --audit-signing-enable;
//   - since or the log id differ from the record or from memory;
//   - the current key has signed (record or memory) but the newest signed
//     entry is by a previous key (a leaked old key rewrote the tail).
//
// These hold only while the record or this process survives: a storage
// writer who deletes the record and every signed entry, then restarts the
// server, is caught only by an external anchor (halo audit verify --anchor
// or --compare-export against the SIEM copy).
func (s *Server) checkSigning(c *chainCheck) {
	l := s.auditLog
	if c.err != nil || c.verifier == nil {
		return
	}
	rec, err := l.readSigningRecord()
	if err != nil {
		c.err = fmt.Errorf("read the signing record: %w", err)
		return
	}
	mem := l.knownSince.Load()
	curKey := ""
	if l.key != nil {
		curKey = bundle.KeyID(l.key.Verifier())
	}
	l.vmu.Lock()
	memKey, memLog := l.knownKey, l.knownLog
	l.vmu.Unlock()
	switch {
	case c.since == 0 && (mem > 0 || rec.Since > 0):
		c.err = fmt.Errorf("signing was enabled at seq %d, but no signed entry is left in the chain. If this data was restored from a backup taken before signing was enabled, restore the signing record from the same backup, or check the log against your SIEM copy (halo audit verify --strict --compare-export) and remove audit-signing.json (or the audit-signing document) before starting once with --audit-signing-enable=<head seq>. Otherwise the signed tail was deleted: investigate", max(mem, rec.Since))
		return
	case c.since == 0:
		return // never signed
	case rec.Since == 0:
		if err := s.takeSigningEnable(c.total); err != nil {
			c.err = fmt.Errorf("the chain is signed but the signing record is missing: restore it from backup, or check the chain against your SIEM copy (halo audit verify --strict --compare-export) and start halo-server once with --audit-signing-enable=%d: %w", c.total, err)
			return
		}
	case rec.Since != 0 && (rec.Since != c.since || (rec.Log != "" && rec.Log != c.logID)):
		c.err = fmt.Errorf("signed entries say signing was enabled at seq %d (log %s), the signing record says %d (log %s)", c.since, c.logID, rec.Since, rec.Log)
		return
	case memLog != "" && memLog != c.logID:
		c.err = fmt.Errorf("the chain is log %s, this process signed log %s: the log was replaced", c.logID, memLog)
		return
	case mem > 0 && mem != c.since:
		c.err = fmt.Errorf("signed entries say signing was enabled at seq %d, this process saw %d", c.since, mem)
		return
	case curKey != "" && (rec.Key == curKey || memKey == curKey) && c.newestSignedKey != 0:
		c.err = errors.New("the current audit key has signed, but the newest signed entry is by a previous key: the tail was rewritten")
		return
	}
	l.knownSince.Store(c.since)
	l.vmu.Lock()
	l.knownLog = c.logID
	l.vmu.Unlock()
	want := rec
	want.Since, want.Log = c.since, c.logID
	if curKey != "" && c.newestSignedKey == 0 && rec.Key != curKey {
		want.Key, want.KeyFrom = curKey, c.signedSeq
	}
	if want != rec {
		if err := l.writeSigningRecord(want); err != nil {
			c.err = fmt.Errorf("write the signing record: %w", err)
			return
		}
	}
	if want.Key != "" {
		l.vmu.Lock()
		l.knownKey = want.Key
		l.vmu.Unlock()
	}
}

// readSigningRecord reads the record (zero: none, or no durable store).
func (l *auditLog) readSigningRecord() (signingRecord, error) {
	var r signingRecord
	var b []byte
	switch ds, ok := l.shared.(docStore); {
	case ok:
		ctx, cancel := storage.Ctx()
		defer cancel()
		d, found, err := ds.GetDoc(ctx, kindAuditSigning, "since")
		if err != nil || !found {
			return r, err
		}
		b = d
	case l.dir != "":
		d, err := os.ReadFile(filepath.Join(l.dir, kindAuditSigning+".json"))
		if errors.Is(err, fs.ErrNotExist) {
			return r, nil
		}
		if err != nil {
			return r, err
		}
		b = d
	default:
		return r, nil
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("signing record: %w", err)
	}
	return r, nil
}

func (l *auditLog) writeSigningRecord(r signingRecord) error {
	b, _ := json.Marshal(r) // plain struct: cannot fail
	switch ds, ok := l.shared.(docStore); {
	case ok:
		ctx, cancel := storage.Ctx()
		defer cancel()
		return ds.PutDoc(ctx, kindAuditSigning, "since", b)
	case l.dir != "":
		return fsutil.WriteAtomic(filepath.Join(l.dir, kindAuditSigning+".json"), b, 0o600)
	}
	return nil
}

// errUntrusted: an entry the work needs is not proven by the cached chain;
// the caller re-verifies from scratch once (another replica may have
// redacted it) before giving up.
var errUntrusted = errors.New("audit: entry neither intact nor a vouched-for redaction")

// redaction is a redacted entry with the stored body it replaces.
type redaction struct {
	e   AuditEntry
	old []byte
}

// redactions streams the chain and returns the redacted form of every entry
// naming the subject, by seq. c is the chain as just verified: an entry whose
// content is not proven (its hash matches, or a subject.erase vouched for it)
// is never redacted, so the server never signs a vouch for content someone
// with write access changed.
func (l *auditLog) redactions(c chainCheck, m subjectMatcher, pseudo string) (map[uint64]redaction, error) {
	snap, err := l.snapshot()
	if err != nil {
		return nil, err
	}
	defer snap.close()
	out := map[uint64]redaction{}
	var bad error
	err = snap.from(0, func(raw []byte, e AuditEntry) bool {
		r, ok := m.redact(e, pseudo)
		if !ok {
			return true
		}
		if !c.trusted(e) {
			bad = fmt.Errorf("%w: seq %d", errUntrusted, e.Seq)
			return false
		}
		out[e.Seq] = redaction{e: r, old: bytes.Clone(raw)}
		return true
	})
	return out, errors.Join(err, bad)
}

// errRedactRace: a row changed between reading and redacting it (another
// erasure, or tampering): nothing of this redaction is stored.
var errRedactRace = errors.New("audit: an entry changed while it was being redacted")

// redact stores the redacted entries in place of the originals, each only
// if the stored body is still the one read (compare and swap).
func (l *auditLog) redact(red map[uint64]redaction) error {
	if len(red) == 0 {
		return nil
	}
	defer l.dropCache() // the cached verified prefix held the originals
	if l.shared != nil {
		am, ok := l.shared.(auditMaintainer)
		if !ok {
			return errors.New("audit: this backend cannot redact entries")
		}
		bodies := make(map[uint64][2][]byte, len(red))
		for seq, r := range red {
			b, _ := json.Marshal(r.e) // plain struct: cannot fail
			bodies[seq] = [2][]byte{r.old, b}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return am.RedactAudit(ctx, bodies)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		for i, e := range l.mem {
			if r, ok := red[e.Seq]; ok {
				l.mem[i] = r.e
			}
		}
		return nil
	}
	segs, err := listAuditSegs(l.dir)
	if err != nil {
		return err
	}
	for _, sg := range segs {
		if err := rewriteAuditFile(sg.path, red); err != nil {
			return err
		}
	}
	_ = l.f.Close() // synced on every append; Windows cannot rename over an open file
	rerr := rewriteAuditFile(l.path, red)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.f = nil // appends fail closed
		return errors.Join(rerr, fmt.Errorf("audit: reopen %s: %w", l.path, err))
	}
	l.f = f
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
	return rerr
}

// rewriteAuditFile replaces, in one segment, the lines of the entries in red.
// It streams the segment to a temporary file line by line (memory stays at one
// line, whatever the segment size) and renames it over the original only when
// something changed; a line that is no longer the one read refuses the whole
// segment. l.mu is held meanwhile, so appends wait for one pass over the
// segments: with rotation each is bounded by maxBytes.
func rewriteAuditFile(path string, red map[uint64]redaction) (err error) {
	hit := false
	if err := eachAuditFile(path, func(_ []byte, e AuditEntry) bool {
		_, hit = red[e.Seq]
		return !hit
	}); err != nil || !hit {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".halo-audit-*")
	if err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()           // already failing
			_ = os.Remove(tmp.Name()) // already failing
		}
	}()
	w := bufio.NewWriter(tmp)
	var werr error
	if err := eachAuditFile(path, func(raw []byte, e AuditEntry) bool {
		if r, ok := red[e.Seq]; ok {
			if !bytes.Equal(raw, r.old) {
				werr = fmt.Errorf("%w: seq %d", errRedactRace, e.Seq)
				return false
			}
			raw, _ = json.Marshal(r.e) // plain struct: cannot fail
		}
		if _, werr = w.Write(raw); werr == nil { // raw is the scanner's buffer: never append to it
			werr = w.WriteByte('\n')
		}
		return werr == nil
	}); err != nil {
		return err
	}
	if werr != nil {
		return fmt.Errorf("audit: redact %s: %w", path, werr)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	if err := fsutil.RestrictToOwner(tmp.Name()); err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("audit: redact %s: %w", path, err)
	}
	return fsutil.SyncDir(filepath.Dir(path))
}

// retentionCut picks the newest seq retention may delete: the contiguous
// prefix of entries older than cutoff, never past what every export sink has
// delivered, never the newest checkpoint (a signed entry must always remain),
// and on the file backend only whole rotated segments. hash is that entry's
// hash. Each entry's time comes from its body, and the body must be proven
// (hash, or a vouched-for redaction, per c, the chain as just verified) and
// linked to the one before: neither a back-dated Postgres `at` column nor a
// back-dated body (which breaks its hash) can pull fresh entries into a cut
// the server then signs. untrusted reports that the scan stopped at an entry
// c could not prove (the caller re-verifies from scratch and retries once).
func (l *auditLog) retentionCut(c chainCheck, cutoff time.Time, delivered uint64) (seq uint64, hash string, untrusted bool, err error) {
	snap, err := l.snapshot()
	if err != nil {
		return 0, "", false, err
	}
	defer snap.close()
	limit := delivered
	if c.newestCheckpoint > 0 {
		limit = min(limit, c.newestCheckpoint-1)
	}
	prev := ""
	ok := func(e AuditEntry) bool {
		trusted := c.trusted(e)
		untrusted = untrusted || !trusted
		good := e.Hash != "" && (prev == "" || e.Prev == prev) && trusted && e.Time.Before(cutoff) && e.Seq <= limit
		prev = e.Hash
		return good
	}
	if snap.shared != nil {
		_, err = snap.sharedFrom(0, func(_ []byte, e AuditEntry) bool {
			if !ok(e) {
				return false
			}
			seq, hash = e.Seq, e.Hash
			return true
		})
		return seq, hash, untrusted, err
	}
	for i := range snap.segs { // rotated segments only, oldest first, each whole or not at all
		var last AuditEntry
		whole := true
		if _, err := snap.segment(i, func(_ []byte, e AuditEntry) bool {
			if whole = ok(e); whole {
				last = e
			}
			return whole
		}); err != nil {
			return 0, "", false, err
		}
		if !whole || last.Hash == "" {
			break
		}
		seq, hash = last.Seq, last.Hash
	}
	return seq, hash, untrusted, nil
}

// prune deletes entries through seq (a cut retentionCut picked).
func (l *auditLog) prune(through uint64) (int, error) {
	if l.shared != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		n, err := l.shared.(auditMaintainer).PruneAudit(ctx, through)
		return int(n), err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	segs, err := listAuditSegs(l.dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for i, sg := range segs {
		next := l.first // the active segment's first seq bounds the last rotated one
		if i+1 < len(segs) {
			next = segs[i+1].first
		}
		if next == 0 || next-1 > through {
			break
		}
		if err := os.Remove(sg.path); err != nil {
			return n, fmt.Errorf("audit: delete segment %s: %w", sg.path, err)
		}
		n += int(next - sg.first) //nolint:gosec // entries in one segment fit an int
	}
	return n, fsutil.SyncDir(l.dir)
}

// delivered is the newest seq every export sink has delivered (all of the
// log when none is configured): retention never deletes undelivered entries.
func (s *Server) delivered(ctx context.Context) (uint64, error) {
	if len(s.forwarders) == 0 {
		return ^uint64(0), nil
	}
	if s.cfg.Backend == nil {
		low := ^uint64(0)
		for _, f := range s.forwarders {
			low = min(low, f.acked.Load())
		}
		return low, nil
	}
	// Each configured sink's own cursor, by name: a cursor document left by a
	// sink no longer configured must not stand in for a new one.
	dg, ok := s.cfg.Backend.(interface {
		GetDoc(ctx context.Context, kind, name string) ([]byte, bool, error)
	})
	if !ok {
		return 0, nil
	}
	low := ^uint64(0)
	for _, f := range s.forwarders {
		d, found, err := dg.GetDoc(ctx, kindAuditCursor, f.name)
		if err != nil || !found { // a sink that never delivered holds everything
			return 0, err
		}
		var c auditCursor
		if json.Unmarshal(d, &c) != nil {
			return 0, nil
		}
		low = min(low, c.Seq)
	}
	return low, nil
}

// ---- signed checkpoints (ADR-0041) ----

// checkpointSigner returns the auditLog.sign func for k.
func checkpointSigner(k bundle.KeySigner) func(ctx context.Context, log string, since, seq uint64, head string, now time.Time) (AuditEntry, error) {
	keyID := bundle.KeyID(k.Verifier())
	return func(ctx context.Context, log string, since, seq uint64, head string, now time.Time) (AuditEntry, error) {
		if !hashRE.MatchString(head) { // never a signing oracle for whatever a writer put in the head column
			return AuditEntry{}, fmt.Errorf("audit: refusing to sign checkpoint of seq %d: head is not a SHA-256 hex digest", seq)
		}
		if since == 0 || since > seq || !logIDRE.MatchString(log) {
			return AuditEntry{}, fmt.Errorf("audit: refusing to sign checkpoint of seq %d: signing is not enabled in the chain", seq)
		}
		now = now.UTC()
		sinceS := strconv.FormatUint(since, 10)
		sig, err := k.Sign(ctx, checkpointMsg(log, sinceS, seq, head, now))
		if err != nil {
			return AuditEntry{}, fmt.Errorf("audit: sign checkpoint: %w", err)
		}
		return AuditEntry{Time: now, Actor: systemActor, Action: actionCheckpoint, Details: map[string]string{
			"log": log, "since": sinceS, "seq": strconv.FormatUint(seq, 10), "head": head, "alg": k.Type(), "keyId": keyID,
			"sig": base64.StdEncoding.EncodeToString(sig),
		}}, nil
	}
}

// systemActor is the actor of entries halo-server writes on its own.
const systemActor = "halo-server"

// auditVerifier is the key set checkpoints and vouches verify under: the
// current audit key and every previous one (rotation, ADR-0041); nil when
// there is none. A signature verifies under any key of its algorithm.
func auditVerifier(cur bundle.KeySigner, prev []bundle.PublicKeyVerifier) (bundle.Verifier, error) {
	var ring bundle.Keyring
	if cur != nil {
		pk, ok := cur.Verifier().(bundle.PublicKeyVerifier)
		if !ok {
			return nil, errors.New("server: the audit signing key exposes no public key")
		}
		ring = append(ring, pk)
	}
	ring = append(ring, prev...)
	if len(ring) == 0 {
		return nil, nil
	}
	return ring, nil
}

// subjectHashKey derives the subjectHash key from the session key (HKDF,
// its own label), or draws a per-process one without a session key (demo
// mode: hashes are then not comparable across restarts).
func subjectHashKey(sessionKey []byte) ([]byte, error) {
	if len(sessionKey) == 0 {
		k := make([]byte, 32)
		_, err := rand.Read(k)
		return k, err
	}
	return hkdf.Key(sha256.New, sessionKey, nil, "halos/erasure-subject-hash/v1", 32)
}

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// logIDRE: a log id, 16 random bytes in hex (ADR-0041).
var logIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// checkpointMargin: a checkpoint is dropped (and retried next interval) when
// more entries than checkpointWindow minus this landed while it was signed,
// so it never names an entry the verifier can no longer see.
const checkpointMargin = 32

var errCheckpointStale = errors.New("audit: too many entries landed while the checkpoint was signed; dropped, retrying next interval")

// checkpointStale refuses, at append time and under the lock that orders
// appends (headSeq is the seq the entry will follow), a checkpoint naming an
// entry the verifier's window can no longer reach.
func checkpointStale(e AuditEntry, headSeq uint64) error {
	if e.Action == actionSigningEnabled && e.Details["since"] != strconv.FormatUint(headSeq+1, 10) {
		return errCheckpointStale // it signed the seq it lands at: another entry got there first
	}
	if e.Action != actionCheckpoint {
		return nil
	}
	named, err := strconv.ParseUint(e.Details["seq"], 10, 64)
	if err != nil || named > headSeq || headSeq-named >= checkpointWindow-checkpointMargin {
		return errCheckpointStale
	}
	return nil
}

// signDetails adds the audit key's signature over msg to d (alg, keyId,
// sig); without a key it does nothing.
func (l *auditLog) signDetails(ctx context.Context, msg string, d map[string]string) error {
	if l.key == nil {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	sig, err := l.key.Sign(sctx, msg)
	if err != nil {
		return fmt.Errorf("audit: sign: %w", err)
	}
	d["alg"], d["keyId"], d["sig"] = l.key.Type(), bundle.KeyID(l.key.Verifier()), base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Checkpoint appends a signed checkpoint of the chain head, unless the head
// already is one (nothing happened since). It reports whether it appended.
func (s *Server) Checkpoint(ctx context.Context) (bool, error) {
	l := s.auditLog
	if l.sign == nil {
		return false, nil
	}
	// The head signed is the head of the chain as just verified, never a
	// head someone recomputed in storage (verifiedChain refuses that).
	c, err := s.verifiedChain("checkpoint")
	// Nothing new since the last checkpoint: skip, unless that checkpoint is a
	// previous key's (after a rotation the current key signs at once, so an
	// idle deployment verifies with the new key first).
	if err != nil || c.total == 0 || (c.lastAction == actionCheckpoint && c.newestSignedKey == 0) {
		return false, err
	}
	if c, err = s.signingChain(ctx, "checkpoint"); err != nil { // enables signing on first use
		return false, err
	}
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cp, err := l.sign(sctx, c.logID, c.since, c.total, c.last, s.cfg.Now())
	if err != nil {
		return false, err
	}
	// A slow signer (a KMS under load) and a burst of entries: the append
	// refuses, under the audit lock or the head-row lock, a checkpoint naming
	// an entry too far behind the head (checkpointStale); retried next interval.
	if err := l.append(cp); err != nil {
		if errors.Is(err, errCheckpointStale) {
			return false, err
		}
		s.auditFails.Add(1)
		return false, err
	}
	s.noteSigned()
	return true, nil
}

// ---- sweep ----

// Sweep applies the retention policy once and returns what it removed per
// store. Each removal is audited (actor halo-server). Errors of one store do
// not stop the others; they are joined.
func (s *Server) Sweep(ctx context.Context) (map[string]int, error) {
	r := s.cfg.Retention
	now := s.cfg.Now().UTC()
	out := map[string]int{}
	var errs []error
	note := func(store string, n int, err error) {
		if n > 0 {
			out[store] = n
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", store, err))
		}
	}
	if r.FleetReports > 0 {
		if hr, ok := s.cfg.Store.(hostRemover); ok {
			n, err := hr.PruneHosts(now.Add(-r.FleetReports))
			note("fleetReports", n, err)
		}
	}
	if r.Requests > 0 {
		cut := now.Add(-r.Requests)
		del, _, err := s.reqs.remove(func(q *Request) bool {
			return (q.Status == StatusApproved || q.Status == StatusDenied) && q.DecidedAt != nil && q.DecidedAt.Before(cut)
		}, nil, false)
		note("requests", len(del), err)
	}
	if r.Devices > 0 {
		cut := now.Add(-r.Devices)
		n, err := s.devices.remove(func(d Device) bool {
			exp := d.ExpiresAt
			if exp.IsZero() {
				exp = d.CreatedAt.Add(s.devices.ttl)
			}
			return (d.Revoked && d.LastSeen.Before(cut)) || exp.Before(cut)
		}, false)
		note("devices", n, err)
	}
	if r.Audit > 0 {
		n, err := s.pruneAudit(ctx, now.Add(-r.Audit))
		note("auditEntries", n, err)
	}
	if len(out) > 0 {
		d := map[string]string{}
		for k, v := range out {
			d[k] = strconv.Itoa(v)
		}
		s.Audit(ctx, systemActor, "retention.sweep", "", d)
	}
	return out, errors.Join(errs...)
}

// pruneAudit deletes audit entries older than cutoff. The audit.retention
// entry recording the cut is appended first: a crash between the two leaves a
// recorded cut not yet made, never a cut nobody recorded.
func (s *Server) pruneAudit(ctx context.Context, cutoff time.Time) (int, error) {
	if err := s.requireKeyIfSigned(); err != nil {
		return 0, err
	}
	delivered, err := s.delivered(ctx)
	if err != nil || delivered == 0 {
		return 0, err
	}
	c, err := s.signingChain(ctx, "retention cut")
	if err != nil {
		return 0, err
	}
	seq, hash, untrusted, err := s.auditLog.retentionCut(c, cutoff, delivered)
	if err == nil && untrusted { // another replica may have redacted an entry the cached chain predates
		s.auditLog.dropCache()
		if c, err = s.verifiedChain("retention cut"); err != nil {
			return 0, err
		}
		seq, hash, _, err = s.auditLog.retentionCut(c, cutoff, delivered)
	}
	if err != nil || seq == 0 {
		return 0, err
	}
	// Signed with the audit key (ADR-0041), binding since: with a verifier,
	// only a signed cut, at least MinAuditRetention old at its own time,
	// explains a chain that no longer starts at seq 1.
	d := map[string]string{"through": strconv.FormatUint(seq, 10), "throughHash": hash, "cutoff": cutoff.UTC().Format(time.RFC3339)}
	if c.since > 0 {
		d["since"], d["log"] = strconv.FormatUint(c.since, 10), c.logID
	}
	e := AuditEntry{Time: s.cfg.Now().UTC(), Actor: systemActor, Action: actionRetention, Details: d}
	if err := s.auditLog.signDetails(ctx, retentionMsg(e), e.Details); err != nil {
		return 0, err
	}
	if err := s.auditLog.append(e); err != nil {
		s.auditFails.Add(1)
		return 0, err
	}
	n, err := s.auditLog.prune(seq)
	s.noteSigned()
	return n, err
}

// hostRemover is a fleet report Store that can delete reports (both built-in
// ones are; a custom Store that is not is skipped by retention and erasure).
type hostRemover interface {
	RemoveHosts(match func(Host) bool, dry bool) (int, error)
	PruneHosts(cutoff time.Time) (int, error)
}

// RunMaintenance runs the retention sweep and appends signed audit
// checkpoints until ctx ends; it returns at once when neither is configured.
// With a shared Backend it runs on one replica at a time (lease
// "maintenance"), as the controller and audit export do.
func (s *Server) RunMaintenance(ctx context.Context) {
	if !s.cfg.Retention.enabled() && s.auditLog.sign == nil {
		return
	}
	run := func(ctx context.Context) {
		if s.auditLog.sign != nil { // at start: a rotated key signs a checkpoint now, not at the next interval
			if _, err := s.Checkpoint(ctx); err != nil {
				s.cfg.Log.Error("audit checkpoint at start failed; retrying next interval", "err", err)
			}
		}
		var sweep, cp <-chan time.Time
		if s.cfg.Retention.enabled() {
			t := time.NewTicker(s.retentionInterval())
			defer t.Stop()
			sweep = t.C
		}
		if s.auditLog.sign != nil {
			t := time.NewTicker(s.checkpointInterval())
			defer t.Stop()
			cp = t.C
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep:
				if out, err := s.Sweep(ctx); err != nil {
					s.cfg.Log.Error("retention sweep failed; retrying next interval", "removed", out, "err", err)
				} else if len(out) > 0 {
					s.cfg.Log.Info("retention sweep", "removed", out)
				}
			case <-cp:
				if _, err := s.Checkpoint(ctx); err != nil {
					s.cfg.Log.Error("audit checkpoint failed; retrying next interval", "err", err)
				}
			}
		}
	}
	if b := s.cfg.Backend; b != nil {
		b.Leased(ctx, "maintenance", func(lctx context.Context, _ rollout.Docs) { run(lctx) })
		return
	}
	run(ctx)
}

func (s *Server) retentionInterval() time.Duration {
	if s.cfg.Retention.Interval > 0 {
		return s.cfg.Retention.Interval
	}
	return DefaultRetentionInterval
}

func (s *Server) checkpointInterval() time.Duration {
	if s.cfg.AuditCheckpointInterval > 0 {
		return s.cfg.AuditCheckpointInterval
	}
	return DefaultCheckpointInterval
}

// ---- erasure ----

// EraseRequest is POST /api/v1/users/erase. The subject is in the body, not
// the path, so it never reaches request logs.
type EraseRequest struct {
	User string `json:"user"`
	// Aliases are other identifiers of the same person to erase with User: an
	// OS user name or hostname fleet-token reports carry.
	Aliases []string `json:"aliases,omitempty"`
	Reason  string   `json:"reason"`
	DryRun  bool     `json:"dryRun,omitempty"`
}

// EraseReport is what an erasure removed or pseudonymised, per store.
type EraseReport struct {
	// Pseudonym replaced the subject in the records kept (audit entries,
	// requests the subject decided); it is random, so it cannot be linked back.
	Pseudonym string            `json:"pseudonym,omitempty"`
	DryRun    bool              `json:"dryRun,omitempty"`
	Erased    map[string]int    `json:"erased"`
	Retained  map[string]string `json:"retained"`
	Errors    map[string]string `json:"errors,omitempty"`
}

// erasureRetained names what an erasure keeps, and why (ADR-0040).
var erasureRetained = map[string]string{
	"sessionRevocations":    "the user id and a timestamp: the epoch that keeps the subject's sessions revoked",
	"credentialRevocations": "dropped automatically an hour after each revocation",
	"rolloutApprovals":      "approvals of rollout steps are change records; the matching audit entries are pseudonymised",
	"serviceTokens":         "service-account tokens are not personal data; revoke the subject's tokens first",
	"scim":                  "deprovision the user in the IdP (SCIM DELETE) before erasing",
	"budgets":               "spend counters age out after 95 days (budget.MaxRetention)",
	"siem":                  "entries already exported stay in your SIEM: apply the subject.erase entry there",
}

const maxEraseAliases = 16

// eraseVouchBatch caps the redacted entries one subject.erase entry vouches
// for, so it stays far below the audit line limit.
const eraseVouchBatch = 2000

// pendingErasureTTL is how long a second admin has to confirm an erasure.
const pendingErasureTTL = time.Hour

const kvPendingErasure = "erasure-pending"

// pendingErasure is an erasure waiting for a second admin.
type pendingErasure struct {
	Request     EraseRequest `json:"request"`
	RequestedBy string       `json:"requestedBy"`
	Expires     time.Time    `json:"expires"`
}

// PendingErasure is the 202 answer, and GET /api/v1/users/erase/{id}: an
// erasure waiting for a second admin. User, Aliases and Reason are what the
// confirming admin must resubmit, unchanged.
type PendingErasure struct {
	ID          string    `json:"id"`
	RequestedBy string    `json:"requestedBy"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Confirm     string    `json:"confirm"` // the route a different admin calls
	User        string    `json:"user,omitempty"`
	Aliases     []string  `json:"aliases,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// eraseUser (admin, a person, never themselves): POST /api/v1/users/erase.
// A dry run answers at once. Anything else is a pending erasure (202) that a
// different admin confirms (two-person rule, ADR-0040): erasure destroys
// evidence, and no single admin may do it alone.
func (s *Server) eraseUser(w http.ResponseWriter, r *http.Request, p Principal) {
	if !s.requireHuman(w, r, p, r.Pattern) {
		return
	}
	var in EraseRequest
	if err := decodeBody(w, r, 16<<10, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	m, ok := s.checkErasure(w, p, &in)
	if !ok {
		return
	}
	if in.DryRun {
		s.runErasure(w, r, m, in, p.ID, "", nil)
		return
	}
	id := randB64(18)
	pe := pendingErasure{Request: in, RequestedBy: p.ID, Expires: s.cfg.Now().UTC().Add(pendingErasureTTL)}
	b, _ := json.Marshal(pe) // plain struct: cannot fail
	if err := s.kv.Put(r.Context(), kvPendingErasure, id, b, pe.Expires); err != nil {
		s.cfg.Log.Error("erasure: store pending", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	if err := s.AuditStrict(r.Context(), p.ID, "subject.erase.request", id, map[string]string{
		"severity": "high", "reason": in.Reason, "subject": s.subjectHash(in.User), "aliases": strconv.Itoa(len(in.Aliases)),
	}); err != nil {
		_ = s.kv.Delete(context.WithoutCancel(r.Context()), kvPendingErasure, id) // unaudited: not pending
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	writeJSON(w, http.StatusAccepted, PendingErasure{ID: id, RequestedBy: p.ID, ExpiresAt: pe.Expires, Confirm: "POST /api/v1/users/erase/" + id + "/confirm"})
}

// getPendingErasure (admin): GET /api/v1/users/erase/{id} shows what a
// pending erasure would erase, so the second admin can review it.
func (s *Server) getPendingErasure(w http.ResponseWriter, r *http.Request, _ Principal) {
	pe, ok := s.pendingErasure(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, PendingErasure{ID: id, RequestedBy: pe.RequestedBy, ExpiresAt: pe.Expires, Confirm: "POST /api/v1/users/erase/" + id + "/confirm",
		User: pe.Request.User, Aliases: pe.Request.Aliases, Reason: pe.Request.Reason})
}

func (s *Server) pendingErasure(w http.ResponseWriter, r *http.Request) (pendingErasure, bool) {
	var pe pendingErasure
	b, ok, err := s.kv.Get(r.Context(), kvPendingErasure, r.PathValue("id"))
	if err != nil {
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return pe, false
	}
	if !ok || json.Unmarshal(b, &pe) != nil {
		apiErr(w, http.StatusNotFound, "no such pending erasure (expired, confirmed or never requested)")
		return pe, false
	}
	return pe, true
}

// confirmErasure (admin, a person, not the requester, not the subject):
// POST /api/v1/users/erase/{id}/confirm, with the same user, aliases and
// reason as the request, runs the pending erasure. A mismatch is 409 and
// the erasure stays pending: the confirmer must know what they confirm.
func (s *Server) confirmErasure(w http.ResponseWriter, r *http.Request, p Principal) {
	if !s.requireHuman(w, r, p, r.Pattern) {
		return
	}
	var in EraseRequest
	if err := decodeBody(w, r, 16<<10, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "resubmit the erasure's user, aliases and reason as JSON")
		return
	}
	pe, ok := s.pendingErasure(w, r)
	if !ok {
		return
	}
	if p.is(pe.RequestedBy) {
		apiErr(w, http.StatusForbidden, "a different admin must confirm the erasure you requested")
		return
	}
	m, ok := s.checkErasure(w, p, &pe.Request)
	if !ok {
		return
	}
	if !sameErasure(in, pe.Request) {
		apiErr(w, http.StatusConflict, "the user, aliases or reason differ from the pending erasure: read it with GET /api/v1/users/erase/"+r.PathValue("id"))
		return
	}
	id := r.PathValue("id")
	s.runErasure(w, r, m, pe.Request, p.ID, pe.RequestedBy, func(ctx context.Context) error { // under the erasure lock: a busy lock loses nothing
		if _, ok, err := s.kv.Take(ctx, kvPendingErasure, id); err != nil || !ok { // one confirmation wins
			return errors.New("this erasure was confirmed or expired meanwhile")
		}
		return nil
	})
}

// sameErasure compares a resubmitted erasure with the pending one: user and
// aliases as canonical ids (aliases as a set), the reason trimmed.
func sameErasure(a, b EraseRequest) bool {
	set := func(ids []string) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, canonicalUser(strings.TrimSpace(id)))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return canonicalUser(strings.TrimSpace(a.User)) == canonicalUser(b.User) && slices.Equal(set(a.Aliases), set(b.Aliases)) &&
		strings.TrimSpace(a.Reason) == b.Reason
}

// checkErasure validates in (trimming it) and that p is not erasing
// themselves under any of the subject's ids.
func (s *Server) checkErasure(w http.ResponseWriter, p Principal, in *EraseRequest) (subjectMatcher, bool) {
	in.User, in.Reason = strings.TrimSpace(in.User), strings.TrimSpace(in.Reason)
	org, _, _ := s.pol.Get()
	if in.Reason == "" || len(in.Reason) > 1000 {
		apiErr(w, http.StatusUnprocessableEntity, "reason required (<=1000 chars): name the request you are fulfilling, not the person")
		return nil, false
	}
	if len(in.Aliases) > maxEraseAliases {
		apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("at most %d aliases", maxEraseAliases))
		return nil, false
	}
	for i := range in.Aliases {
		in.Aliases[i] = strings.TrimSpace(in.Aliases[i])
	}
	ids := append([]string{in.User}, in.Aliases...)
	for _, id := range ids {
		if err := checkSubjectID(id, org); err != nil {
			apiErr(w, http.StatusUnprocessableEntity, "user and aliases must identify a person: "+err.Error())
			return nil, false
		}
	}
	m, self := newSubjectMatcher(ids...), newSubjectMatcher(p.ID, p.OnBehalfOf)
	if m.match(p.ID) || (p.OnBehalfOf != "" && m.match(p.OnBehalfOf)) || slices.ContainsFunc(ids, self.match) {
		apiErr(w, http.StatusForbidden, "you cannot erase yourself (as the user or an alias): another admin must")
		return nil, false
	}
	return m, true
}

// subjectHash names an id in an audit entry without naming it: HMAC-SHA256
// under a key only the server holds (derived from the session key), so it
// cannot be reversed by trying candidate ids. "" without such a key.
func (s *Server) subjectHash(id string) string {
	if len(s.subjectKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.subjectKey)
	mac.Write([]byte(canonicalUser(id)))
	return "h:" + hex.EncodeToString(mac.Sum(nil)[:12])
}

// runErasure takes the erasure lock (renewed while it runs; the erasure is
// cancelled if a renewal fails), then claim (a confirmation takes the pending
// erasure only once it holds the lock), then erases and answers.
func (s *Server) runErasure(w http.ResponseWriter, r *http.Request, m subjectMatcher, in EraseRequest, actor, requestedBy string, claim func(context.Context) error) {
	unlock, err := s.eraseMu.Lock()
	if err != nil {
		apiErr(w, http.StatusServiceUnavailable, "another erasure is running; retry")
		return
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context())) // a client hanging up must not stop it half-way
	defer cancel()
	stop := s.eraseMu.keepAlive(cancel)
	defer func() { stop(); unlock() }()
	if claim != nil {
		if err := claim(ctx); err != nil {
			apiErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	rep := s.erase(ctx, m, in, actor, requestedBy)
	if in.DryRun {
		rep.Pseudonym = ""
		s.Audit(r.Context(), actor, "subject.erase.preview", "", map[string]string{"reason": in.Reason, "subject": s.subjectHash(in.User)})
		writeJSON(w, http.StatusOK, rep)
		return
	}
	code := http.StatusOK
	if len(rep.Errors) > 0 {
		code = http.StatusInternalServerError
	}
	writeJSON(w, code, rep)
}

// errStoreFailed is what a client and the audit entry learn of a store
// failure; the error itself goes to the server log only.
const errStoreFailed = "store failed; see the halo-server log, then retry"

// errLockLost: the erasure lock lapsed (a renewal failed); the erasure stops
// before the audit log is touched.
const errLockLost = "the erasure lock was lost; nothing more was erased: retry"

// erase runs one erasure (eraseMu held). Order: sessions and devices first,
// so the subject loses access before anything else; the audit chain last,
// after the subject.erase entries that vouch for its redactions.
func (s *Server) erase(ctx context.Context, m subjectMatcher, in EraseRequest, actor, requestedBy string) EraseReport {
	dry := in.DryRun
	rep := EraseReport{Pseudonym: "erased-" + randB64(9), DryRun: dry, Erased: map[string]int{}, Retained: erasureRetained, Errors: map[string]string{}}
	note := func(store string, n int, err error) {
		if n > 0 {
			rep.Erased[store] = n
		}
		if err != nil {
			rep.Errors[store] = errStoreFailed
			s.cfg.Log.Error("erasure: store failed", "store", store, "err", err)
		}
	}
	if !dry {
		if err := s.requireKeyIfSigned(); err != nil {
			s.cfg.Log.Error("erasure refused", "err", err)
			rep.Errors["auditEntries"] = err.Error()
			return rep
		}
	}
	// The chain must verify before anything is erased: the erasure signs a
	// vouch over redacted entries, and must never launder tampered ones.
	verify := s.verifiedChain
	if !dry {
		verify = func(what string) (chainCheck, error) { return s.signingChain(ctx, what) }
	}
	c, err := verify("erasure")
	if err != nil {
		rep.Errors["auditEntries"] = "the audit chain does not verify, so nothing was erased: run `halo audit verify` and see the halo-server log"
		return rep
	}
	if !dry {
		err := s.revoked.revoke(in.User, s.cfg.Now())
		note("sessions", 0, err)
	}
	n, err := s.devices.remove(func(d Device) bool { return m.match(d.UserID) }, dry)
	note("devices", n, err)

	pseudo := rep.Pseudonym
	del, fixed, err := s.reqs.remove(func(q *Request) bool { return m.match(q.User) }, func(q *Request) bool {
		changed := false
		if m.match(q.DecidedBy) {
			q.DecidedBy, changed = pseudo, true
		}
		q.Approvals = slices.Clone(q.Approvals) // q is a copy; its slice is not
		for i := range q.Approvals {
			if m.match(q.Approvals[i].By) {
				q.Approvals[i].By, changed = pseudo, true
			}
		}
		return changed
	}, dry)
	note("requests", len(del), err)
	note("requestsPseudonymised", fixed, nil)
	if !dry {
		for i := range del {
			s.releasePending(&del[i])
		}
	}

	if hr, ok := s.cfg.Store.(hostRemover); ok {
		n, err := hr.RemoveHosts(func(h Host) bool { return m.match(h.User) }, dry)
		note("fleetReports", n, err)
	} else {
		rep.Errors["fleetReports"] = "this report store cannot delete reports"
	}

	if ctx.Err() != nil {
		rep.Errors["auditEntries"] = errLockLost
		return rep
	}
	red, err := s.auditLog.redactions(c, m, pseudo)
	if errors.Is(err, errUntrusted) { // another replica may have redacted an entry the cached chain predates
		s.auditLog.dropCache()
		if c, err = s.verifiedChain("erasure"); err == nil {
			red, err = s.auditLog.redactions(c, m, pseudo)
		}
	}
	note("auditEntries", len(red), err)
	if dry || err != nil {
		if len(rep.Errors) == 0 {
			rep.Errors = nil
		}
		return rep
	}
	// The subject.erase entries go in before the redactions: each vouches for
	// the redacted form of the entries it lists, so a crash in between leaves
	// vouched-for entries not yet redacted (still valid), never the reverse.
	// With an audit key each vouch list is signed (ADR-0041): a verifier with
	// the public key accepts no other.
	seqs := slices.Sorted(maps.Keys(red))
	parts := slices.Collect(slices.Chunk(seqs, eraseVouchBatch))
	if len(parts) == 0 {
		parts = [][]uint64{nil}
	}
	for i, part := range parts {
		list := make([]string, 0, len(part))
		for _, seq := range part {
			list = append(list, strconv.FormatUint(seq, 10)+":"+red[seq].e.redactionDigest())
		}
		d := map[string]string{"severity": "high", "subject": pseudo, "redacted": strings.Join(list, ",")}
		if c.since > 0 {
			d["since"], d["log"] = strconv.FormatUint(c.since, 10), c.logID
		}
		if i == 0 {
			d["reason"] = in.Reason
			d["aliases"] = strconv.Itoa(len(in.Aliases))
			hashes := make([]string, 0, len(in.Aliases))
			for _, a := range in.Aliases {
				hashes = append(hashes, s.subjectHash(a))
			}
			d["aliasHashes"] = strings.Join(hashes, ",")
			if requestedBy != "" {
				d["requestedBy"] = requestedBy // the first admin of the two (two-person rule)
			}
			for k, v := range rep.Erased {
				d["erased."+k] = strconv.Itoa(v)
			}
			for k, v := range rep.Errors {
				d["error."+k] = v
			}
		}
		if len(parts) > 1 {
			d["part"] = fmt.Sprintf("%d/%d", i+1, len(parts))
		}
		if err := s.auditLog.signDetails(ctx, eraseMsg(d["log"], d["since"], pseudo, d["redacted"]), d); err != nil {
			s.cfg.Log.Error("erasure: sign subject.erase", "err", err)
			rep.Errors["auditEntries"] = "the audit key could not sign the erasure record; nothing was redacted in the audit log"
			return rep
		}
		if ctx.Err() != nil {
			rep.Errors["auditEntries"] = errLockLost
			return rep
		}
		if err := s.AuditStrict(ctx, actor, actionErase, pseudo, d); err != nil {
			rep.Errors["auditEntries"] = errAuditFailed
			return rep
		}
	}
	if ctx.Err() != nil {
		rep.Errors["auditEntries"] = errLockLost // vouched for, not yet redacted: still valid; retry
		return rep
	}
	note("auditEntries", 0, s.auditLog.redact(red))
	s.noteSigned()
	if len(rep.Errors) == 0 {
		rep.Errors = nil
	}
	return rep
}
