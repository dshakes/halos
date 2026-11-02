package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/storage"
)

// AuditEntry is one privileged action. Hash covers every other field, Prev is
// the previous entry's Hash (empty for the first), so editing, reordering or
// removing any entry but the newest breaks the chain from that point on.
//
// Redacted marks an entry whose personal data an erasure pseudonymised
// (ADR-0040). Its Hash is the original one, which still links the chain; its
// content is vouched for instead by a later subject.erase entry listing its
// seq and redaction digest. omitempty keeps every other entry's hash as it was.
type AuditEntry struct {
	Seq       uint64            `json:"seq"`
	Time      time.Time         `json:"time"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Target    string            `json:"target,omitempty"`
	IP        string            `json:"ip,omitempty"`
	RequestID string            `json:"requestId,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Redacted  bool              `json:"redacted,omitempty"`
	Prev      string            `json:"prev"`
	Hash      string            `json:"hash"`
}

func (e AuditEntry) sum() string {
	e.Hash = ""
	b, _ := json.Marshal(e) // plain struct: cannot fail; map keys are sorted, so stable
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// redactionDigest is what a subject.erase entry records for a redacted entry:
// SHA-256 over the whole stored entry, its original Hash included.
func (e AuditEntry) redactionDigest() string {
	b, _ := json.Marshal(e) // plain struct: cannot fail
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// intact reports whether e's content is its own proof: the hash matches, or
// it is redacted (then a later erasure entry must vouch for it).
func (e AuditEntry) intact() bool { return e.Redacted || e.Hash == e.sum() }

// Audit actions the chain itself interprets (ADR-0040, ADR-0041).
const (
	actionCheckpoint     = "audit.checkpoint"      // signed {seq, head} of the entry it follows
	actionRetention      = "audit.retention"       // entries through details.through are being deleted
	actionErase          = "subject.erase"         // a subject's data was erased; details.redacted vouches for redacted entries
	actionSigningEnabled = "audit.signing.enabled" // signing started here: its seq is the since every signed entry carries
)

// VerifyAuditChain checks seq continuity, prev links, every entry hash,
// redactions and retention cuts. ponytail: truncating the newest entries is
// undetectable from the log alone; anchor on a signed checkpoint your SIEM
// holds (ADR-0041, `halo audit verify --anchor`) if that matters.
func VerifyAuditChain(entries []AuditEntry) error {
	var c chainCheck
	for _, e := range entries {
		c.add(e)
	}
	return c.done()
}

// chainCheck verifies a chain one entry at a time, so a log of any size is
// checked in constant memory (plus the redacted entries awaiting their
// erasure record). err is the first break; total and last keep counting past
// it (GET /api/v1/audit reports them as total and head). total is the seq of
// the last entry, so a chain whose oldest entries retention removed starts
// counting at its first entry.
type chainCheck struct {
	total      uint64
	last       string
	err        error
	lastAction string // the newest entry's action

	// cut: the chain starts after a retention cut at seq cut (cutHash its
	// hash); an audit.retention entry must vouch for exactly that cut.
	cut      uint64
	cutHash  string
	cutFound bool
	// pending: redacted entries (seq -> redaction digest) not yet vouched for
	// by a subject.erase entry.
	pending map[uint64]string
	// vouched: redacted entries a subject.erase vouched for (seq -> digest).
	// Erasure and retention consult it before re-signing over them.
	vouched map[uint64]string
	// since: the seq of the audit.signing.enabled entry, learned from any
	// verified signed entry (each signs it); 0 = this chain was never signed.
	// unsignedMax: the newest unsigned subject.erase or audit.retention. With
	// a verifier, one at or after since is a forgery (done), wherever it sits
	// and whatever was cut before it; one before since is legacy, links-only.
	since       uint64
	unsignedMax uint64
	// currentSeen: an entry signed by the current key (the key set's first)
	// verified; from then on an entry signed by a previous key is refused.
	currentSeen bool
	// logID: the log's id from its signed entries (all must agree).
	// newestSignedKey and newestCheckpointKey: which key (0 = current) signed
	// the newest verified signed entry, and the newest verified checkpoint.
	logID               string
	newestSignedKey     int
	newestCheckpointKey int
	// requireCurrentKey (offline, several keys): the newest verified
	// checkpoint must be the current key's.
	requireCurrentKey bool
	// newestCheckpoint: the seq the newest checkpoint that checked out names;
	// retention never cuts it (nor the checkpoint after it), so it stays verifiable.
	newestCheckpoint uint64
	// strict (offline verification with a key): a chain that has unsigned
	// vouches or a cut but no signed entry at all is refused; the server, which
	// may be about to enable signing over legacy vouches, checks its signing
	// record instead.
	strict bool

	// ADR-0041: verifier checks checkpoint signatures (nil: links only).
	verifier bundle.Verifier
	recent   [checkpointWindow]struct {
		seq  uint64
		hash string
	}
	checkpoints int
	signedSeq   uint64 // seq of the last checkpoint entry that verified
	signedTime  time.Time
	// anchor: a checkpoint held outside the log; the log must hold it unchanged.
	anchor      *AuditEntry
	anchorFound bool
	// export: the SIEM's copy (seq -> hash and content digest); every seq the
	// log still holds must match it, or be a vouched-for redaction of it.
	export              map[uint64]ExportedEntry
	exportMax           uint64
	redactedSinceExport int
}

// ExportedEntry is one entry of a SIEM export, as --compare-export loads it.
type ExportedEntry struct{ Hash, Digest string }

// checkpointWindow is how far back a checkpoint may point: it is appended
// right after reading the head, so only entries racing it come in between.
const checkpointWindow = 256

func (c *chainCheck) fail(format string, a ...any) {
	if c.err == nil {
		c.err = fmt.Errorf(format, a...)
	}
}

// clone copies c so a cached prefix is never mutated by a later add.
func (c chainCheck) clone() chainCheck {
	if c.pending != nil {
		c.pending = maps.Clone(c.pending)
	}
	if c.vouched != nil {
		c.vouched = maps.Clone(c.vouched)
	}
	return c
}

// trusted reports whether e's content is proven: its hash matches, or it is
// a redaction a subject.erase vouched for (with the digest it has now).
func (c *chainCheck) trusted(e AuditEntry) bool {
	if !e.Redacted {
		return e.Hash == e.sum()
	}
	d, ok := c.vouched[e.Seq]
	return ok && d == e.redactionDigest()
}

func (c *chainCheck) add(e AuditEntry) {
	if c.total == 0 && c.last == "" && e.Seq > 1 && c.err == nil && !c.cutFound { // retention removed the oldest entries
		c.cut, c.cutHash = e.Seq-1, e.Prev
		c.total, c.last = c.cut, c.cutHash
	}
	prev := c.last
	c.total++
	c.last, c.lastAction = e.Hash, e.Action
	c.recent[e.Seq%checkpointWindow] = struct {
		seq  uint64
		hash string
	}{e.Seq, e.Hash}
	if c.anchor != nil && e.Seq == c.anchor.Seq {
		c.anchorFound = true
		if e.Hash != c.anchor.Hash {
			c.fail("seq %d differs from the anchored checkpoint: the log was rewritten", e.Seq)
		}
	}
	if x, ok := c.export[e.Seq]; ok {
		switch {
		case x.Hash != e.Hash:
			c.fail("seq %d differs from the SIEM export: the log was rewritten", e.Seq)
		case x.Digest != e.redactionDigest() && e.Redacted:
			c.redactedSinceExport++ // must still be vouched for, below
		case x.Digest != e.redactionDigest():
			c.fail("seq %d: content differs from the SIEM export", e.Seq)
		}
	}
	if c.err != nil {
		return
	}
	switch {
	case e.Seq != c.total:
		c.fail("entry %d: seq %d out of order (entry removed or reordered)", c.total, e.Seq)
	case e.Prev != prev:
		c.fail("seq %d: prev hash does not match the preceding entry", e.Seq)
	case !e.intact():
		c.fail("seq %d: entry was modified (hash mismatch)", e.Seq)
	}
	if c.err != nil {
		return
	}
	if e.Redacted {
		if c.pending == nil {
			c.pending = map[uint64]string{}
		}
		c.pending[e.Seq] = e.redactionDigest()
	}
	switch e.Action {
	case actionRetention:
		if !c.signedBy(e, retentionMsg(e)) {
			return
		}
		cutoff, err := time.Parse(time.RFC3339, e.Details["cutoff"])
		if e.Actor == systemActor && err == nil && !cutoff.After(e.Time.Add(-MinAuditRetention)) &&
			e.Details["through"] == strconv.FormatUint(c.cut, 10) && e.Details["throughHash"] == c.cutHash {
			c.cutFound = true
		}
	case actionErase:
		if !c.signedBy(e, eraseMsg(e.Details["log"], e.Details["since"], e.Details["subject"], e.Details["redacted"])) {
			return
		}
		for _, v := range strings.Split(e.Details["redacted"], ",") {
			seq, digest, ok := strings.Cut(v, ":")
			n, err := strconv.ParseUint(seq, 10, 64)
			if ok && err == nil && c.pending[n] == digest {
				delete(c.pending, n)
				if c.vouched == nil {
					c.vouched = map[uint64]string{}
				}
				c.vouched[n] = digest
			}
		}
	case actionCheckpoint:
		c.checkpoint(e)
	case actionSigningEnabled:
		if e.Details["since"] != strconv.FormatUint(e.Seq, 10) {
			c.fail("seq %d: audit.signing.enabled names since %q, not its own seq", e.Seq, e.Details["since"])
			return
		}
		if c.verifier != nil {
			c.verifySigned(e, signingMsg(e))
		}
	}
}

// signedBy reports whether a vouching entry (subject.erase, audit.retention)
// may vouch. Without a verifier, always: links-only verification
// authenticates nothing. With one, a signed entry vouches when its signature
// verifies; an unsigned one is noted (unsignedMax) and vouches provisionally:
// done refuses the chain if it sits at or after the seq signing was enabled
// at (since, known from any verified signed entry). An unsigned vouch is
// legitimate only from before signing was enabled.
func (c *chainCheck) signedBy(e AuditEntry, msg string) bool {
	if c.verifier == nil {
		return true
	}
	if e.Details["sig"] == "" {
		c.unsignedMax = max(c.unsignedMax, e.Seq)
		return true
	}
	return c.verifySigned(e, msg)
}

// verifySigned checks a signed entry: its signature over msg (which includes
// the since it carries), that since agrees with every other signed entry, and
// that no previous key signs after the current key took over. It fails the
// chain and reports false on any mismatch.
func (c *chainCheck) verifySigned(e AuditEntry, msg string) bool {
	since, err := strconv.ParseUint(e.Details["since"], 10, 64)
	if err != nil || since == 0 || since > e.Seq {
		c.fail("seq %d: signed %s carries no valid since", e.Seq, e.Action)
		return false
	}
	log := e.Details["log"]
	key, err := verifySigKey(c.verifier, e.Details["alg"], e.Details["sig"], msg)
	switch {
	case err != nil:
		c.fail("seq %d: %s signature does not verify: %v", e.Seq, e.Action, err)
		return false
	case !logIDRE.MatchString(log):
		c.fail("seq %d: signed %s carries no valid log id", e.Seq, e.Action)
		return false
	case c.logID != "" && log != c.logID:
		c.fail("seq %d: %s was signed for another log (%s, this one is %s)", e.Seq, e.Action, log, c.logID)
		return false
	case c.since != 0 && since != c.since:
		c.fail("seq %d: %s says signing was enabled at seq %d, other signed entries say %d", e.Seq, e.Action, since, c.since)
		return false
	case key > 0 && c.currentSeen:
		c.fail("seq %d: %s signed by a previous audit key after the current key took over", e.Seq, e.Action)
		return false
	}
	c.since, c.logID, c.newestSignedKey = since, log, key
	c.currentSeen = c.currentSeen || key == 0
	return true
}

// Messages the audit key signs, one domain each, every one binding the log
// id (one per deployment, so a signature never replays across logs that
// share a key) and since (ADR-0040, ADR-0041).
func eraseMsg(log, since, subject, redacted string) string {
	return "halos.audit.erase.v3\n" + log + "\n" + since + "\n" + subject + "\n" + redacted
}

func retentionMsg(e AuditEntry) string {
	return fmt.Sprintf("halos.audit.retention.v3\n%s\n%s\n%s\n%s\n%s\n%s", e.Details["log"], e.Details["since"], e.Details["through"], e.Details["throughHash"], e.Details["cutoff"], e.Time.UTC().Format(time.RFC3339Nano))
}

// signingMsg is what audit.signing.enabled signs: the log id it creates,
// its own seq (since), the hash it follows and its time.
func signingMsg(e AuditEntry) string {
	return fmt.Sprintf("halos.audit.signing.v3\n%s\n%d\n%s\n%s", e.Details["log"], e.Seq, e.Prev, e.Time.UTC().Format(time.RFC3339Nano))
}

// verifySigKey verifies sig and reports which key of v did: 0 is the current
// key (the first of a key set), >0 a previous one.
func verifySigKey(v bundle.Verifier, alg, sig64, msg string) (int, error) {
	sig, err := base64.StdEncoding.DecodeString(sig64)
	if err != nil {
		return 0, fmt.Errorf("signature encoding: %w", err)
	}
	ring, ok := v.(bundle.Keyring)
	if !ok {
		return 0, bundle.VerifyAs(context.Background(), v, alg, msg, sig)
	}
	for i, k := range ring {
		if bundle.VerifyAs(context.Background(), k, alg, msg, sig) == nil {
			return i, nil
		}
	}
	return 0, fmt.Errorf("bundle: signature matches none of the %d trusted keys", len(ring))
}

// checkpoint checks a signed checkpoint entry (ADR-0041): the {seq, head} it
// names must be an entry just before it, and with a verifier its signature
// must verify. A chain recomputed after an edit fails here at the first
// checkpoint after the edit, since the key that signed it is not the editor's.
func (c *chainCheck) checkpoint(e AuditEntry) {
	seq, err := strconv.ParseUint(e.Details["seq"], 10, 64)
	if err == nil && c.cut > 0 && seq <= c.cut { // it names an entry retention removed: nothing left to check it against
		return
	}
	r := c.recent[seq%checkpointWindow]
	switch {
	case err != nil || seq >= e.Seq || r.seq != seq:
		c.fail("seq %d: checkpoint names seq %q, not one of the entries before it", e.Seq, e.Details["seq"])
		return
	case r.hash != e.Details["head"]:
		c.fail("seq %d: checkpoint head does not match seq %d: the chain was recomputed", e.Seq, seq)
		return
	}
	if c.verifier != nil {
		if !c.verifySigned(e, checkpointMsg(e.Details["log"], e.Details["since"], seq, r.hash, e.Time)) {
			return
		}
		c.signedSeq, c.signedTime, c.newestCheckpointKey = e.Seq, e.Time, c.newestSignedKey
	}
	c.checkpoints++
	c.newestCheckpoint = seq
}

// done is the verdict once every entry was added: the first break, or a
// retention cut nothing vouches for, a redaction no erasure vouches for, or an
// anchor the log no longer reaches.
func (c *chainCheck) done() error {
	if c.err != nil {
		return c.err
	}
	if c.requireCurrentKey && c.checkpoints > 0 && c.newestCheckpointKey != 0 {
		return errors.New("the newest signed checkpoint is not signed by the current key (the first --public-key): pass --allow-rotation-window while replicas are switching keys")
	}
	if c.strict && c.since == 0 && (c.unsignedMax > 0 || c.cut > 0) {
		return errors.New("the chain has unsigned erasures or retention cuts and no signed entry: nothing authenticates them (were the signed entries deleted?)")
	}
	if c.verifier != nil && c.since > 0 && c.unsignedMax >= c.since {
		return fmt.Errorf("seq %d: unsigned subject.erase or audit.retention after signing was enabled (seq %d): only the audit key vouches from then on", c.unsignedMax, c.since)
	}
	if c.cut > 0 && !c.cutFound {
		return fmt.Errorf("chain starts at seq %d but no audit.retention entry records that cut: the oldest entries were removed", c.cut+1)
	}
	if len(c.pending) > 0 {
		seqs := slices.Sorted(maps.Keys(c.pending))
		return fmt.Errorf("seq %d: redacted entry not vouched for by any subject.erase entry (or its content changed since)", seqs[0])
	}
	if c.export != nil && c.exportMax > c.total {
		return fmt.Errorf("log ends at seq %d, but the SIEM export holds seq %d: entries were cut from the end", c.total, c.exportMax)
	}
	if c.anchor != nil && !c.anchorFound {
		if c.total < c.anchor.Seq {
			return fmt.Errorf("log ends at seq %d, before the anchored checkpoint at seq %d: entries were cut from the end", c.total, c.anchor.Seq)
		}
		return fmt.Errorf("the anchored checkpoint at seq %d is no longer in the log", c.anchor.Seq)
	}
	return nil
}

// checkpointMsg is the message an audit checkpoint signs.
func checkpointMsg(log, since string, seq uint64, head string, t time.Time) string {
	return fmt.Sprintf("halos.audit.checkpoint.v3\n%s\n%s\n%d\n%s\n%s", log, since, seq, head, t.UTC().Format(time.RFC3339Nano))
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

	// ADR-0041: sign builds a signed checkpoint of (seq, head) (nil: signing
	// off); verifier checks them on every verification.
	sign     func(ctx context.Context, log string, since, seq uint64, head string, now time.Time) (AuditEntry, error)
	verifier bundle.Verifier
	key      bundle.KeySigner // signs subject.erase and audit.retention entries too (nil: unsigned)
	// knownSince and knownKey (under vmu): what this process saw of how the
	// chain is signed (ADR-0041): since, and the newest key that has signed.
	knownSince atomic.Uint64
	knownKey   string
	knownLog   string
	// checkHook holds a verified chain to the signing record (Server.checkSigning).
	checkHook func(*chainCheck)

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
	if err := checkpointStale(e, l.seq); err != nil {
		return err
	}
	e = ChainAuditEntry(e, l.seq, l.head)
	if l.f != nil {
		b, _ := json.Marshal(e) // plain struct: cannot fail
		if l.rotateDue(e.Time, len(b)+1) {
			// ADR-0041: a segment closes with a signed checkpoint of its last
			// entry, so a rotated segment is anchored even between periodic ones.
			// Like every signature, only over a chain that verifies (and that has
			// signing enabled already: the marker comes from Checkpoint).
			if l.sign != nil {
				err := errChainUnverified
				c, verr := l.verifiedLocked()
				if verr == nil && l.checkHook != nil {
					l.checkHook(&c) // the signing record and memory too, as for every signature
					verr = c.err
				}
				if verr == nil && c.since > 0 && c.total == l.seq && c.last == l.head {
					sctx, cancel := context.WithTimeout(context.Background(), rotationSignTimeout) // appends wait on l.mu: never a slow signer's full timeout
					var cp AuditEntry
					cp, err = l.sign(sctx, c.logID, c.since, l.seq, l.head, e.Time)
					cancel()
					if err == nil {
						err = l.write(ChainAuditEntry(cp, l.seq, l.head))
					}
				}
				if err != nil {
					orDefault(l.log).Error("audit: no checkpoint at rotation; rotating without it", "err", err)
				}
				e = ChainAuditEntry(e, l.seq, l.head)
			}
			// A failed rotation is not an audit failure: the entry still goes to
			// the active segment (or the write below fails closed) and the next
			// append retries. On Windows a reader holding the file open is enough.
			if err := l.rotate(); err != nil {
				l.rotateErrs.Add(1)
				orDefault(l.log).Error("audit rotation failed; appending to the active segment", "err", err)
			}
		}
		if err := l.write(e); err != nil {
			return err
		}
	} else {
		l.mem = append(l.mem, e)
		l.seq, l.head = e.Seq, e.Hash
	}
	if l.wake != nil { // wake export forwarders: close-and-replace broadcasts to all of them
		close(l.wake)
		l.wake = nil
	}
	return nil
}

// write appends the chained entry e to the active segment, durably (l.mu held).
func (l *auditLog) write(e AuditEntry) error {
	b, _ := json.Marshal(e) // plain struct: cannot fail
	b = append(b, '\n')
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
	l.seq, l.head = e.Seq, e.Hash
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
	return l.snapshotLocked()
}

// snapshotLocked is snapshot with l.mu held (file and memory backends).
func (l *auditLog) snapshotLocked() (*auditSnap, error) {
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
// size and mtime is caught by `halo audit verify`, which never caches. The
// returned check's err is the final verdict (chainCheck.done).
func (l *auditLog) verify(s *auditSnap) (chainCheck, error) {
	if s.shared != nil {
		return l.verifyShared(s)
	}
	c := l.newCheck()
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
			c = l.vcache.c.clone()
		}
		l.vmu.Unlock()
		if !hit {
			for i := range s.segs {
				if _, err := s.segment(i, add); err != nil {
					return c, err
				}
			}
			l.vmu.Lock()
			l.vcache.key, l.vcache.c = key.String(), c.clone()
			l.vmu.Unlock()
		}
	}
	_, err := s.segment(len(s.segs), add)
	c.err = c.done()
	return c, err
}

// newCheck is a chainCheck with this log's checkpoint verifier.
func (l *auditLog) newCheck() chainCheck { return chainCheck{verifier: l.verifier} }

// verifiedLocked verifies the file or memory chain with l.mu held (the
// rotation checkpoint signs only over a chain that verifies).
func (l *auditLog) verifiedLocked() (chainCheck, error) {
	snap, err := l.snapshotLocked()
	if err != nil {
		return chainCheck{}, err
	}
	defer snap.close()
	c, err := l.verify(snap)
	if err == nil && c.err != nil {
		err = c.err
	}
	return c, err
}

// dropCache forgets the verified prefix, so the next verification reads
// the whole chain (another replica may have redacted entries in it).
func (l *auditLog) dropCache() {
	l.vmu.Lock()
	l.vcache.key, l.vcache.c = "", chainCheck{}
	l.vmu.Unlock()
}

// auditReadTimeout bounds one page of a streamed read of the shared chain.
const auditReadTimeout = time.Minute

// auditPage is how many rows one page of a shared-chain read holds: each
// page has its own auditReadTimeout, so a log of any size can be read.
const auditPage = 5000

// rotationSignTimeout bounds the checkpoint signed at rotation, under l.mu:
// past it the segment rotates unsigned and the periodic checkpoint covers it.
var rotationSignTimeout = 5 * time.Second // var: tests shorten it

// sharedFrom streams the shared chain from seq on, oldest first.
func (s *auditSnap) sharedFrom(seq uint64, fn func(raw []byte, e AuditEntry) bool) (bool, error) {
	return eachAuditPaged(context.Background(), s.shared, seq, fn)
}

// eachAuditPaged streams b's chain from seq on, oldest first, a page at a
// time, each page under its own timeout (and ctx).
func eachAuditPaged(ctx context.Context, b Backend, seq uint64, fn func(raw []byte, e AuditEntry) bool) (bool, error) {
	for {
		pctx, cancel := context.WithTimeout(ctx, auditReadTimeout)
		n, last, cont := 0, uint64(0), true
		err := b.EachAudit(pctx, seq, func(raw []byte, e AuditEntry) bool {
			n++
			last = max(last, e.Seq)
			cont = fn(raw, e)
			return cont && n < auditPage
		})
		cancel()
		if err != nil {
			return false, fmt.Errorf("audit: read: %w", err)
		}
		if !cont || n < auditPage {
			return cont, nil
		}
		next := last + 1
		if next <= seq { // a page of undecodable rows: step past them
			next = seq + uint64(n)
		}
		seq = next
	}
}

// verifyShared verifies the shared chain. A verified prefix is cached and
// reused only while its last entry still reads back with the same hash, so a
// request reads just the entries appended since. ponytail: an edit to an
// older row that keeps that last hash is caught by `halo audit verify
// --database-url-file`, which never caches (as the file backend's segment
// cache). An erasure drops the cache (auditLog.redact).
func (l *auditLog) verifyShared(s *auditSnap) (chainCheck, error) {
	l.vmu.Lock()
	c := l.vcache.c.clone()
	l.vmu.Unlock()
	if c.err != nil || c.total == 0 {
		c = l.newCheck()
	} else {
		same := false
		if _, err := s.sharedFrom(c.total, func(_ []byte, e AuditEntry) bool { same = e.Seq == c.total && e.Hash == c.last; return false }); err != nil {
			return c, err
		}
		if !same {
			c = l.newCheck()
		}
	}
	if _, err := s.sharedFrom(c.total+1, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
		return c, err
	}
	if c.err == nil {
		l.vmu.Lock()
		l.vcache.c = c.clone()
		l.vmu.Unlock()
	}
	c.err = c.done()
	return c, nil
}

// AuditVerifyOptions tune the offline verifiers (`halo audit verify`).
type AuditVerifyOptions struct {
	// Verifier checks checkpoint signatures (ADR-0041); nil checks links only.
	Verifier bundle.Verifier
	// Anchor is a checkpoint entry held outside the log (the newest one your
	// SIEM received): the log must still hold it unchanged, so cutting entries
	// from the end, or recomputing the chain, is caught.
	Anchor *AuditEntry
	// Export is the SIEM's copy (LoadExport): every seq both hold must have
	// the same hash and content, unless the log's entry is a vouched-for
	// redaction, and the log must reach the export's last seq. Unlike Anchor,
	// this compares content, not just the newest checkpoint.
	Export map[uint64]ExportedEntry
	// RequireCurrentKey: the newest verified checkpoint must be signed by the
	// Verifier's first key (the current one): a leaked previous key cannot
	// rewrite the tail after a rotation.
	RequireCurrentKey bool
}

func (o AuditVerifyOptions) check() chainCheck {
	c := chainCheck{verifier: o.Verifier, anchor: o.Anchor, export: o.Export, strict: o.Verifier != nil, requireCurrentKey: o.RequireCurrentKey}
	for seq := range o.Export {
		c.exportMax = max(c.exportMax, seq)
	}
	return c
}

// LoadExport reads a SIEM export for AuditVerifyOptions.Export. ponytail:
// holds two hex digests per exported entry in memory (about 150 bytes each);
// split the export by seq range if it is too large for that.
func LoadExport(path string) (map[uint64]ExportedEntry, error) {
	out := map[uint64]ExportedEntry{}
	bad := 0
	err := eachExportedEntry(path, func(e AuditEntry) {
		if e.Hash == "" {
			bad++
			return
		}
		out[e.Seq] = ExportedEntry{Hash: e.Hash, Digest: e.redactionDigest()}
	})
	switch {
	case err != nil:
		return nil, err
	case bad > 0:
		return nil, fmt.Errorf("%s: %d lines are not audit entries (native, or OCSF with raw_data)", path, bad)
	case len(out) == 0:
		return nil, fmt.Errorf("%s: holds no audit entries: an empty export anchors nothing", path)
	}
	return out, nil
}

// VerifyAuditBackend verifies the whole shared chain, streaming and uncached
// (`halo audit verify --database-url-file`). Segments is 0: there are none.
func VerifyAuditBackend(ctx context.Context, b Backend, o AuditVerifyOptions) (AuditVerifyResult, error) {
	c := o.check()
	if _, err := eachAuditPaged(ctx, b, 1, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
		return AuditVerifyResult{}, fmt.Errorf("verify audit log: %w", err)
	}
	// The head row is updated with every append: rows deleted from the end
	// (or all of them) leave it ahead of the table.
	seq, hash, err := b.AuditHead(ctx)
	if err != nil {
		return AuditVerifyResult{}, fmt.Errorf("verify audit log: read head: %w", err)
	}
	if seq != c.total || hash != c.last {
		c.fail("the table ends at seq %d but the head row says seq %d: entries were deleted from the end", c.total, seq)
	}
	return c.result(0), nil
}

// AuditVerifyResult is what VerifyAuditDir reports. With a verifier,
// Checkpoints counts the checkpoints whose signature verified and
// UnsignedTail the entries after the last of them: what could have been cut
// or rewritten without breaking a signature, unless an anchor pins it.
type AuditVerifyResult struct {
	Entries        uint64 `json:"entries"`
	Segments       int    `json:"segments"` // files read, the active one included
	Head           string `json:"head"`
	Error          string `json:"error,omitempty"`
	First          uint64 `json:"first,omitempty"` // seq of the oldest entry, when retention removed older ones
	Checkpoints    int    `json:"checkpoints,omitempty"`
	LastCheckpoint uint64 `json:"lastCheckpoint,omitempty"`
	UnsignedTail   uint64 `json:"unsignedTail,omitempty"`
	Anchored       bool   `json:"anchored,omitempty"` // the anchor was found unchanged
	// RedactedSinceExport counts entries that differ from the SIEM export only
	// because an erasure redacted them (each vouched for).
	RedactedSinceExport int `json:"redactedSinceExport,omitempty"`
}

func (c *chainCheck) result(segments int) AuditVerifyResult {
	r := AuditVerifyResult{Entries: c.total - c.cut, Segments: segments, Head: c.last, Checkpoints: c.checkpoints, Anchored: c.anchorFound && c.err == nil,
		RedactedSinceExport: c.redactedSinceExport}
	if c.cut > 0 {
		r.First = c.cut + 1
	}
	if c.verifier != nil {
		r.LastCheckpoint, r.UnsignedTail = c.signedSeq, c.total-max(c.signedSeq, c.cut)
	}
	if err := c.done(); err != nil {
		r.Error = err.Error()
	}
	return r
}

// VerifyAuditExport verifies a file of exported entries (one native entry
// per line, or OCSF events whose raw_data is one) as a SIEM received them.
// An export may start after genesis: its first entry is taken as the start.
func VerifyAuditExport(path string, o AuditVerifyOptions) (AuditVerifyResult, error) {
	c := o.check()
	first := true
	err := eachExportedEntry(path, func(e AuditEntry) {
		if first && e.Seq > 1 { // a sink anchors on the oldest entry still on disk
			c.cut, c.cutHash, c.cutFound = e.Seq-1, e.Prev, true
			c.total, c.last = c.cut, c.cutHash
		}
		first = false
		c.add(e)
	})
	if err != nil {
		return AuditVerifyResult{}, fmt.Errorf("verify audit export: %w", err)
	}
	return c.result(1), nil
}

// eachExportedEntry streams the entries of an export file: native lines, or
// OCSF events carrying the native entry in raw_data.
func eachExportedEntry(path string, fn func(AuditEntry)) error {
	return eachAuditFile(path, func(raw []byte, e AuditEntry) bool {
		var o struct {
			RawData string `json:"raw_data"`
		}
		if e.Hash == "" && json.Unmarshal(raw, &o) == nil && o.RawData != "" {
			e = AuditEntry{}
			_ = json.Unmarshal([]byte(o.RawData), &e) // garbage: zero entry, the chain breaks there
		}
		fn(e)
		return true
	})
}

// LastCheckpoint returns the newest checkpoint entry in an export file, to
// pass as AuditVerifyOptions.Anchor. Its own hash must match its content and,
// with v, its signature must verify; ok is false when the file holds none.
func LastCheckpoint(path string, v bundle.Verifier) (e AuditEntry, ok bool, err error) {
	err = eachExportedEntry(path, func(x AuditEntry) {
		if x.Action == actionCheckpoint {
			e, ok = x, true
		}
	})
	if err != nil || !ok {
		return e, ok, err
	}
	if e.Hash != e.sum() {
		return e, false, fmt.Errorf("anchor checkpoint seq %d: hash does not match its content", e.Seq)
	}
	if v != nil {
		if err := verifyCheckpointSig(v, e); err != nil {
			return e, false, fmt.Errorf("anchor checkpoint seq %d: %w", e.Seq, err)
		}
	}
	return e, true, nil
}

// verifyCheckpointSig checks e's signature over the {seq, head} it names.
func verifyCheckpointSig(v bundle.Verifier, e AuditEntry) error {
	seq, err := strconv.ParseUint(e.Details["seq"], 10, 64)
	if err != nil {
		return fmt.Errorf("checkpoint seq %q: %w", e.Details["seq"], err)
	}
	_, err = verifySigKey(v, e.Details["alg"], e.Details["sig"], checkpointMsg(e.Details["log"], e.Details["since"], seq, e.Details["head"], e.Time))
	return err
}

// VerifyAuditDir verifies the chain across every segment in dir (rotated
// segments oldest first, then audit.jsonl), streaming and uncached. It only
// reads, so it is safe against a live server's data dir. err is an I/O error;
// a broken chain is AuditVerifyResult.Error.
func VerifyAuditDir(dir string, o AuditVerifyOptions) (AuditVerifyResult, error) {
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
	c := o.check()
	for _, p := range paths {
		if err := eachAuditFile(p, func(_ []byte, e AuditEntry) bool { c.add(e); return true }); err != nil {
			return AuditVerifyResult{}, fmt.Errorf("verify audit log: %w", err)
		}
	}
	return c.result(len(paths)), nil
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
	details = authzDetails(ctx, actor, details) // the scoped grant that authorized it (ADR-0037)
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
	// ADR-0041: Signed is true when checkpoint signing is on; Checkpoints
	// counts the checkpoints that verified (their signatures too when Signed),
	// LastCheckpoint is the seq of the newest one whose signature verified.
	Signed         bool   `json:"signed,omitempty"`
	Checkpoints    int    `json:"checkpoints,omitempty"`
	LastCheckpoint uint64 `json:"lastCheckpoint,omitempty"`
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
	s.checkSigning(&c)                                                                                                // the signing record too: what the server would refuse to sign over is not "verified"
	resp := AuditResponse{Entries: []AuditEntry{}, Total: int(c.total - c.cut), Verified: c.err == nil, Head: c.last, //nolint:gosec // entry count fits an int
		Signed: c.verifier != nil, Checkpoints: c.checkpoints, LastCheckpoint: c.signedSeq}
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
