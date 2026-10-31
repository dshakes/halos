package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/rollout"
)

// importLogs are the JSONL logs `halo-server import` copies record for record.
var importLogs = []string{"devices", "requests", "session-revocations", "killswitch", "controller-state", "scim"}

// ImportReport is what ImportDataDir copied, by the names pgstore.DB.Counts uses.
type ImportReport struct {
	Copied  map[string]int64 // e.g. "journal/devices", "audit", "reports", "docs/rollout-state"
	Skipped map[string]int   // torn or undecodable source lines, per file
	Head    string           // audit chain head hash after the copy
}

// ImportDataDir copies a stopped single-replica server's data dir into an
// empty Postgres database, then verifies it: per-log record counts, report
// and rollout counts, and the whole audit chain (which must verify in the
// source too, and end at the same head). The source is only read. The copy
// and the verification run in one transaction, so an import that fails at
// any step leaves the database empty and can simply be run again.
func ImportDataDir(ctx context.Context, dir string, b *PGBackend) (ImportReport, error) {
	rep := ImportReport{Copied: map[string]int64{}, Skipped: map[string]int{}}
	src, err := readDataDir(dir, &rep)
	if err != nil {
		return rep, err
	}
	err = b.Import(ctx, func(im *pgstore.Importer) error {
		for _, e := range src.audit {
			body, err := json.Marshal(e)
			if err != nil {
				return fmt.Errorf("import: audit seq %d: %w", e.Seq, err)
			}
			if err := im.AppendAudit(pgstore.AuditLink{Seq: e.Seq, Hash: e.Hash, Prev: e.Prev, Entry: body, At: e.Time}); err != nil {
				return fmt.Errorf("import: audit seq %d: %w", e.Seq, err)
			}
		}
		for _, name := range importLogs {
			for _, l := range src.logs[name] {
				if err := im.AppendJournal(name, l); err != nil { // unkeyed: an exact copy, history included
					return fmt.Errorf("import: %w", err)
				}
			}
		}
		for _, h := range src.reports {
			body, err := json.Marshal(h)
			if err != nil {
				return fmt.Errorf("import: report %s: %w", h.Hostname, err)
			}
			if err := im.PutReport(h.key(), h.Hostname, body); err != nil {
				return fmt.Errorf("import: %w", err)
			}
		}
		if err := im.AddBudget(src.budgets); err != nil {
			return fmt.Errorf("import: %w", err)
		}
		for name, raw := range src.cursors {
			if err := im.PutDoc(kindAuditCursor, name, raw); err != nil {
				return fmt.Errorf("import: %w", err)
			}
		}
		for name, raw := range src.rollouts {
			if err := im.PutDoc(rollout.DocKind, name, raw); err != nil {
				return fmt.Errorf("import: %w", err)
			}
		}
		for _, r := range src.revocations {
			if err := im.PutRevocation(r); err != nil {
				return fmt.Errorf("import: %w", err)
			}
		}
		for _, t := range src.tokens {
			if err := im.PutServiceToken(t); err != nil {
				return fmt.Errorf("import: %w", err)
			}
		}
		return verifyImport(im, src, &rep)
	})
	return rep, err
}

// dataDir is everything ImportDataDir copies, read and checked up front.
type dataDir struct {
	audit    []AuditEntry
	logs     map[string][]json.RawMessage
	reports  []Host
	budgets  []pgstore.BudgetCounter
	cursors  map[string]json.RawMessage
	rollouts map[string][]byte
	// revocations: the credential revocation log replayed (one row per
	// target, ADR-0026), so none is lost moving to the database.
	revocations []pgstore.Revocation
	// tokens: the service-token log replayed (one row per token, revocations
	// kept, ADR-0036), so no token is lost or revived by the move.
	tokens []pgstore.ServiceToken
}

func readDataDir(dir string, rep *ImportReport) (dataDir, error) {
	src := dataDir{logs: map[string][]json.RawMessage{}, cursors: map[string]json.RawMessage{}, rollouts: map[string][]byte{}}
	// Audit first: refuse a source whose chain is already broken.
	// Rotated segments (ADR-0016) oldest first, then the active one: one chain.
	segs, err := listAuditSegs(dir)
	if err != nil {
		return src, fmt.Errorf("import: %w", err)
	}
	for _, p := range append(segPaths(segs), filepath.Join(dir, auditActive)) {
		es, skipped, err := readJSONL[AuditEntry](p, func(e AuditEntry) bool { return e.Hash != "" })
		if err != nil {
			return src, err
		}
		if skipped > 0 {
			rep.Skipped[filepath.Base(p)] = skipped
		}
		src.audit = append(src.audit, es...)
	}
	if len(src.audit) > 0 && src.audit[0].Seq != 1 {
		return src, fmt.Errorf("import: the source audit chain starts at seq %d, not 1: its oldest segments were removed (archived after rotation). "+
			"Copy the archived audit-*.jsonl segments back into %s and import again; the database chain must start at genesis", src.audit[0].Seq, dir)
	}
	if err := VerifyAuditChain(src.audit); err != nil {
		return src, fmt.Errorf("import: source audit chain does not verify, not importing: %w", err)
	}
	rep.Copied["audit"] = int64(len(src.audit))

	for _, name := range importLogs {
		lines, skipped, err := readJSONL[json.RawMessage](filepath.Join(dir, name+".jsonl"), func(json.RawMessage) bool { return true })
		if err != nil {
			return src, err
		}
		if skipped > 0 {
			rep.Skipped[name+".jsonl"] = skipped
		}
		if len(lines) > 0 {
			src.logs[name] = lines
			rep.Copied["journal/"+name] = int64(len(lines))
		}
	}

	hosts, skipped, err := readJSONL[Host](filepath.Join(dir, "reports.jsonl"), func(h Host) bool { return h.Hostname != "" })
	if err != nil {
		return src, err
	}
	if skipped > 0 {
		rep.Skipped["reports.jsonl"] = skipped
	}
	latest := map[string]Host{} // last line per reporter wins, as the file store replays
	for _, h := range hosts {
		latest[h.key()] = h
	}
	for _, h := range latest {
		src.reports = append(src.reports, h)
	}
	if len(latest) > 0 {
		rep.Copied["reports"] = int64(len(latest))
	}

	if src.budgets, err = readBudgets(dir); err != nil {
		return src, err
	}
	if len(src.budgets) > 0 {
		rep.Copied["budget-buckets"] = int64(len(src.budgets))
	}

	paths, err := filepath.Glob(filepath.Join(dir, "audit-forward", "*.json"))
	if err != nil {
		return src, fmt.Errorf("import: %w", err)
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return src, fmt.Errorf("import: %w", err)
		}
		var c auditCursor
		if err := json.Unmarshal(raw, &c); err != nil {
			return src, fmt.Errorf("import: cursor %s: %w", p, err)
		}
		src.cursors[strings.TrimSuffix(filepath.Base(p), ".json")] = raw
		rep.Copied["docs/"+kindAuditCursor]++
	}

	names, err := rolloutNames(filepath.Join(dir, "rollouts"))
	if err != nil {
		return src, err
	}
	for _, n := range names {
		st, err := rollout.LoadState(filepath.Join(dir, "rollouts"), n) // verifies the history chain
		if err != nil {
			return src, fmt.Errorf("import: %w", err)
		}
		b, err := json.Marshal(&st)
		if err != nil {
			return src, fmt.Errorf("import: rollout %s: %w", n, err)
		}
		src.rollouts[n] = b
	}
	if len(names) > 0 {
		rep.Copied["docs/"+rollout.DocKind] = int64(len(names))
	}

	revs, skipped, err := readJSONL[pgstore.Revocation](filepath.Join(dir, revocationLogName+".jsonl"), func(r pgstore.Revocation) bool { return r.Key != "" })
	if err != nil {
		return src, err
	}
	if skipped > 0 {
		rep.Skipped[revocationLogName+".jsonl"] = skipped
	}
	rl := &revocationLog{m: map[[2]string]pgstore.Revocation{}, now: time.Now}
	for _, r := range revs {
		rl.merge(r)
	}
	for _, r := range rl.m { // expired rows too: the database skips and prunes them
		src.revocations = append(src.revocations, r)
	}
	if len(src.revocations) > 0 {
		rep.Copied["revocations"] = int64(len(src.revocations))
	}

	toks, skipped, err := readJSONL[pgstore.ServiceToken](filepath.Join(dir, serviceTokenLogName+".jsonl"), func(t pgstore.ServiceToken) bool { return t.ID != "" })
	if err != nil {
		return src, err
	}
	if skipped > 0 {
		rep.Skipped[serviceTokenLogName+".jsonl"] = skipped
	}
	tl := &serviceTokenLog{m: map[string]pgstore.ServiceToken{}}
	for _, t := range toks {
		tl.merge(t)
	}
	for _, t := range tl.m {
		src.tokens = append(src.tokens, t)
	}
	if len(src.tokens) > 0 {
		rep.Copied["service-tokens"] = int64(len(src.tokens))
	}
	return src, nil
}

// verifyImport checks, inside the import transaction, that the database holds
// exactly what was read and that the copied chain verifies to the source head.
func verifyImport(im *pgstore.Importer, src dataDir, rep *ImportReport) error {
	after, err := im.Counts()
	if err != nil {
		return err
	}
	for k, n := range rep.Copied {
		if after[k] != n {
			return fmt.Errorf("import: verify %s: copied %d, database has %d", k, n, after[k])
		}
	}
	for k, n := range after {
		if _, ok := rep.Copied[k]; !ok && n > 0 {
			return fmt.Errorf("import: verify: unexpected %d rows in %s", n, k)
		}
	}
	var c chainCheck
	if err := im.EachAudit(func(_ uint64, raw []byte) bool {
		var e AuditEntry
		_ = json.Unmarshal(raw, &e) // garbage: zero entry, the chain breaks there
		c.add(e)
		return true
	}); err != nil {
		return fmt.Errorf("import: verify: %w", err)
	}
	if c.err != nil {
		return fmt.Errorf("import: verify: imported audit chain: %w", c.err)
	}
	rep.Head = c.last
	if len(src.audit) > 0 && rep.Head != src.audit[len(src.audit)-1].Hash {
		return errors.New("import: verify: imported audit head differs from the source head")
	}
	return nil
}

func segPaths(segs []auditSeg) []string {
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		out = append(out, s.path)
	}
	return out
}

// readBudgets reads budgets.json's counters (ADR-0017), bucket for bucket.
// Remembered batch ids are not copied: they expire within the hour.
func readBudgets(dir string) ([]pgstore.BudgetCounter, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "budgets.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}
	if _, err := budget.LoadLedger(raw); err != nil { // the version check the server applies
		return nil, fmt.Errorf("import: budgets.json: %w", err)
	}
	var f struct {
		Counters budget.Counters `json:"counters"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("import: budgets.json: %w", err)
	}
	var incs []pgstore.BudgetCounter
	for name, byKey := range f.Counters {
		for key, bk := range byKey {
			for start, sp := range bk {
				incs = append(incs, pgstore.BudgetCounter{Budget: name, Key: key, Bucket: start, USD: sp.USD, Tokens: sp.Tokens})
			}
		}
	}
	return incs, nil
}

// readJSONL decodes every line of path (missing = empty), counting lines that
// do not decode or that keep rejects (torn writes) as skipped.
func readJSONL[T any](path string, keep func(T) bool) ([]T, int, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("import: %w", err)
	}
	var out []T
	skipped := 0
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var v T
		if json.Unmarshal(line, &v) != nil || !keep(v) {
			skipped++
			continue
		}
		out = append(out, v)
	}
	return out, skipped, nil
}

// rolloutNames lists <dir>/<name>.json (missing dir = none).
func rolloutNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok && !e.IsDir() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}
