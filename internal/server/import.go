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

	"github.com/dshakes/halos/internal/rollout"
)

// importLogs are the JSONL logs `halo-server import` copies record for record.
var importLogs = []string{"devices", "requests", "session-revocations", "killswitch", "controller-state"}

// ImportReport is what ImportDataDir copied, by the names pgstore.DB.Counts uses.
type ImportReport struct {
	Copied  map[string]int64 // e.g. "journal/devices", "audit", "reports", "docs/rollout-state"
	Skipped map[string]int   // torn or undecodable source lines, per file
	Head    string           // audit chain head hash after the copy
}

// ImportDataDir copies a stopped single-replica server's data dir into an
// empty Postgres database, then verifies it: per-log record counts, report
// and rollout counts, and the whole audit chain (which must verify in the
// source too, and end at the same head). The source is only read.
func ImportDataDir(ctx context.Context, dir string, b *PGBackend) (ImportReport, error) {
	rep := ImportReport{Copied: map[string]int64{}, Skipped: map[string]int{}}
	before, err := b.Counts(ctx)
	if err != nil {
		return rep, err
	}
	for k, n := range before {
		if n > 0 {
			return rep, fmt.Errorf("import: target database is not empty (%s has %d rows): import into a freshly migrated database", k, n)
		}
	}

	// Audit first: refuse a source whose chain is already broken.
	entries, skipped, err := readJSONL[AuditEntry](filepath.Join(dir, "audit.jsonl"), func(e AuditEntry) bool { return e.Hash != "" })
	if err != nil {
		return rep, err
	}
	if skipped > 0 {
		rep.Skipped["audit.jsonl"] = skipped
	}
	if err := VerifyAuditChain(entries); err != nil {
		return rep, fmt.Errorf("import: source audit chain does not verify, not importing: %w", err)
	}
	for _, e := range entries {
		if err := b.ImportAuditEntry(ctx, e); err != nil {
			return rep, fmt.Errorf("import: audit seq %d: %w", e.Seq, err)
		}
	}
	rep.Copied["audit"] = int64(len(entries))

	for _, name := range importLogs {
		lines, skipped, err := readJSONL[json.RawMessage](filepath.Join(dir, name+".jsonl"), func(json.RawMessage) bool { return true })
		if err != nil {
			return rep, err
		}
		if skipped > 0 {
			rep.Skipped[name+".jsonl"] = skipped
		}
		if len(lines) == 0 {
			continue
		}
		log, err := b.OpenLog(ctx, name, func([]byte) {})
		if err != nil {
			return rep, fmt.Errorf("import: %s: %w", name, err)
		}
		for _, l := range lines {
			if err := log.Append(ctx, "", l); err != nil { // unkeyed: an exact copy, history included
				return rep, fmt.Errorf("import: %s: %w", name, err)
			}
		}
		rep.Copied["journal/"+name] = int64(len(lines))
	}

	hosts, skipped, err := readJSONL[Host](filepath.Join(dir, "reports.jsonl"), func(h Host) bool { return h.Hostname != "" })
	if err != nil {
		return rep, err
	}
	if skipped > 0 {
		rep.Skipped["reports.jsonl"] = skipped
	}
	latest := map[string]Host{} // last line per reporter wins, as the file store replays
	for _, h := range hosts {
		latest[h.key()] = h
	}
	reports := NewPGStore(b.DB)
	for _, h := range latest {
		if err := reports.Put(h); err != nil {
			return rep, fmt.Errorf("import: report %s: %w", h.Hostname, err)
		}
	}
	if len(latest) > 0 {
		rep.Copied["reports"] = int64(len(latest))
	}

	names, err := rolloutNames(filepath.Join(dir, "rollouts"))
	if err != nil {
		return rep, err
	}
	states := b.RolloutStates()
	for _, n := range names {
		st, err := rollout.LoadState(filepath.Join(dir, "rollouts"), n) // verifies the history chain
		if err != nil {
			return rep, fmt.Errorf("import: %w", err)
		}
		if err := states.Save(ctx, &st); err != nil {
			return rep, fmt.Errorf("import: rollout %s: %w", n, err)
		}
	}
	if len(names) > 0 {
		rep.Copied["docs/rollout-state"] = int64(len(names))
	}

	// Verify what landed.
	after, err := b.Counts(ctx)
	if err != nil {
		return rep, err
	}
	for k, n := range rep.Copied {
		if after[k] != n {
			return rep, fmt.Errorf("import: verify %s: copied %d, database has %d", k, n, after[k])
		}
	}
	for k, n := range after {
		if _, ok := rep.Copied[k]; !ok && n > 0 {
			return rep, fmt.Errorf("import: verify: unexpected %d rows in %s", n, k)
		}
	}
	vr, err := VerifyAuditBackend(ctx, b)
	if err != nil {
		return rep, err
	}
	if vr.Error != "" {
		return rep, fmt.Errorf("import: verify: imported audit chain: %s", vr.Error)
	}
	rep.Head = vr.Head
	if len(entries) > 0 && rep.Head != entries[len(entries)-1].Hash {
		return rep, errors.New("import: verify: imported audit head differs from the source head")
	}
	return rep, nil
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
