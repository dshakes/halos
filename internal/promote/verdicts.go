package promote

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
)

// verdictRow is one entry of the verdicts file halo-server reads (server.Verdict).
type verdictRow struct {
	Experiment string `json:"experiment"`
	Report
	EvaluatedAt time.Time `json:"evaluatedAt"`
}

// UpsertVerdict replaces (or appends) the experiment's entry in the JSON array
// at path, atomically. Other entries are kept verbatim.
// ponytail: read-modify-write without a lock; run one writer (controller or
// `halo exp analyze`) per file.
func UpsertVerdict(path, experiment string, rep Report, at time.Time) error {
	var rows []json.RawMessage
	switch b, err := os.ReadFile(path); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read verdicts %s: %w", path, err)
	default:
		if err := json.Unmarshal(b, &rows); err != nil {
			return fmt.Errorf("parse verdicts %s (want a JSON array): %w", path, err)
		}
	}
	nb, err := json.Marshal(verdictRow{experiment, rep, at})
	if err != nil {
		return fmt.Errorf("encode verdict %s: %w", experiment, err)
	}
	replaced := false
	for i, r := range rows {
		var k struct {
			Experiment string `json:"experiment"`
		}
		if json.Unmarshal(r, &k) == nil && k.Experiment == experiment {
			rows[i], replaced = nb, true
			break
		}
	}
	if !replaced {
		rows = append(rows, nb)
	}
	out, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return fmt.Errorf("encode verdicts %s: %w", path, err)
	}
	if err := fsutil.WriteAtomic(path, append(out, '\n'), fsutil.ExistingPerm(path, 0o644)); err != nil {
		return fmt.Errorf("write verdicts %s: %w", path, err)
	}
	return nil
}
