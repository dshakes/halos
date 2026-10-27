package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dshakes/halos/internal/promote"
)

// Table is the ClickHouse table stored records are copied to for analytics
// (deploy/observability/clickhouse/schema.sql). The audit chain stays the
// record of truth; the table is a query copy, one row per stored version
// (ReplacingMergeTree on stored_at keeps the latest). record_sha256 is the
// SHA-256 of the record JSON halo-server put in the audit entry's
// details.record, so a row can be checked against the chain.
const Table = "halo_session_ledger"

type row struct {
	ID             string   `json:"id"`
	SessionID      string   `json:"session_id"`
	User           string   `json:"user"`
	VendorUser     string   `json:"vendor_user"`
	UnitID         string   `json:"unit_id"`
	Agents         []string `json:"agents"`
	Harness        string   `json:"harness"`
	HarnessVersion string   `json:"harness_version"`
	Release        string   `json:"release"`
	Ring           string   `json:"ring"`
	Experiment     string   `json:"experiment"`
	Variant        string   `json:"variant"`
	Models         []string `json:"models"`
	MCPServers     []string `json:"mcp_servers"`
	Tools          []string `json:"tools"`
	Repos          []string `json:"repos"`
	Files          []string `json:"files"`
	FilesTouched   int      `json:"files_touched"`
	InputTokens    int64    `json:"input_tokens"`
	OutputTokens   int64    `json:"output_tokens"`
	CostUSD        float64  `json:"cost_usd"`
	StartedAt      string   `json:"started_at"`
	EndedAt        string   `json:"ended_at"`
	Outcome        string   `json:"outcome"`
	Sources        []string `json:"sources"`
	Confidence     string   `json:"confidence"`
	Redacted       int      `json:"redacted"`
	StoredAt       string   `json:"stored_at"`
	RecordSHA256   string   `json:"record_sha256"`
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// toRow maps a stored record to a halo_session_ledger row.
func toRow(r Record, storedAt time.Time) (row, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return row{}, err
	}
	sum := sha256.Sum256(b)
	return row{
		ID: r.ID, SessionID: r.SessionID, User: r.Who.User, VendorUser: r.Who.VendorUser, UnitID: r.Who.Unit, Agents: nonNil(r.Who.Agents),
		Harness: r.Harness, HarnessVersion: r.HarnessVersion, Release: r.Release, Ring: r.Ring, Experiment: r.Experiment, Variant: r.Variant,
		Models: nonNil(r.Models), MCPServers: nonNil(r.MCPServers), Tools: nonNil(r.Tools), Repos: nonNil(r.Repos), Files: nonNil(r.Files),
		FilesTouched: r.FilesTouched, InputTokens: r.InputTokens, OutputTokens: r.OutputTokens, CostUSD: r.CostUSD,
		StartedAt: chTime(r.Start), EndedAt: chTime(r.End), Outcome: r.Outcome, Sources: nonNil(r.Sources), Confidence: r.Confidence,
		Redacted: r.Redacted, StoredAt: chTime(storedAt), RecordSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// Insert copies records halo-server stored (POST /api/v1/sessions answers
// them) into the ClickHouse table. A record that does not validate is refused.
func Insert(ctx context.Context, ch *promote.ClickHouse, recs []Record, storedAt time.Time) error {
	if len(recs) == 0 {
		return nil
	}
	rows := make([]any, 0, len(recs))
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("ledger insert: session %s: %w", trunc(r.SessionID), err)
		}
		row, err := toRow(r, storedAt)
		if err != nil {
			return fmt.Errorf("ledger insert: %w", err)
		}
		rows = append(rows, row)
	}
	if err := ch.Insert(ctx, Table, rows); err != nil {
		return fmt.Errorf("ledger insert: %w", err)
	}
	return nil
}
