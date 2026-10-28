// Package ledger is the agent session ledger (ADR-0031): one normalized,
// identity-linked record per agent session, built from several evidence
// sources (halo-proxy spans, Claude Code OTel events, the Anthropic Compliance
// API, the GitHub enterprise audit log, a JSONL import).
//
// A record holds identifiers, counts and timestamps only. Every string field
// must match a token pattern with no whitespace, so prose (a prompt, a tool
// input, an error message) cannot be stored in any field; file paths and
// repositories are dropped or salted-hashed by the redaction policy before a
// record leaves Normalize. Validate re-checks all of it on the server, which
// refuses the whole batch on the first violation (fail closed).
package ledger

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Evidence sources.
const (
	SourceGateway   = "gateway"   // halo-proxy GenAI spans (authenticated collector receiver)
	SourceOTel      = "otel"      // Claude Code OTel log events (client-reachable receiver)
	SourceAnthropic = "anthropic" // Anthropic Compliance API activities
	SourceGitHub    = "github"    // GitHub enterprise audit log
	SourceJSONL     = "jsonl"     // operator-supplied import
)

// Confidence is the trust of the best evidence behind a record.
const (
	High   = "high"   // server-side or vendor-authenticated evidence
	Medium = "medium" // client-reported telemetry
	Low    = "low"    // operator import of unknown provenance
)

// Outcomes.
const (
	OutcomeCompleted = "completed"
	OutcomeError     = "error"
	OutcomeCancelled = "cancelled"
	OutcomeUnknown   = "unknown"
)

// sourceRank orders sources by trust: a merge fills each field from the most
// trusted source that has it. Confidence follows the same order.
var sourceRank = map[string]int{SourceGateway: 0, SourceAnthropic: 1, SourceGitHub: 2, SourceOTel: 3, SourceJSONL: 4}

var sourceConfidence = map[string]string{SourceGateway: High, SourceAnthropic: High, SourceGitHub: High, SourceOTel: Medium, SourceJSONL: Low}

// Who is the session's principal.
type Who struct {
	// User is the Halos identity (the SCIM userName). Only halo-server sets it,
	// from its directory; a value sent by a client is discarded (Join).
	User string `json:"user,omitempty"`
	// VendorUser is the identity the source reported: an email, a GitHub login,
	// an Anthropic account id.
	VendorUser string `json:"vendorUser,omitempty"`
	// Unit is halo-proxy's halo.unit pseudonym (a salted hash of the verified
	// subject) when that is all the evidence carries.
	Unit string `json:"unit,omitempty"`
	// Agents is the delegated agent chain, root side first (ADR-0024).
	Agents []string `json:"agents,omitempty"`
}

// Record is one agent session.
type Record struct {
	ID             string   `json:"id"` // IDFor(Harness, SessionID)
	SessionID      string   `json:"sessionId"`
	Who            Who      `json:"who"`
	Harness        string   `json:"harness"`
	HarnessVersion string   `json:"harnessVersion,omitempty"`
	Release        string   `json:"release,omitempty"`
	Ring           string   `json:"ring,omitempty"`
	Experiment     string   `json:"experiment,omitempty"`
	Variant        string   `json:"variant,omitempty"`
	Models         []string `json:"models,omitempty"`
	MCPServers     []string `json:"mcpServers,omitempty"`
	Tools          []string `json:"tools,omitempty"`
	Repos          []string `json:"repos,omitempty"` // "h:<hex>" once redacted
	Files          []string `json:"files,omitempty"` // "h:<hex>" once redacted
	FilesTouched   int      `json:"filesTouched,omitempty"`
	// DLPSecrets and DLPInjections count the gateway's DLP findings in the
	// session (ADR-0033): secrets and prompt-injection signals, never content.
	DLPSecrets    int64     `json:"dlpSecrets,omitempty"`
	DLPInjections int64     `json:"dlpInjections,omitempty"`
	InputTokens   int64     `json:"inputTokens,omitempty"`
	OutputTokens  int64     `json:"outputTokens,omitempty"`
	CostUSD       float64   `json:"costUsd,omitempty"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end,omitzero"`
	Outcome       string    `json:"outcome"`
	Sources       []string  `json:"sources"`
	Confidence    string    `json:"confidence"`
	// Redacted counts values the redaction policy withheld (paths dropped,
	// identifiers that were not tokens).
	Redacted int `json:"redacted,omitempty"`
}

// IDFor is the ledger id of a harness session: stable across sources and
// imports, opaque and URL-safe.
func IDFor(harness, sessionID string) string {
	h := sha256.Sum256([]byte(harness + "\x00" + sessionID))
	return hex.EncodeToString(h[:12])
}

// Limits keep one record well under the audit chain's 1 MiB line cap.
const (
	maxList  = 256
	maxToken = 256
)

// tokenRE is every string a record may hold: no whitespace, no control
// characters, no quotes, so no field can carry prose.
var (
	tokenRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+@:/=>#~-]*$`)
	hashedRE = regexp.MustCompile(`^h:[0-9a-f]{32}$`)
)

func token(s string) bool { return len(s) <= maxToken && tokenRE.MatchString(s) }

// Redaction is the path policy. Prompt text has no policy: no field can hold it.
type Redaction struct {
	// Paths is "drop" (the default: files and repos are counted, not kept) or
	// "hash" (HMAC-SHA256 with Salt, truncated; equal paths stay comparable
	// within one salt).
	Paths string
	Salt  []byte
}

// Redaction modes.
const (
	PathsDrop = "drop"
	PathsHash = "hash"
)

func (p Redaction) check() error {
	switch p.Paths {
	case "", PathsDrop:
		return nil
	case PathsHash:
		if len(p.Salt) < 16 {
			return errors.New("redaction: hash needs a salt of at least 16 bytes")
		}
		return nil
	}
	return fmt.Errorf("redaction: unknown paths mode %q (want drop or hash)", p.Paths)
}

func (p Redaction) hash(s string) string {
	m := hmac.New(sha256.New, p.Salt)
	m.Write([]byte(s))
	return "h:" + hex.EncodeToString(m.Sum(nil)[:16])
}

// redact applies p to r and drops every identifier that is not a token.
func (p Redaction) redact(r *Record) {
	paths := func(in []string) []string {
		var out []string
		for _, v := range in {
			if p.Paths == PathsHash && v != "" {
				out = append(out, p.hash(v))
			} else {
				r.Redacted++
			}
		}
		return out
	}
	r.FilesTouched = max(r.FilesTouched, len(r.Files))
	r.Files, r.Repos = paths(r.Files), paths(r.Repos)
	for _, f := range []*string{&r.Who.User, &r.Who.VendorUser, &r.Who.Unit, &r.HarnessVersion, &r.Release, &r.Ring, &r.Experiment, &r.Variant} {
		if *f != "" && !token(*f) {
			*f = ""
			r.Redacted++
		}
	}
	for _, l := range []*[]string{&r.Who.Agents, &r.Models, &r.MCPServers, &r.Tools} {
		n := len(*l)
		*l = slices.DeleteFunc(*l, func(s string) bool { return !token(s) })
		r.Redacted += n - len(*l)
	}
}

// Validate is the fail-closed check every stored record passes.
func (r *Record) Validate() error {
	switch {
	case !token(r.SessionID):
		return fmt.Errorf("session id %q is not a token", trunc(r.SessionID))
	case !token(r.Harness):
		return fmt.Errorf("harness %q is not a token", trunc(r.Harness))
	case r.ID != IDFor(r.Harness, r.SessionID):
		return fmt.Errorf("id %q does not match harness and session id", trunc(r.ID))
	case r.Start.IsZero():
		return errors.New("start is required")
	case !r.End.IsZero() && r.End.Before(r.Start):
		return errors.New("end is before start")
	case r.InputTokens < 0 || r.OutputTokens < 0 || r.CostUSD < 0 || r.FilesTouched < 0 || r.Redacted < 0 || r.DLPSecrets < 0 || r.DLPInjections < 0:
		return errors.New("negative count")
	case !slices.Contains([]string{OutcomeCompleted, OutcomeError, OutcomeCancelled, OutcomeUnknown}, r.Outcome):
		return fmt.Errorf("outcome %q (want completed, error, cancelled or unknown)", trunc(r.Outcome))
	case !slices.Contains([]string{High, Medium, Low}, r.Confidence):
		return fmt.Errorf("confidence %q (want high, medium or low)", trunc(r.Confidence))
	case len(r.Sources) == 0:
		return errors.New("no evidence source")
	}
	for _, s := range r.Sources {
		if _, ok := sourceRank[s]; !ok {
			return fmt.Errorf("unknown source %q", trunc(s))
		}
	}
	for name, v := range map[string]string{"who.user": r.Who.User, "who.vendorUser": r.Who.VendorUser, "who.unit": r.Who.Unit,
		"harnessVersion": r.HarnessVersion, "release": r.Release, "ring": r.Ring, "experiment": r.Experiment, "variant": r.Variant} {
		if v != "" && !token(v) {
			return fmt.Errorf("%s is not a token (prose is never stored)", name)
		}
	}
	for name, l := range map[string][]string{"who.agents": r.Who.Agents, "models": r.Models, "mcpServers": r.MCPServers, "tools": r.Tools} {
		if len(l) > maxList {
			return fmt.Errorf("%s: more than %d entries", name, maxList)
		}
		for _, v := range l {
			if !token(v) {
				return fmt.Errorf("%s has a value that is not a token (prose is never stored)", name)
			}
		}
	}
	for name, l := range map[string][]string{"files": r.Files, "repos": r.Repos} {
		if len(l) > maxList {
			return fmt.Errorf("%s: more than %d entries", name, maxList)
		}
		for _, v := range l {
			if !hashedRE.MatchString(v) {
				return fmt.Errorf("%s holds an unredacted value: paths are stored hashed (h:<hex>) or not at all", name)
			}
		}
	}
	return nil
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// Normalize merges records of the same session (by ID), applies the
// redaction policy and validates. Any invalid record fails the whole call, so
// nothing unredacted is ever printed, sent or stored. Records without an ID
// get IDFor(Harness, SessionID).
func Normalize(recs []Record, p Redaction) ([]Record, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	merged := map[string]*Record{}
	var order []string
	for _, r := range recs {
		r.ID, r.Who.User = IDFor(r.Harness, r.SessionID), "" // only halo-server sets who.user (Join)
		if r.Outcome == "" {
			r.Outcome = OutcomeUnknown
		}
		if m := merged[r.ID]; m != nil {
			merge(m, r)
			continue
		}
		r := r
		merged[r.ID] = &r
		order = append(order, r.ID)
	}
	out := make([]Record, 0, len(order))
	for _, id := range order {
		r := merged[id]
		for _, l := range []*[]string{&r.Models, &r.MCPServers, &r.Tools, &r.Repos, &r.Files} {
			*l = limitList(*l)
		}
		p.redact(r)
		slices.Sort(r.Sources)
		r.Sources = slices.Compact(r.Sources)
		r.Confidence = confidence(r.Sources)
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("session %s (%s): %w", trunc(r.SessionID), r.Harness, err)
		}
		out = append(out, *r)
	}
	return out, nil
}

// limitList de-duplicates, sorts and caps a list (the cap is counted in
// Validate's terms: no more than maxList entries).
func limitList(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	l = slices.Clone(l)
	slices.Sort(l)
	l = slices.Compact(l)
	return l[:min(len(l), maxList)]
}

func confidence(sources []string) string {
	best := Low
	for _, s := range sources {
		if c := sourceConfidence[s]; c == High || (c == Medium && best == Low) {
			best = c
		}
	}
	return best
}

// merge folds b into a. Scalars come from the more trusted source, lists are
// unioned, counters take the larger reading (two sources measuring the same
// session must not double count), the span widens to cover both.
func merge(a *Record, b Record) {
	if rank(b.Sources) < rank(a.Sources) {
		a.Who.VendorUser, a.Who.Unit = cmp.Or(b.Who.VendorUser, a.Who.VendorUser), cmp.Or(b.Who.Unit, a.Who.Unit)
		a.HarnessVersion, a.Release, a.Ring = cmp.Or(b.HarnessVersion, a.HarnessVersion), cmp.Or(b.Release, a.Release), cmp.Or(b.Ring, a.Ring)
		a.Experiment, a.Variant = cmp.Or(b.Experiment, a.Experiment), cmp.Or(b.Variant, a.Variant)
		if b.Outcome != "" && b.Outcome != OutcomeUnknown {
			a.Outcome = b.Outcome
		}
	} else {
		a.Who.VendorUser, a.Who.Unit = cmp.Or(a.Who.VendorUser, b.Who.VendorUser), cmp.Or(a.Who.Unit, b.Who.Unit)
		a.HarnessVersion, a.Release, a.Ring = cmp.Or(a.HarnessVersion, b.HarnessVersion), cmp.Or(a.Release, b.Release), cmp.Or(a.Ring, b.Ring)
		a.Experiment, a.Variant = cmp.Or(a.Experiment, b.Experiment), cmp.Or(a.Variant, b.Variant)
		if a.Outcome == OutcomeUnknown {
			a.Outcome = cmp.Or(b.Outcome, OutcomeUnknown)
		}
	}
	if len(a.Who.Agents) == 0 {
		a.Who.Agents = b.Who.Agents
	}
	a.Models = append(a.Models, b.Models...)
	a.MCPServers = append(a.MCPServers, b.MCPServers...)
	a.Tools = append(a.Tools, b.Tools...)
	a.Repos = append(a.Repos, b.Repos...)
	a.Files = append(a.Files, b.Files...)
	a.FilesTouched = max(a.FilesTouched, b.FilesTouched)
	a.DLPSecrets, a.DLPInjections = max(a.DLPSecrets, b.DLPSecrets), max(a.DLPInjections, b.DLPInjections)
	a.InputTokens, a.OutputTokens, a.CostUSD = max(a.InputTokens, b.InputTokens), max(a.OutputTokens, b.OutputTokens), max(a.CostUSD, b.CostUSD)
	if a.Start.IsZero() || (!b.Start.IsZero() && b.Start.Before(a.Start)) {
		a.Start = b.Start
	}
	if b.End.After(a.End) {
		a.End = b.End
	}
	a.Sources = append(a.Sources, b.Sources...)
}

func rank(sources []string) int {
	best := len(sourceRank)
	for _, s := range sources {
		if r, ok := sourceRank[s]; ok && r < best {
			best = r
		}
	}
	return best
}

// Join sets Who.User from the identity directory, keyed by the identity the
// source reported. A Who.User the caller supplied is discarded first: the
// Halos identity on a stored record only ever comes from the directory.
func Join(recs []Record, lookup func(vendorUser string) (user string, ok bool)) {
	for i := range recs {
		r := &recs[i]
		r.Who.User = ""
		if r.Who.VendorUser == "" || lookup == nil {
			continue
		}
		if u, ok := lookup(r.Who.VendorUser); ok && token(u) {
			r.Who.User = u
		}
	}
}

// Filter selects records for list and export. Zero fields match everything.
type Filter struct {
	User, Harness, Ring, Tool string
	Since, Until              time.Time // on Start: Since inclusive, Until exclusive
}

// Match reports whether r passes f. User matches the Halos identity or, when
// the session is unresolved, the vendor identity.
func (f Filter) Match(r *Record) bool {
	return (f.User == "" || strings.EqualFold(f.User, r.Who.User) || (r.Who.User == "" && strings.EqualFold(f.User, r.Who.VendorUser))) &&
		(f.Harness == "" || f.Harness == r.Harness) &&
		(f.Ring == "" || f.Ring == r.Ring) &&
		(f.Tool == "" || slices.Contains(r.Tools, f.Tool) || slices.Contains(r.MCPServers, f.Tool)) &&
		(f.Since.IsZero() || !r.Start.Before(f.Since)) &&
		(f.Until.IsZero() || r.Start.Before(f.Until))
}

// Stored is a record as halo-server keeps it: the audit chain entry holding
// it is the tamper evidence (ADR-0016's chain, exported to SIEM).
type Stored struct {
	Record
	AuditSeq  uint64 `json:"auditSeq"`
	AuditHash string `json:"auditHash"`
}
