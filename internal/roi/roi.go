// Package roi measures the delivery impact of a policy change (ADR-0027).
//
// It ingests pull-request outcomes (GitHub, or a generic CSV/JSONL export from
// any SCM or tracker), maps their authors to Halos subjects, recovers each
// developer's arm with the same assignment the fleet used (policy.ResolveRing
// and Experiment.AssignVariant, both on internal/assign), and estimates the
// difference between arms with a developer-clustered bootstrap. Only an
// experiment's variants are randomized; a comparison between rings is
// labelled observational and never reported as an effect.
package roi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// PR is one pull/merge request outcome. Titles, bodies and diffs are never
// stored: only what the estimators need.
type PR struct {
	Source string `json:"source"` // github | file
	Repo   string `json:"repo"`
	Number int64  `json:"number"`
	// Author is the SCM login, lowercased. Subject, when the source knows it
	// (a generic export), is the Halos subject id and wins over Author.
	Author  string `json:"author,omitempty"`
	Subject string `json:"subject,omitempty"`
	// Bot marks an author the SCM reports as a bot account; never counted.
	Bot          bool       `json:"bot,omitempty"`
	OpenedAt     time.Time  `json:"opened_at"`
	MergedAt     *time.Time `json:"merged_at,omitempty"`
	ReviewRounds int        `json:"review_rounds"`
	Additions    int        `json:"additions"`
	Deletions    int        `json:"deletions"`
	// ChangeFailure is the change-failure proxy: the merged PR was later
	// reverted or followed by a hotfix that references it.
	ChangeFailure bool `json:"change_failure,omitempty"`
}

func (p PR) key() string {
	return p.Source + "\x00" + strings.ToLower(p.Repo) + "\x00" + strconv.FormatInt(p.Number, 10)
}

// Check rejects a record the estimators cannot use.
func (p PR) Check() error {
	switch {
	case p.Repo == "" || p.Number <= 0:
		return fmt.Errorf("pr %s#%d: repo and a positive number are required", p.Repo, p.Number)
	case p.Author == "" && p.Subject == "":
		return fmt.Errorf("pr %s#%d: author or subject is required", p.Repo, p.Number)
	case p.OpenedAt.IsZero():
		return fmt.Errorf("pr %s#%d: opened_at is required", p.Repo, p.Number)
	case p.MergedAt != nil && p.MergedAt.Before(p.OpenedAt):
		return fmt.Errorf("pr %s#%d: merged_at is before opened_at", p.Repo, p.Number)
	case p.ReviewRounds < 0 || p.Additions < 0 || p.Deletions < 0:
		return fmt.Errorf("pr %s#%d: counts must be >= 0", p.Repo, p.Number)
	}
	return nil
}

// merged reports whether the PR merged before end.
func (p PR) merged(end time.Time) bool { return p.MergedAt != nil && p.MergedAt.Before(end) }

// Store holds ingested PRs. Put replaces records with the same (source, repo,
// number), so re-ingesting a window refreshes late reverts and merges.
type Store interface {
	Put(ctx context.Context, prs []PR) error
	// PRs returns the PRs opened in [from, to).
	PRs(ctx context.Context, from, to time.Time) ([]PR, error)
}

// ArmCost is one arm's AI spend over a window.
type ArmCost struct {
	USD   float64 `json:"usd"`
	Units int     `json:"units"`
}

// CostSource reports AI spend per arm (variant of experiment, or ring when
// experiment is "") and which receiver the rows came through.
type CostSource interface {
	ArmCosts(ctx context.Context, experiment string, rings []string, from, to time.Time) (map[string]ArmCost, string, error)
}

// FileStore is a JSONL file of PRs: the local mode for tests and for teams
// without ClickHouse.
type FileStore struct{ Path string }

func (f FileStore) read() ([]PR, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	prs, err := parseJSONL(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	return prs, nil
}

// Put merges prs into the file (atomic rename).
func (f FileStore) Put(_ context.Context, prs []PR) error {
	old, err := f.read()
	if err != nil {
		return err
	}
	idx := map[string]int{}
	for i, p := range old {
		idx[p.key()] = i
	}
	for _, p := range prs {
		if i, ok := idx[p.key()]; ok {
			old[i] = p
			continue
		}
		idx[p.key()] = len(old)
		old = append(old, p)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, p := range old {
		if err := enc.Encode(p); err != nil {
			return fmt.Errorf("roi store: encode %s#%d: %w", p.Repo, p.Number, err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".roi-*.jsonl")
	if err != nil {
		return fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after the rename
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return fmt.Errorf("roi store %s: %w", f.Path, err)
	}
	return nil
}

// PRs returns the PRs opened in [from, to).
func (f FileStore) PRs(_ context.Context, from, to time.Time) ([]PR, error) {
	all, err := f.read()
	if err != nil {
		return nil, err
	}
	var out []PR
	for _, p := range all {
		if !p.OpenedAt.Before(from) && p.OpenedAt.Before(to) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Table is the ClickHouse table `halo roi ingest` writes
// (deploy/observability/clickhouse/schema.sql).
const Table = "halo_delivery_prs"

// ClickHouseStore keeps PRs in halo_delivery_prs and reads AI spend from
// halo_metrics, through the same client `halo exp analyze` uses.
type ClickHouseStore struct{ CH *promote.ClickHouse }

type chRow struct {
	PR
	IngestedAt time.Time `json:"ingested_at"`
}

// Put inserts prs; ReplacingMergeTree(ingested_at) keeps the newest per key.
func (s ClickHouseStore) Put(ctx context.Context, prs []PR) error {
	now := time.Now().UTC()
	rows := make([]any, len(prs))
	for i, p := range prs {
		rows[i] = chRow{p, now}
	}
	return s.CH.Insert(ctx, Table, rows)
}

// PRs reads the latest version of each PR opened in [from, to).
func (s ClickHouseStore) PRs(ctx context.Context, from, to time.Time) ([]PR, error) {
	sql := "SELECT source, repo, toUInt32(number) AS number, author, subject, bot, " +
		"toFloat64(toUnixTimestamp64Milli(opened_at)) AS opened_ms, " +
		"if(merged_at IS NULL, 0., toFloat64(toUnixTimestamp64Milli(assumeNotNull(merged_at)))) AS merged_ms, " +
		"review_rounds, additions, deletions, change_failure FROM " + Table + " FINAL " +
		"WHERE opened_at >= fromUnixTimestamp64Milli({from:Int64}) AND opened_at < fromUnixTimestamp64Milli({to:Int64})"
	var out []PR
	err := s.CH.Query(ctx, sql, map[string]string{
		"from": strconv.FormatInt(from.UnixMilli(), 10), "to": strconv.FormatInt(to.UnixMilli(), 10),
	}, func(raw json.RawMessage) error {
		var r struct {
			PR
			OpenedMS float64 `json:"opened_ms"`
			MergedMS float64 `json:"merged_ms"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("decode %s row: %w", Table, err)
		}
		r.OpenedAt = time.UnixMilli(int64(r.OpenedMS)).UTC()
		if r.MergedMS > 0 {
			m := time.UnixMilli(int64(r.MergedMS)).UTC()
			r.MergedAt = &m
		}
		out = append(out, r.PR)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("roi: read %s: %w", Table, err)
	}
	return out, nil
}

// ArmCosts sums halo.cost.usd per arm. Rows the collector stamped on its
// authenticated gateway receiver win; otherwise the CLI-reported rows are
// used and labelled promote.SourceCLI (client-supplied).
func (s ClickHouseStore) ArmCosts(ctx context.Context, experiment string, rings []string, from, to time.Time) (map[string]ArmCost, string, error) {
	type agg struct{ gw, cli map[string]ArmCost }
	a := agg{map[string]ArmCost{}, map[string]ArmCost{}}
	run := func(arm, cond string, params map[string]string) error {
		params["from"], params["to"] = strconv.FormatInt(from.UnixMilli(), 10), strconv.FormatInt(to.UnixMilli(), 10)
		sql := "SELECT " + arm + " AS arm, attrs['halo.source'] = '" + promote.SourceGateway + "' AS gw, " +
			"toFloat64(sum(value)) AS usd, toUInt32(uniqExact(unit_id)) AS units FROM halo_metrics " +
			"WHERE metric = 'halo.cost.usd' AND unit_id != '' AND " + cond +
			" AND ts >= fromUnixTimestamp64Milli({from:Int64}) AND ts < fromUnixTimestamp64Milli({to:Int64}) GROUP BY arm, gw"
		return s.CH.Query(ctx, sql, params, func(raw json.RawMessage) error {
			var r struct {
				Arm   string  `json:"arm"`
				GW    any     `json:"gw"`
				USD   float64 `json:"usd"`
				Units int     `json:"units"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return fmt.Errorf("decode cost row: %w", err)
			}
			m := a.cli
			if r.GW == true || r.GW == float64(1) {
				m = a.gw
			}
			m[r.Arm] = ArmCost{USD: r.USD, Units: r.Units}
			return nil
		})
	}
	var err error
	if experiment != "" {
		err = run("variant", "experiment = {exp:String}", map[string]string{"exp": experiment})
	} else {
		for _, r := range rings {
			if err = run("ring", "ring = {ring:String}", map[string]string{"ring": r}); err != nil {
				break
			}
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("roi: cost from halo_metrics: %w", err)
	}
	if len(a.gw) > 0 {
		return a.gw, promote.SourceGateway, nil
	}
	if len(a.cli) > 0 {
		return a.cli, promote.SourceCLI, nil
	}
	return nil, "", nil
}

// Open picks the sources. PRs come from the JSONL file at path when set,
// else from ClickHouse; AI spend comes from ClickHouse's halo_metrics when ch
// is set (cost is nil otherwise).
func Open(ch *promote.ClickHouse, path string) (st Store, cost CostSource, err error) {
	if ch != nil {
		s := ClickHouseStore{CH: ch}
		st, cost = s, s
	}
	if path != "" {
		st = FileStore{Path: path}
	}
	if st == nil {
		return nil, nil, errors.New("roi: no store: pass --clickhouse URL or --store FILE.jsonl")
	}
	return st, cost, nil
}

// Window resolves a report window from since/until (ParseTime). until
// defaults to now; since defaults to e's first telemetry in ClickHouse, so it
// is required without an experiment or ch.
func Window(ctx context.Context, ch *promote.ClickHouse, e *policy.Experiment, since, until string, now time.Time) (from, to time.Time, err error) {
	if from, err = ParseTime(since); err != nil {
		return from, to, fmt.Errorf("since: %w", err)
	}
	if to, err = ParseTime(until); err != nil {
		return from, to, fmt.Errorf("until: %w", err)
	}
	if to.IsZero() {
		to = now.UTC()
	}
	if !from.IsZero() {
		return from, to, nil
	}
	if e == nil || ch == nil {
		return from, to, errors.New("since is required (it defaults to the experiment's first telemetry only with an experiment and ClickHouse)")
	}
	w, err := ch.Window(ctx, e.Name)
	if err != nil {
		return from, to, err
	}
	if w.Start.IsZero() {
		return from, to, fmt.Errorf("no telemetry for experiment %s in ClickHouse; give since", e.Name)
	}
	return w.Start, to, nil
}

// ReadFile parses a generic export: .csv (header row naming the PR JSON
// fields) or .jsonl/.ndjson (one PR object per line). Every record is
// checked; Source defaults to "file" and logins are lowercased.
func ReadFile(path string) ([]PR, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied input path
	if err != nil {
		return nil, fmt.Errorf("roi: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	var prs []PR
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		prs, err = parseCSV(f)
	case ".jsonl", ".ndjson":
		prs, err = parseJSONL(f)
	default:
		return nil, fmt.Errorf("roi: %s: want a .csv, .jsonl or .ndjson file", path)
	}
	if err != nil {
		return nil, fmt.Errorf("roi: %s: %w", path, err)
	}
	for i := range prs {
		if prs[i].Source == "" {
			prs[i].Source = "file"
		}
		prs[i].Author = strings.ToLower(strings.TrimSpace(prs[i].Author))
		if err := prs[i].Check(); err != nil {
			return nil, fmt.Errorf("roi: %s: %w", path, err)
		}
	}
	return prs, nil
}

func parseJSONL(r io.Reader) ([]PR, error) {
	var out []PR
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var p PR
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var csvColumns = []string{"source", "repo", "number", "author", "subject", "bot", "opened_at", "merged_at", "review_rounds", "additions", "deletions", "change_failure"}

func parseCSV(r io.Reader) ([]PR, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range head {
		h = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(csvColumns, h) {
			return nil, fmt.Errorf("unknown column %q (have: %s)", h, strings.Join(csvColumns, ", "))
		}
		col[h] = i
	}
	var out []PR
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		get := func(k string) string {
			if i, ok := col[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		var p PR
		var errs []error
		num := func(k string) int64 {
			v := get(k)
			if v == "" {
				return 0
			}
			n, err := strconv.ParseInt(v, 10, 64)
			errs = append(errs, err)
			return n
		}
		flag := func(k string) bool {
			v := get(k)
			if v == "" {
				return false
			}
			b, err := strconv.ParseBool(v)
			errs = append(errs, err)
			return b
		}
		p.Source, p.Repo, p.Author, p.Subject = get("source"), get("repo"), get("author"), get("subject")
		p.Number = num("number")
		p.ReviewRounds, p.Additions, p.Deletions = int(num("review_rounds")), int(num("additions")), int(num("deletions"))
		p.Bot, p.ChangeFailure = flag("bot"), flag("change_failure")
		if p.OpenedAt, err = ParseTime(get("opened_at")); err != nil {
			errs = append(errs, err)
		}
		if v := get("merged_at"); v != "" {
			m, err := ParseTime(v)
			errs = append(errs, err)
			p.MergedAt = &m
		}
		if err := errors.Join(errs...); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, p)
	}
}

// ParseTime accepts RFC 3339 or a date (YYYY-MM-DD, UTC midnight).
func ParseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q: want RFC 3339 or YYYY-MM-DD", s)
	}
	return t, nil
}

// Identities is the roster: SCM logins mapped to Halos subjects with the IdP
// groups ring membership uses. Developers missing from it are unmapped and
// never guessed.
type Identities struct {
	byLogin   map[string]policy.Subject
	bySubject map[string]policy.Subject
	subjects  []policy.Subject // roster order, unique
}

// LoadIdentities reads a CSV with a header: login,subject[,groups][,kind].
// groups are separated by ';'. kind "workload" marks a CI or bot identity,
// which is excluded. Logins compare case-insensitively; subjects are
// canonicalised with policy.CanonicalUser.
func LoadIdentities(path string) (*Identities, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied input path
	if err != nil {
		return nil, fmt.Errorf("roi identities: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	ids, err := ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("roi identities %s: %w", path, err)
	}
	return ids, nil
}

// ParseIdentities is LoadIdentities on a reader.
func ParseIdentities(r io.Reader) (*Identities, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range head {
		h = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains([]string{"login", "subject", "groups", "kind"}, h) {
			return nil, fmt.Errorf("unknown column %q (want login,subject[,groups][,kind])", h)
		}
		col[h] = i
	}
	if _, ok := col["subject"]; !ok {
		return nil, errors.New("header needs a subject column")
	}
	ids := &Identities{byLogin: map[string]policy.Subject{}, bySubject: map[string]policy.Subject{}}
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return ids, nil
		}
		if err != nil {
			return nil, err
		}
		get := func(k string) string {
			if i, ok := col[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		s := policy.Subject{ID: policy.CanonicalUser(get("subject"))}
		if s.ID == "" {
			return nil, fmt.Errorf("line %d: subject is empty", line)
		}
		switch k := get("kind"); k {
		case "", "human":
		case policy.SubjectWorkload:
			s.Kind = k
		default:
			return nil, fmt.Errorf("line %d: kind %q: want human or %s", line, k, policy.SubjectWorkload)
		}
		for g := range strings.SplitSeq(get("groups"), ";") {
			if g = strings.TrimSpace(g); g != "" {
				s.Groups = append(s.Groups, g)
			}
		}
		if prev, ok := ids.bySubject[s.ID]; ok {
			if !slices.Equal(prev.Groups, s.Groups) || prev.Kind != s.Kind {
				return nil, fmt.Errorf("line %d: subject %s listed again with different groups or kind", line, s.ID)
			}
		} else {
			ids.bySubject[s.ID] = s
			ids.subjects = append(ids.subjects, s)
		}
		if login := strings.ToLower(get("login")); login != "" {
			if prev, ok := ids.byLogin[login]; ok && prev.ID != s.ID {
				return nil, fmt.Errorf("line %d: login %s maps to both %s and %s", line, login, prev.ID, s.ID)
			}
			ids.byLogin[login] = s
		}
	}
}

// Resolve maps a PR's author to a subject: its Subject when set, else its
// login. ok is false when the identity is not on the roster.
func (ids *Identities) Resolve(p PR) (policy.Subject, bool) {
	if p.Subject != "" {
		s, ok := ids.bySubject[policy.CanonicalUser(p.Subject)]
		return s, ok
	}
	s, ok := ids.byLogin[strings.ToLower(strings.TrimSpace(p.Author))]
	return s, ok
}

// Subjects is the roster in file order.
func (ids *Identities) Subjects() []policy.Subject { return ids.subjects }
