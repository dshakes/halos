package cloudagents

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/ledger"
	"github.com/dshakes/halos/internal/policy"
)

// Kill scopes: what a kill fans out to.
const (
	ScopeUser       = "user"
	ScopeRing       = "ring"
	ScopeExperiment = "experiment"
)

// Groups returns a Halos user's groups (the SCIM directory on halo-server;
// nil in the CLI, where ring membership then comes from users, percent and
// default only).
type Groups func(user string) []string

func subject(user string, groups Groups) policy.Subject {
	s := policy.Subject{ID: user}
	if groups != nil {
		s.Groups = groups(user)
	}
	return s
}

// Select returns the active tasks a kill of scope/name reaches: tasks of the
// user, of every user the ring resolves, or of every user the experiment
// assigns a variant (internal/assign through policy, never reimplemented).
// unattributed counts active tasks with no Halos user, which no ring or
// experiment kill can reach.
func Select(org *policy.Org, tasks []Task, scope, name string, groups Groups) (hit []Task, unattributed int, err error) {
	var exp *policy.Experiment
	switch scope {
	case ScopeUser:
		if strings.TrimSpace(name) == "" {
			return nil, 0, fmt.Errorf("user is required")
		}
	case ScopeRing:
		if !slices.ContainsFunc(org.Rings, func(r *policy.Ring) bool { return r.Name == name }) {
			return nil, 0, fmt.Errorf("unknown ring %q", name)
		}
	case ScopeExperiment:
		i := slices.IndexFunc(org.Experiments, func(e *policy.Experiment) bool { return e.Name == name })
		if i < 0 {
			return nil, 0, fmt.Errorf("unknown experiment %q", name)
		}
		exp = org.Experiments[i]
	default:
		return nil, 0, fmt.Errorf("scope %q: want user, ring or experiment", scope)
	}
	for _, t := range tasks {
		if !t.Active() {
			continue
		}
		if t.User == "" {
			unattributed++
			continue
		}
		s := subject(t.User, groups)
		var ok bool
		switch scope {
		case ScopeUser:
			ok = policy.CanonicalUser(t.User) == policy.CanonicalUser(name)
		case ScopeRing:
			r := org.ResolveRing(s)
			ok = r != nil && r.Name == name
		case ScopeExperiment:
			if r := org.ResolveRing(s); r != nil {
				ok = exp.AssignVariant(s, r.Name) != nil
			}
		}
		if ok {
			hit = append(hit, t)
		}
	}
	return hit, unattributed, nil
}

// Alert kinds.
const (
	AlertDisabled     = "disabled"     // a task of a vendor policy disables
	AlertUngoverned   = "ungoverned"   // a task of a vendor policy does not list
	AlertUnmanaged    = "unmanaged"    // a run of a workflow Halos did not render
	AlertRepo         = "repo"         // a task in a repository not allowed
	AlertModel        = "model"        // a task on a model not allowed
	AlertUnattributed = "unattributed" // a task no identity maps to a Halos user
	AlertConcurrency  = "concurrency"  // more running tasks than maxConcurrent
	AlertBudget       = "budget"       // vendor-reported usage over a budget
)

// Alert is one policy violation or over-limit among tasks. Pause lists the
// tasks to pause when the vendor's onOverLimit is pause (empty otherwise, and
// for kinds that do not pause).
type Alert struct {
	Vendor  string   `json:"vendor"`
	Kind    string   `json:"kind"`
	Key     string   `json:"key,omitempty"` // user:<id>, group:<g>, org, the repo, the model
	Message string   `json:"message"`
	Value   int64    `json:"value,omitempty"`
	Limit   int64    `json:"limit,omitempty"`
	Tasks   []string `json:"tasks"`
	Pause   []string `json:"pause,omitempty"`
}

// Evaluate checks tasks against policy at now: per-task violations (any
// status), then concurrency (active tasks) and budgets (usage since each
// budget's window cutoff). Alerts are sorted for stable output.
func Evaluate(org *policy.Org, tasks []Task, groups Groups, now time.Time) []Alert {
	ca := org.CloudAgents
	if ca == nil {
		return nil
	}
	var out []Alert
	add := func(t Task, a *policy.CloudAgent, kind, key, msg string) {
		al := Alert{Vendor: t.Vendor, Kind: kind, Key: key, Message: msg, Tasks: []string{t.ID}}
		if a.Pauses() && t.Active() && kind != AlertUnattributed && kind != AlertModel {
			al.Pause = []string{t.ID}
		}
		out = append(out, al)
	}
	byVendor := map[string][]Task{}
	for _, t := range tasks {
		a := ca.Vendor(t.Vendor)
		switch {
		case a == nil:
			out = append(out, Alert{Vendor: t.Vendor, Kind: AlertUngoverned, Message: "cloudAgents has no " + t.Vendor + " section", Tasks: []string{t.ID}})
			continue
		case !a.Enabled:
			add(t, a, AlertDisabled, "", t.Vendor+" is disabled by policy")
		case !t.Managed:
			add(t, a, AlertUnmanaged, t.Workflow, "a workflow Halos did not render runs "+t.Vendor+"; replace it with `halo cloud-agents render` output")
		}
		if t.Repo != "" && !a.RepoAllowed(t.Repo) {
			add(t, a, AlertRepo, t.Repo, "repository "+t.Repo+" is not in cloudAgents."+t.Vendor+".repos")
		}
		if !a.ModelAllowed(t.Model) {
			add(t, a, AlertModel, t.Model, "model "+t.Model+" is not in cloudAgents."+t.Vendor+".models")
		}
		if t.User == "" && t.Active() {
			add(t, a, AlertUnattributed, t.VendorUser, "no cloudAgents.identities entry maps "+t.Vendor+" login "+orDash(t.VendorUser))
		}
		byVendor[t.Vendor] = append(byVendor[t.Vendor], t)
	}
	for _, v := range policy.CloudVendors {
		a := ca.Vendor(v)
		if a == nil {
			continue
		}
		out = append(out, concurrency(v, a, byVendor[v], groups)...)
		out = append(out, budgets(v, a, byVendor[v], groups, org, now)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// concurrency: newest tasks past the limit are the ones paused.
func concurrency(v string, a *policy.CloudAgent, tasks []Task, groups Groups) []Alert {
	mc := a.MaxConcurrent
	if mc.PerUser == 0 && mc.PerGroup == 0 {
		return nil
	}
	count := map[string][]Task{}
	for _, t := range tasks {
		if !t.Active() || t.User == "" {
			continue
		}
		if mc.PerUser > 0 {
			k := "user:" + policy.CanonicalUser(t.User)
			count[k] = append(count[k], t)
		}
		if mc.PerGroup > 0 && groups != nil {
			for _, g := range groups(t.User) {
				if slices.Contains(mc.Groups, g) {
					count["group:"+g] = append(count["group:"+g], t)
				}
			}
		}
	}
	var out []Alert
	for k, ts := range count {
		limit := mc.PerUser
		if strings.HasPrefix(k, "group:") {
			limit = mc.PerGroup
		}
		if len(ts) <= limit {
			continue
		}
		slices.SortFunc(ts, func(x, y Task) int { return cmp.Or(x.Start.Compare(y.Start), strings.Compare(x.ID, y.ID)) })
		al := Alert{Vendor: v, Kind: AlertConcurrency, Key: k, Value: int64(len(ts)), Limit: int64(limit),
			Message: fmt.Sprintf("%d running %s tasks for %s, limit %d", len(ts), v, k, limit)}
		for i, t := range ts {
			al.Tasks = append(al.Tasks, t.ID)
			if a.Pauses() && i >= limit {
				al.Pause = append(al.Pause, t.ID)
			}
		}
		out = append(out, al)
	}
	return out
}

// budgets reuse internal/budget's charge keys and windows; only tokens are
// counted (vendors report no cost).
func budgets(v string, a *policy.CloudAgent, tasks []Task, groups Groups, org *policy.Org, now time.Time) []Alert {
	if len(a.Budgets) == 0 {
		return nil
	}
	type acc struct {
		tokens int64
		tasks  []Task
	}
	spent := map[string]map[string]*acc{}
	for _, t := range tasks {
		if t.Tokens <= 0 || t.User == "" {
			continue
		}
		s := subject(t.User, groups)
		p := budget.Principal{Subject: t.User, Groups: s.Groups}
		if r := org.ResolveRing(s); r != nil {
			p.Ring = r.Name
		}
		for _, c := range budget.Charges(a.Budgets, p) {
			if t.Start.Before(budget.Cutoff(c.Budget, now)) {
				continue
			}
			if spent[c.Budget.Name] == nil {
				spent[c.Budget.Name] = map[string]*acc{}
			}
			x := spent[c.Budget.Name][c.Key]
			if x == nil {
				x = &acc{}
				spent[c.Budget.Name][c.Key] = x
			}
			x.tokens += t.Tokens
			x.tasks = append(x.tasks, t)
		}
	}
	var out []Alert
	for _, b := range a.Budgets {
		if b.LimitTokens <= 0 {
			continue
		}
		for k, x := range spent[b.Name] {
			if x.tokens < b.LimitTokens {
				continue
			}
			al := Alert{Vendor: v, Kind: AlertBudget, Key: b.Name + "/" + k, Value: x.tokens, Limit: b.LimitTokens,
				Message: fmt.Sprintf("budget %s: %s used %d of %d tokens", b.Name, k, x.tokens, b.LimitTokens)}
			for _, t := range x.tasks {
				al.Tasks = append(al.Tasks, t.ID)
				if a.Pauses() && t.Active() {
					al.Pause = append(al.Pause, t.ID)
				}
			}
			out = append(out, al)
		}
	}
	return out
}

// PauseTasks are the distinct tasks alerts ask to pause, in task order.
func PauseTasks(alerts []Alert, tasks []Task) []Task {
	want := map[string]bool{}
	for _, a := range alerts {
		for _, id := range a.Pause {
			want[id] = true
		}
	}
	var out []Task
	for _, t := range tasks {
		if want[t.ID] {
			out = append(out, t)
			delete(want, t.ID)
		}
	}
	return out
}

// Harness names cloud tasks get in the session ledger.
var ledgerHarness = map[string]string{
	policy.CloudClaude: "claude-code-action", policy.CloudGemini: "gemini-cli-action",
	policy.CloudCopilot: "copilot-cloud-agent", policy.CloudCursor: "cursor-cloud-agent", policy.CloudCodex: "codex-cloud",
}

// LedgerRecord is the session ledger record of a finished task (ADR-0031),
// normalized and redacted under the default policy (repositories counted,
// not kept). ok is false while the task runs or when it does not normalize.
func (t Task) LedgerRecord() (ledger.Record, bool) {
	if t.Active() || t.Start.IsZero() {
		return ledger.Record{}, false
	}
	outcome := map[string]string{StatusCompleted: ledger.OutcomeCompleted, StatusFailed: ledger.OutcomeError, StatusCancelled: ledger.OutcomeCancelled}[t.Status]
	r := ledger.Record{
		SessionID: t.ID, Harness: ledgerHarness[t.Vendor], Who: ledger.Who{VendorUser: t.VendorUser},
		Start: t.Start, End: t.End, Outcome: outcome, Sources: []string{ledger.SourceCloudAgents},
	}
	if t.Model != "" {
		r.Models = []string{t.Model}
	}
	if t.Repo != "" {
		r.Repos = []string{t.Repo}
	}
	recs, err := ledger.Normalize([]ledger.Record{r}, ledger.Redaction{})
	if err != nil || len(recs) != 1 {
		return ledger.Record{}, false
	}
	recs[0].Who.User = t.User // halo-server's attribution, from policy identities
	return recs[0], true
}
