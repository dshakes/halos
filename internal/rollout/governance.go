package rollout

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Governance is the change-governance input to one decision (ADR-0030):
// halo-server's incident freeze and the approvals recorded for advancing the
// live step. The policy's freeze windows and approval rules come from org.
type Governance struct {
	Incident  *policy.ActiveFreeze `json:"incident,omitempty"` // nil = none
	Approvals []policy.Approval    `json:"approvals,omitempty"`
	// Requester proposes the advance ("" = the controller): their own
	// approval never counts.
	Requester string `json:"-"`
}

// stepRingList is the rings step s exposes: its ring, else every ring of the
// backing experiment.
func stepRingList(org *policy.Org, r *policy.Rollout, s policy.RolloutStep) []string {
	if s.Ring != "" {
		return []string{s.Ring}
	}
	if e := findExp(org, r.Experiment); e != nil {
		return e.Rings
	}
	return nil
}

// Target is what advancing r from live step from (-1 = not started)
// changes: the rings of the step it enters, or the last step's on completion.
func Target(org *policy.Org, r *policy.Rollout, from int) policy.ChangeTarget {
	if len(r.Steps) == 0 {
		return org.RingTarget()
	}
	i := min(max(from+1, 0), len(r.Steps)-1)
	return org.RingTarget(stepRingList(org, r, r.Steps[i])...)
}

// ApprovalKey names the approvals of advancing r from its live step: they
// never carry over to another step or another change. The change is the
// release digest, the alias, the backing experiment and the treatment's route
// for the alias in org, hashed: editing any of them after an approval
// invalidates it.
func ApprovalKey(org *policy.Org, r *policy.Rollout) string {
	// StepRings and ExpRings (ADR-0037 review) are what the approval was given
	// for: the rings the next step enters and the backing experiment's rings,
	// kept apart so moving a step between two of the experiment's rings is a
	// new key too. Retargeting either is a new change, so an approval, scoped
	// or not, stops counting everywhere the key is read (this server, older
	// replicas and every client that asks it for approvals).
	change := struct {
		Release, Alias, Experiment string
		Route                      *policy.ModelRoute `json:",omitempty"`
		StepRings, ExpRings        []string
	}{r.Change.Release, r.Change.Alias, r.Experiment, nil, sortedSet(Target(org, r, r.StepIndex(r.Step)).Rings), nil}
	if e := findExp(org, r.Experiment); e != nil {
		change.ExpRings = sortedSet(e.Rings)
		if _, t, ok := e.Arms(); ok {
			if rt, ok := t.Routes[r.Change.Alias]; ok {
				change.Route = &rt
			}
		}
	}
	b, _ := json.Marshal(change) // strings and a plain struct: cannot fail
	sum := sha256.Sum256(b)
	return r.Name + "/" + cmp.Or(r.Step, "-") + "/" + hex.EncodeToString(sum[:16])
}

// sortedSet is xs sorted, without repeats (a fresh slice).
func sortedSet(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return slices.Compact(out)
}

// Apply sets ev.Freeze and ev.Quorum for advancing r from st.Step at now. A
// recorded approval satisfies a plain approval gate when no rule covers it.
func (g Governance) Apply(org *policy.Org, r *policy.Rollout, st State, ev *Evidence, now time.Time) {
	t := Target(org, r, st.Step)
	fs := org.FreezeAt(now, t)
	if g.Incident != nil {
		fs.AddIncident(g.Incident.By, g.Incident.Reason)
	}
	if fs.Frozen {
		ev.Freeze = &fs
	}
	ticket := ""
	for _, a := range g.Approvals {
		if a.Ticket != "" {
			ticket = a.Ticket
			break
		}
	}
	res := TargetResource(org, r, st.Step)
	ev.Quorum = org.QuorumFor(&res, t, g.Requester, ticket, g.Approvals)
	// A scoped approval (ADR-0037) whose scope does not cover the step's
	// rings satisfies no plain approval gate either.
	// The requester's own approval satisfies nothing (separation of duties), as in a quorum.
	if ev.Quorum == nil && slices.ContainsFunc(g.Approvals, func(a policy.Approval) bool {
		return a.ScopeCovers(&res) && (g.Requester == "" || policy.CanonicalUser(a.By) != policy.CanonicalUser(g.Requester))
	}) {
		ev.Approved = true
	}
}

// TargetResource is what advancing r from live step from touches, for
// scoped authorization (ADR-0037): the rings of Target, every unit's members.
func TargetResource(org *policy.Org, r *policy.Rollout, from int) policy.Resource {
	return policy.RingResource(Target(org, r, from).Rings...)
}

// GovernanceBody is the PR-body section recording a decision's approvals and
// ticket ("" when no rule covered it).
func GovernanceBody(d Decision) string {
	q := d.Quorum
	if q == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("**Change governance (ADR-0030)**\n\n")
	if q.Ticket != "" {
		fmt.Fprintf(&b, "- Ticket: `%s`\n", q.Ticket)
	}
	for _, r := range q.Rules {
		fmt.Fprintf(&b, "- Rule `%s`: %d/%d approvals (%s)", r.Rule, r.Have, r.Need, strings.Join(r.Approvers, ", "))
		if !r.Met {
			b.WriteString(" **not met**")
		}
		b.WriteString("\n")
	}
	return b.String()
}
