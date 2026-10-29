package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// Change governance (ADR-0030): the incident freeze and recorded approvals of
// rollout steps. Freeze windows and approval rules live in policy.

// approvalLog holds rollout-step approvals, keyed by rollout.ApprovalKey: an
// append-only log (approvals.jsonl, or the shared backend) replayed into memory.
// ponytail: no compaction; approvals are human-scale.
type approvalLog struct {
	mu    sync.Mutex
	byKey map[string][]policy.Approval
	log   storage.Log
}

type approvalRecord struct {
	Key string `json:"key"`
	policy.Approval
}

func openApprovalLog(o storage.Opener) (*approvalLog, error) {
	l := &approvalLog{byKey: map[string][]policy.Approval{}}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, "approvals", func(line []byte) {
		var r approvalRecord
		if json.Unmarshal(line, &r) == nil && r.Key != "" && r.By != "" { // torn line: skip
			l.byKey[r.Key] = append(l.byKey[r.Key], r.Approval)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	l.log = log
	return l, nil
}

func (l *approvalLog) close() error { return storage.CloseLog(&l.mu, l.log) }

// get returns key's approvals after catching up with other replicas.
func (l *approvalLog) get(key string) ([]policy.Approval, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.catchup(); err != nil {
		return nil, err
	}
	return slices.Clone(l.byKey[key]), nil
}

func (l *approvalLog) catchup() error {
	if l.log == nil {
		return nil
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return l.log.Catchup(ctx)
}

// add records a; false when a.By already approved key.
func (l *approvalLog) add(key string, a policy.Approval) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.catchup(); err != nil {
		return false, err
	}
	if slices.ContainsFunc(l.byKey[key], func(x policy.Approval) bool { return sameUser(x.By, a.By) }) {
		return false, nil
	}
	if l.log != nil {
		b, err := json.Marshal(approvalRecord{Key: key, Approval: a})
		if err != nil {
			return false, err
		}
		ctx, cancel := storage.Ctx()
		defer cancel()
		if err := l.log.Append(ctx, "", b); err != nil {
			return false, err
		}
	}
	l.byKey[key] = append(l.byKey[key], a)
	return true, nil
}

// approverGroups is the rules' approver groups p holds; an error names the
// rules when p holds none of them.
func approverGroups(rules []policy.ApprovalRule, p Principal) ([]string, error) {
	var held, names []string
	for _, r := range rules {
		names = append(names, fmt.Sprintf("%s (%s)", r.Name, strings.Join(r.Groups, ", ")))
		for _, g := range r.Groups {
			if slices.Contains(p.Groups, g) && !slices.Contains(held, g) {
				held = append(held, g)
			}
		}
	}
	if len(held) == 0 {
		return nil, fmt.Errorf("you hold none of the approver groups of %s", strings.Join(names, "; "))
	}
	return held, nil
}

// IncidentFreeze returns the incident freeze, or nil when none is set.
func (s *Server) IncidentFreeze() (*policy.ActiveFreeze, error) {
	rec, err := s.kills.Incident()
	if err != nil || rec == nil {
		return nil, err
	}
	return &policy.ActiveFreeze{Name: policy.IncidentFreezeName, Reason: rec.Reason, By: rec.By, Incident: true}, nil
}

// RolloutGovernance is controller.Controller.Governance for this server: the
// incident freeze and the approvals recorded for r's live step.
func (s *Server) RolloutGovernance(_ context.Context, org *policy.Org, r *policy.Rollout) (rollout.Governance, error) {
	inc, err := s.IncidentFreeze()
	if err != nil {
		return rollout.Governance{}, fmt.Errorf("incident freeze: %w", err)
	}
	as, err := s.approvals.get(rollout.ApprovalKey(org, r))
	if err != nil {
		return rollout.Governance{}, fmt.Errorf("rollout %s approvals: %w", r.Name, err)
	}
	return rollout.Governance{Incident: inc, Approvals: as}, nil
}

// FreezeView is GET /api/v1/freeze.
type FreezeView struct {
	Incident *policy.ActiveFreeze           `json:"incident"`
	Rings    map[string]policy.FreezeStatus `json:"rings"`
}

func (s *Server) getFreeze(w http.ResponseWriter, _ *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return
	}
	inc, err := s.IncidentFreeze()
	if err != nil {
		s.cfg.Log.Error("read incident freeze", "err", err)
		apiErr(w, http.StatusInternalServerError, "freeze state unreadable")
		return
	}
	v := FreezeView{Incident: inc, Rings: map[string]policy.FreezeStatus{}}
	now := s.cfg.Now()
	for _, r := range org.Rings {
		st := org.FreezeAt(now, org.RingTarget(r.Name))
		if inc != nil {
			st.AddIncident(inc.By, inc.Reason)
		}
		v.Rings[r.Name] = st
	}
	writeJSON(w, http.StatusOK, v)
}

// postFreeze (admin): POST /api/v1/freeze {"frozen": true|false, "reason": "..."}
// sets or lifts the incident freeze. Rollbacks and the kill switch are never
// frozen. Audit-strict: a freeze whose record fails stays set (fail safe); a
// lift whose record fails is reverted.
func (s *Server) postFreeze(w http.ResponseWriter, r *http.Request, p Principal) {
	var in struct {
		Frozen *bool  `json:"frozen"`
		Reason string `json:"reason"`
	}
	if err := decodeBody(w, r, 2048, &in); err != nil || in.Frozen == nil {
		apiErr(w, http.StatusBadRequest, `want {"frozen": true|false, "reason": "..."}`)
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 500 {
		apiErr(w, http.StatusUnprocessableEntity, "reason is required (<=500 chars)")
		return
	}
	set, action := s.kills.Unfreeze, "freeze.off"
	if *in.Frozen {
		set, action = s.kills.Freeze, "freeze.on"
	}
	changed, err := set(r.Context(), p.ID, in.Reason)
	if err != nil {
		s.cfg.Log.Error("incident freeze update failed", "frozen", *in.Frozen, "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if changed {
		if err := s.AuditStrict(r.Context(), p.ID, action, policy.IncidentFreezeName, map[string]string{"reason": in.Reason}); err != nil {
			if !*in.Frozen { // an unrecorded lift must not stay in force
				if _, rerr := s.kills.Freeze(r.Context(), p.ID, "audit failure: lift reverted"); rerr != nil {
					s.cfg.Log.Error("revert freeze lift after audit failure", "err", rerr)
				}
			}
			apiErr(w, http.StatusInternalServerError, errAuditFailed)
			return
		}
		s.cfg.Log.Warn("incident freeze changed", "frozen", *in.Frozen, "by", p.ID, "reason", in.Reason)
	}
	writeJSON(w, http.StatusOK, map[string]any{"frozen": *in.Frozen, "changed": changed})
}

// RolloutApprovals is GET /api/v1/rollouts/{name}/approvals and the answer to
// an approval: the live step's approvals and what they add up to.
type RolloutApprovals struct {
	Rollout   string               `json:"rollout"`
	Step      string               `json:"step"`
	Target    policy.ChangeTarget  `json:"target"`
	Approvals []policy.Approval    `json:"approvals"`
	Quorum    *policy.QuorumResult `json:"quorum,omitempty"` // nil = no rule covers the next step
	Freeze    policy.FreezeStatus  `json:"freeze"`
}

func (s *Server) rolloutApprovals(org *policy.Org, ro *policy.Rollout) (RolloutApprovals, error) {
	as, err := s.approvals.get(rollout.ApprovalKey(org, ro))
	if err != nil {
		return RolloutApprovals{}, err
	}
	inc, err := s.IncidentFreeze()
	if err != nil {
		return RolloutApprovals{}, err
	}
	t := rollout.Target(org, ro, ro.StepIndex(ro.Step))
	ticket := ""
	for _, a := range as {
		if a.Ticket != "" {
			ticket = a.Ticket
			break
		}
	}
	out := RolloutApprovals{Rollout: ro.Name, Step: ro.Step, Target: t, Approvals: as, Quorum: org.Quorum(t, "", ticket, as), Freeze: org.FreezeAt(s.cfg.Now(), t)}
	if out.Approvals == nil {
		out.Approvals = []policy.Approval{}
	}
	if inc != nil {
		out.Freeze.AddIncident(inc.By, inc.Reason)
	}
	return out, nil
}

func (s *Server) findRollout(w http.ResponseWriter, name string) (*policy.Org, *policy.Rollout) {
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return nil, nil
	}
	for _, ro := range org.Rollouts {
		if ro.Name == name {
			return org, ro
		}
	}
	apiErr(w, http.StatusNotFound, "rollout not found")
	return nil, nil
}

func (s *Server) getRolloutApprovals(w http.ResponseWriter, r *http.Request, _ Principal) {
	org, ro := s.findRollout(w, r.PathValue("name"))
	if ro == nil {
		return
	}
	out, err := s.rolloutApprovals(org, ro)
	if err != nil {
		s.cfg.Log.Error("read rollout approvals", "rollout", ro.Name, "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// postRolloutApprove (approve): POST /api/v1/rollouts/{name}/approve
// {"ticket": "CHG0012345"} approves advancing the rollout from its live step.
// When an approval rule covers the next step, the approver must hold one of
// its groups. Audit-strict: no record, no approval.
func (s *Server) postRolloutApprove(w http.ResponseWriter, r *http.Request, p Principal) {
	var in struct {
		Ticket string `json:"ticket"`
	}
	if err := decodeBody(w, r, 1024, &in); err != nil && !errors.Is(err, io.EOF) {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Ticket = strings.TrimSpace(in.Ticket); in.Ticket != "" {
		if err := policy.ValidTicket(in.Ticket); err != nil {
			apiErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	org, ro := s.findRollout(w, r.PathValue("name"))
	if ro == nil {
		return
	}
	if st := ro.EffectiveStatus(); st == policy.RolloutAborted || st == policy.RolloutCompleted {
		apiErr(w, http.StatusConflict, "rollout is "+st)
		return
	}
	t := rollout.Target(org, ro, ro.StepIndex(ro.Step))
	if rules := org.ApprovalRules(t); len(rules) > 0 {
		if _, err := approverGroups(rules, p); err != nil {
			s.Audit(r.Context(), p.ID, "rollout.approve.denied", ro.Name, map[string]string{"step": ro.Step, "why": err.Error()})
			apiErr(w, http.StatusForbidden, err.Error())
			return
		}
		if in.Ticket != "" {
			if err := org.CheckTicket(t, in.Ticket); err != nil {
				apiErr(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
		}
	}
	key := rollout.ApprovalKey(org, ro)
	if as, err := s.approvals.get(key); err != nil {
		s.cfg.Log.Error("read rollout approvals", "rollout", ro.Name, "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	} else if slices.ContainsFunc(as, func(a policy.Approval) bool { return sameUser(a.By, p.ID) }) {
		apiErr(w, http.StatusConflict, "you already approved this step")
		return
	}
	// The record comes first: an approval that is not in the audit log never counts.
	if err := s.AuditStrict(r.Context(), p.ID, "rollout.approve", ro.Name, map[string]string{"step": ro.Step, "key": key, "ticket": in.Ticket, "groups": strings.Join(p.Groups, ",")}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	if _, err := s.approvals.add(key, policy.Approval{By: p.ID, Groups: slices.Clone(p.Groups), At: s.cfg.Now().UTC(), Ticket: in.Ticket}); err != nil {
		s.cfg.Log.Error("store rollout approval", "rollout", ro.Name, "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	out, err := s.rolloutApprovals(org, ro)
	if err != nil {
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// decisionView answers an approve or deny: the request, plus the quorum when
// an approval rule covers it (202 while it is not yet met).
type decisionView struct {
	Request
	Quorum *policy.QuorumResult `json:"quorum,omitempty"`
}

// recordApproval adds p's approval to req (caller holds the request log's
// mu) and returns the quorum (nil when no rule covers req). done reports that
// it already answered: the ticket no longer passes, p is not an approver, p
// approved before while the quorum is still short, or the audit failed. A
// repeat approval of a met quorum (a retry after a failed PR) adds nothing.
func (s *Server) recordApproval(w http.ResponseWriter, r *http.Request, p Principal, req *Request) (q *policy.QuorumResult, done bool) {
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return nil, true
	}
	t := requestTarget(org, req)
	if err := org.CheckTicket(t, req.Ticket); err != nil {
		apiErr(w, http.StatusConflict, err.Error()+": the requester must file the request again with a ticket")
		return nil, true
	}
	if rules := org.ApprovalRules(t); len(rules) > 0 {
		if _, err := approverGroups(rules, p); err != nil {
			s.Audit(r.Context(), p.ID, "request.approval.denied", req.ID, map[string]string{"why": err.Error()})
			apiErr(w, http.StatusForbidden, err.Error())
			return nil, true
		}
	}
	if slices.ContainsFunc(req.Approvals, func(a policy.Approval) bool { return sameUser(a.By, p.ID) }) {
		if q = org.Quorum(t, req.User, req.Ticket, req.Approvals); q == nil || q.Met {
			return q, false
		}
		apiErr(w, http.StatusConflict, "you already approved this request; it needs "+q.String())
		return nil, true
	}
	if err := s.AuditStrict(r.Context(), p.ID, "request.approval", req.ID, map[string]string{"user": req.User, "kind": req.Kind, "item": req.Item,
		"ticket": req.Ticket, "approvals": fmt.Sprint(len(req.Approvals) + 1), "groups": strings.Join(p.Groups, ",")}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return nil, true
	}
	req.Approvals = append(req.Approvals, policy.Approval{By: p.ID, Groups: slices.Clone(p.Groups), At: s.cfg.Now().UTC(), Ticket: req.Ticket})
	return org.Quorum(t, req.User, req.Ticket, req.Approvals), false
}

// requestTarget is what approving req changes. Requests filed before
// ADR-0030 carry none: their ring and every unit (fail closed).
func requestTarget(org *policy.Org, req *Request) policy.ChangeTarget {
	if req.Target != nil {
		return *req.Target
	}
	var rings []string
	if req.Ring != "" {
		rings = []string{req.Ring}
	}
	return org.RingTarget(rings...)
}
