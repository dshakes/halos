package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/cloudagents"
	"github.com/dshakes/halos/internal/policy"
)

// Cloud agent governance (ADR-0034). A task is an audit entry with action
// cloudagent.task and the task JSON in details["task"], like the session
// ledger (ADR-0031): one hash chain, one SIEM export, one HA backend. The
// newest version of each task (by its vendor updated time) wins, so a
// replayed or reordered delivery never turns a finished task back on.
const (
	actionCloudTask  = "cloudagent.task"
	actionCloudAlert = "cloudagent.alert"
	actionCloudKill  = "cloudagent.kill"
	actionCloudPause = "cloudagent.pause"
	// webhookActor is who records webhook-observed tasks and the pauses they trigger.
	webhookActor = "halo-server:cloud-agents"
	// cloudRecent bounds GET /api/v1/cloud-agents to tasks updated this recently.
	cloudRecent = 7 * 24 * time.Hour
)

// CloudAgentsView is GET /api/v1/cloud-agents.
type CloudAgentsView struct {
	Tasks  []cloudagents.Task  `json:"tasks"`
	Alerts []cloudagents.Alert `json:"alerts"`
	// Configured reports what halo-server can see and do: the webhook
	// receiver and each vendor API client.
	Configured map[string]bool `json:"configured"`
}

// CloudKillRequest is POST /api/v1/cloud-agents/kill. DryRun defaults to true.
type CloudKillRequest struct {
	Scope  string `json:"scope"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	DryRun *bool  `json:"dryRun,omitempty"`
}

// CloudKillResponse is the kill's plan (dry run) or outcome.
type CloudKillResponse struct {
	DryRun       bool                 `json:"dryRun"`
	Actions      []cloudagents.Action `json:"actions"`
	Unattributed int                  `json:"unattributed"`
	NextSteps    []string             `json:"next_steps"`
}

// cloudTasks reads every stored task, newest version per id, attributed with
// the current policy's identities.
// ponytail: a full audit scan per call, like the session ledger; keep an
// index by task id if webhook volume makes this the hot path.
func (s *Server) cloudTasks(ca *policy.CloudAgents) ([]cloudagents.Task, error) {
	snap, err := s.auditLog.snapshot()
	if err != nil {
		return nil, err
	}
	defer snap.close()
	latest := map[string]cloudagents.Task{}
	err = snap.from(1, func(_ []byte, e AuditEntry) bool {
		if e.Action != actionCloudTask {
			return true
		}
		var t cloudagents.Task
		if json.Unmarshal([]byte(e.Details["task"]), &t) != nil || t.ID != e.Target {
			return true
		}
		if old, ok := latest[t.ID]; !ok || !t.Updated.Before(old.Updated) {
			latest[t.ID] = t
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	out := make([]cloudagents.Task, 0, len(latest))
	for _, t := range latest {
		t.Attribute(ca)
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b cloudagents.Task) int {
		if c := b.Start.Compare(a.Start); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// cloudGroups resolves a user's groups from the SCIM directory (nil without one).
func (s *Server) cloudGroups(user string) []string {
	if s.scim == nil {
		return nil
	}
	_, g, ok := s.scim.store.Lookup(user)
	if !ok {
		return nil
	}
	return g
}

// postGitHubWebhook receives GitHub workflow_run deliveries (public; the
// X-Hub-Signature-256 HMAC is the authentication). 404 without a secret.
func (s *Server) postGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.CloudWebhookSecrets) == 0 {
		apiErr(w, http.StatusNotFound, "cloud agent webhooks not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cloudagents.MaxWebhookBody))
	if err != nil {
		apiErr(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	if err := cloudagents.VerifySignature(s.cfg.CloudWebhookSecrets, body, r.Header.Get("X-Hub-Signature-256")); err != nil {
		s.metrics.authFailure("cloud_webhook", "signature")
		apiErr(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	task, ok, err := cloudagents.ParseGitHubEvent(r.Header.Get("X-GitHub-Event"), body)
	if err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !ok {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return
	}
	task.Attribute(org.CloudAgents)
	tasks, err := s.cloudTasks(org.CloudAgents)
	if err != nil {
		s.cfg.Log.Error("read cloud agent tasks", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	if i := slices.IndexFunc(tasks, func(t cloudagents.Task) bool { return t.ID == task.ID }); i >= 0 {
		if task.Updated.Before(tasks[i].Updated) {
			writeJSON(w, http.StatusAccepted, map[string]string{"status": "stale", "task": task.ID})
			return
		}
		tasks[i] = task
	} else {
		tasks = append(tasks, task)
	}
	b, err := json.Marshal(task)
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "encode task")
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if len(delivery) > 64 {
		delivery = delivery[:64]
	}
	if err := s.AuditStrict(r.Context(), webhookActor, actionCloudTask, task.ID, map[string]string{"task": string(b), "delivery": delivery}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	if rec, ok := task.LedgerRecord(); ok {
		if rb, err := json.Marshal(rec); err == nil {
			if err := s.AuditStrict(r.Context(), webhookActor, actionSessionRecord, rec.ID, map[string]string{"record": string(rb)}); err != nil {
				s.cfg.Log.Error("cloud task ledger record", "task", task.ID, "err", err)
			}
		}
	}
	s.cloudEnforce(r.Context(), org, tasks, task.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded", "task": task.ID})
}

// cloudEnforce raises the alerts involving changed and, where the vendor's
// onOverLimit is pause, pauses those tasks through the vendor API. Pausing is
// reversible (disable a workflow, archive an agent) and halo-server never
// resumes anything: a human does.
func (s *Server) cloudEnforce(ctx context.Context, org *policy.Org, tasks []cloudagents.Task, changed string) {
	alerts := cloudagents.Evaluate(org, tasks, s.cloudGroups, s.cfg.Now())
	var mine []cloudagents.Alert
	for _, a := range alerts {
		if slices.Contains(a.Tasks, changed) {
			mine = append(mine, a)
			s.metrics.cloudAlert(a.Vendor, a.Kind)
			s.cfg.Log.Warn("cloud agent alert", "vendor", a.Vendor, "kind", a.Kind, "key", a.Key, "task", changed, "message", a.Message)
			s.Audit(ctx, webhookActor, actionCloudAlert, changed, map[string]string{"vendor": a.Vendor, "kind": a.Kind, "key": a.Key, "message": a.Message})
		}
	}
	pause := cloudagents.PauseTasks(mine, tasks)
	if len(pause) == 0 {
		return
	}
	for _, a := range s.cfg.CloudClients.Execute(ctx, cloudagents.Plan(pause, cloudagents.OpPause)) {
		s.Audit(ctx, webhookActor, actionCloudPause, a.Task.ID, map[string]string{"call": a.Call, "result": a.Result, "error": a.Error, "manual": a.Manual})
		s.cfg.Log.Warn("cloud agent paused", "task", a.Task.ID, "result", a.Result, "error", a.Error)
	}
}

// getCloudAgents (read): tasks updated in the last 7 days and current alerts.
// ?active=true keeps queued and running tasks only.
func (s *Server) getCloudAgents(w http.ResponseWriter, r *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return
	}
	tasks, err := s.cloudTasks(org.CloudAgents)
	if err != nil {
		s.cfg.Log.Error("read cloud agent tasks", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	now := s.cfg.Now()
	active := r.URL.Query().Get("active") == "true"
	view := CloudAgentsView{Tasks: []cloudagents.Task{}, Configured: map[string]bool{
		"githubWebhook": len(s.cfg.CloudWebhookSecrets) > 0, "github": s.cfg.CloudClients.GitHub != nil, "cursor": s.cfg.CloudClients.Cursor != nil,
	}}
	for _, t := range tasks {
		if (active && !t.Active()) || (!t.Active() && now.Sub(t.Updated) > cloudRecent) {
			continue
		}
		view.Tasks = append(view.Tasks, t)
	}
	view.Alerts = cloudagents.Evaluate(org, view.Tasks, s.cloudGroups, now)
	if view.Alerts == nil {
		view.Alerts = []cloudagents.Alert{}
	}
	writeJSON(w, http.StatusOK, view)
}

// postCloudKill (operate): cancel the active cloud tasks of a user, ring or
// experiment. Reason required; a dry run (the default) only plans. The intent
// is audited strictly before any vendor call, and the outcome after.
func (s *Server) postCloudKill(w http.ResponseWriter, r *http.Request, p Principal) {
	var in CloudKillRequest
	if err := decodeBody(w, r, 4096, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 500 {
		apiErr(w, http.StatusUnprocessableEntity, "reason is required (<=500 chars)")
		return
	}
	dry := in.DryRun == nil || *in.DryRun
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return
	}
	tasks, err := s.cloudTasks(org.CloudAgents)
	if err != nil {
		s.cfg.Log.Error("read cloud agent tasks", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	hit, unattributed, err := cloudagents.Select(org, tasks, in.Scope, in.Name, s.cloudGroups)
	if err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := CloudKillResponse{DryRun: dry, Actions: cloudagents.Plan(hit, cloudagents.OpCancel), Unattributed: unattributed}
	details := map[string]string{"scope": in.Scope, "name": in.Name, "reason": in.Reason, "dryRun": fmt.Sprint(dry), "tasks": fmt.Sprint(len(hit))}
	if dry {
		resp.NextSteps = []string{fmt.Sprintf(`POST /api/v1/cloud-agents/kill {"scope":%q,"name":%q,"reason":"...","dryRun":false} (or halo cloud-agents kill --execute) cancels the %d task(s) above`, in.Scope, in.Name, len(hit))}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if err := s.AuditStrict(r.Context(), p.ID, actionCloudKill, in.Scope+":"+in.Name, details); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	resp.Actions = s.cfg.CloudClients.Execute(r.Context(), resp.Actions)
	failed := 0
	for _, a := range resp.Actions {
		if a.Result != cloudagents.ResultDone {
			failed++
		}
		if err := s.AuditStrict(r.Context(), p.ID, actionCloudKill+".result", a.Task.ID, map[string]string{"call": a.Call, "result": a.Result, "error": a.Error}); err != nil {
			s.cfg.Log.Error("audit cloud kill result", "task", a.Task.ID, "err", err) // the cancel stands: fail safe
		}
	}
	s.cfg.Log.Warn("cloud agent kill", "scope", in.Scope, "name", in.Name, "by", p.ID, "tasks", len(hit), "not_done", failed)
	if failed > 0 {
		resp.NextSteps = append(resp.NextSteps, fmt.Sprintf("%d task(s) were not cancelled: follow each action's manual step or error", failed))
	}
	if unattributed > 0 {
		resp.NextSteps = append(resp.NextSteps, fmt.Sprintf("%d active task(s) map to no Halos user and were not reached: add cloudAgents.identities, or cancel them by user", unattributed))
	}
	if resp.NextSteps == nil {
		resp.NextSteps = []string{}
	}
	writeJSON(w, http.StatusOK, resp)
}

// cloudKillHint is what an experiment kill adds to its answer: the cloud tasks
// the experiment's users are running, and how to cancel them (never automatic).
func (s *Server) cloudKillHint(org *policy.Org, experiment string) map[string]any {
	if org.CloudAgents == nil {
		return nil
	}
	tasks, err := s.cloudTasks(org.CloudAgents)
	if err != nil {
		return map[string]any{"error": "cloud agent tasks unreadable"}
	}
	hit, _, err := cloudagents.Select(org, tasks, cloudagents.ScopeExperiment, experiment, s.cloudGroups)
	if err != nil {
		return nil
	}
	return map[string]any{
		"activeTasks": len(hit),
		"next_steps":  []string{fmt.Sprintf(`POST /api/v1/cloud-agents/kill {"scope":"experiment","name":%q,"reason":"..."} plans their cancellation (dry run); add "dryRun":false to cancel`, experiment)},
	}
}
