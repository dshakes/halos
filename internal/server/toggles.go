package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/toggle"
)

// ToggleView is the JSON shape of a toggle in GET /api/v1/toggles.
type ToggleView struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Owner       string              `json:"owner"`
	Expires     string              `json:"expires,omitempty"`
	Stale       bool                `json:"stale"`
	Axis        policy.Axis         `json:"axis"`
	Default     bool                `json:"default"`
	Rules       []policy.ToggleRule `json:"rules"`
	Payload     TogglePayload       `json:"payload"`
	// Kill is set while the toggle is on the signed kill list.
	Kill *ToggleKill `json:"kill,omitempty"`
}

// TogglePayload summarises what a toggle delivers without its secrets: header
// and env values are never shown, override values only as key names.
type TogglePayload struct {
	Harnesses map[string]PatchSummary `json:"harnesses,omitempty"`
	Routes    map[string]string       `json:"routes,omitempty"` // alias -> "upstream/model" (or its targets)
}

// PatchSummary is one harness's fragment, as names.
type PatchSummary struct {
	MCPServers []string `json:"mcpServers,omitempty"` // "name url"
	Hooks      []string `json:"hooks,omitempty"`      // "event matcher"
	Env        []string `json:"env,omitempty"`        // variable names
	Overrides  []string `json:"overrides,omitempty"`  // top-level keys
}

// ToggleKill is the live kill state of a toggle.
type ToggleKill struct {
	By     string    `json:"by"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

func toggleView(t *policy.Toggle, kills map[string]ToggleKill, now time.Time) ToggleView {
	v := ToggleView{Name: t.Name, Description: t.Description, Owner: t.Owner, Expires: t.Expires, Stale: t.Expired(now),
		Axis: t.Axis, Default: t.Default, Rules: t.Rules}
	if v.Rules == nil {
		v.Rules = []policy.ToggleRule{}
	}
	if k, ok := kills[t.Name]; ok {
		v.Kill = &k
	}
	if t.Client != nil {
		v.Payload.Harnesses = map[string]PatchSummary{}
		for h, p := range t.Client.Harnesses {
			var ps PatchSummary
			for _, m := range p.MCPServers {
				ps.MCPServers = append(ps.MCPServers, strings.TrimSpace(m.Name+" "+m.URL+strings.Join(m.Command, " ")))
			}
			for _, hk := range p.Hooks {
				ps.Hooks = append(ps.Hooks, strings.TrimSpace(hk.Event+" "+hk.Matcher))
			}
			for k := range p.Env {
				ps.Env = append(ps.Env, k)
			}
			for k := range p.Overrides {
				ps.Overrides = append(ps.Overrides, k)
			}
			sort.Strings(ps.Env)
			sort.Strings(ps.Overrides)
			v.Payload.Harnesses[h] = ps
		}
	}
	if t.Traffic != nil {
		v.Payload.Routes = map[string]string{}
		for alias, r := range t.Traffic.Routes {
			var parts []string
			for _, c := range r.Candidates() {
				parts = append(parts, c.Upstream+"/"+c.Model)
			}
			v.Payload.Routes[alias] = strings.Join(parts, ", ")
		}
	}
	return v
}

// toggleKills is the active toggle kills of the kill store, by toggle name.
func (s *Server) toggleKills() (map[string]ToggleKill, error) {
	recs, _, err := s.kills.Killed()
	if err != nil {
		return nil, err
	}
	out := map[string]ToggleKill{}
	for _, r := range recs {
		if n, ok := strings.CutPrefix(r.Experiment, toggleKillPrefix); ok {
			out[n] = ToggleKill{By: r.By, Reason: r.Reason, At: r.At}
		}
	}
	return out, nil
}

// listToggles (admin): GET /api/v1/toggles.
func (s *Server) listToggles(w http.ResponseWriter, _ *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	kills, err := s.toggleKills()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	now := s.cfg.Now()
	out := make([]ToggleView, 0, len(org.Toggles))
	for _, t := range org.Toggles {
		out = append(out, toggleView(t, kills, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"toggles": out, "killEnabled": s.cfg.KillKey != nil})
}

// TogglePreview is the "who gets it?" answer of GET /api/v1/toggles/{name}?user=.
type TogglePreview struct {
	Subject  toggle.Subject  `json:"subject"`
	Decision toggle.Decision `json:"decision"`
}

// getToggle (admin): GET /api/v1/toggles/{name}[?user=&ring=&groups=a,b]: the
// toggle, its kill/audit history, and (with user) the evaluation and rule trace
// from internal/toggle, the code the gateway, halod and `halo toggle eval` run.
func (s *Server) getToggle(w http.ResponseWriter, r *http.Request, _ Principal) {
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	name := r.PathValue("name")
	i := slices.IndexFunc(org.Toggles, func(t *policy.Toggle) bool { return t.Name == name })
	if i < 0 {
		apiErr(w, http.StatusNotFound, "toggle not found")
		return
	}
	t := org.Toggles[i]
	kills, err := s.toggleKills()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	entries, err := s.auditLog.all()
	if err != nil {
		s.cfg.Log.Error("read audit log", "err", err)
		apiErr(w, http.StatusInternalServerError, "audit log unreadable")
		return
	}
	history := []AuditEntry{}
	for _, e := range entries {
		if e.Target == name && strings.HasPrefix(e.Action, "toggle.") {
			history = append(history, e)
		}
	}
	if len(history) > 50 {
		history = history[len(history)-50:]
	}
	resp := struct {
		Toggle  ToggleView     `json:"toggle"`
		History []AuditEntry   `json:"history"`
		Preview *TogglePreview `json:"preview,omitempty"`
	}{Toggle: toggleView(t, kills, s.cfg.Now()), History: history}

	if user := strings.TrimSpace(r.URL.Query().Get("user")); user != "" {
		var groups []string
		for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
		sub := toggle.Subject{ID: user, Groups: groups, Ring: r.URL.Query().Get("ring")}
		if sub.Ring == "" { // same resolution as the gateway
			if ring := org.ResolveRing(policy.Subject{ID: user, Groups: groups}); ring != nil {
				sub.Ring = ring.Name
			}
		} else if ringByName(org, sub.Ring) == nil {
			apiErr(w, http.StatusUnprocessableEntity, "unknown ring "+sub.Ring)
			return
		}
		_, killed := kills[name]
		resp.Preview = &TogglePreview{Subject: sub, Decision: toggle.Eval(t.Name, t.Default, t.Rules, sub, killed)}
	}
	writeJSON(w, http.StatusOK, resp)
}

// rolloutProposer is what GitPolicyWriter offers beyond Propose: build a change
// in its clone and open a PR for it. The console reuses it for toggle edits.
type rolloutProposer interface {
	ProposeRollout(ctx context.Context, plan func(dir string) (*promote.Change, error), branch, title string, body func(patch string) string) (string, error)
}

// postToggleProposal (admin): POST /api/v1/toggles/{name}/propose opens a
// policy-repo PR that edits the toggle (default, expiry, a rule's percent or
// rings/groups/users). The change is validated against the full guardrails
// before the PR exists; nothing is written to the served policy and nothing
// merges: a human reviews the PR.
func (s *Server) postToggleProposal(w http.ResponseWriter, r *http.Request, p Principal) {
	var in struct {
		promote.ToggleChange
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 500 {
		apiErr(w, http.StatusUnprocessableEntity, "reason is required (<=500 chars)")
		return
	}
	if err := in.Check(); err != nil {
		apiErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	name := r.PathValue("name")
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return
	}
	if !slices.ContainsFunc(org.Toggles, func(t *policy.Toggle) bool { return t.Name == name }) {
		apiErr(w, http.StatusNotFound, "toggle not found")
		return
	}
	prop, ok := s.cfg.Writer.(rolloutProposer)
	if !ok || s.cfg.Writer == nil {
		apiErr(w, http.StatusNotImplemented, "no policy writer configured (portal policyRepoDir)")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), proposeTimeout)
	defer cancel()
	summary := in.Summary()
	pr, err := prop.ProposeRollout(ctx,
		func(dir string) (*promote.Change, error) { return promote.PlanToggle(dir, name, in.ToggleChange) },
		"halos/toggle-"+name+"-"+strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(randB64(5))),
		"Toggle "+name+": "+summary,
		func(patch string) string {
			return "Change to feature toggle `" + name + "` (" + summary + ") requested by " + p.ID + " from the Halos console.\n\nReason:\n\n" +
				fenceUntrusted(in.Reason) + "\n\n```diff\n" + patch + "```\n\nValidated against the policy guardrails before opening. Opened by Halos; a human must review and merge.\n"
		})
	if err != nil {
		s.cfg.Log.Error("toggle PR failed", "toggle", name, "err", err)
		code := http.StatusBadGateway
		if errors.Is(err, promote.ErrToggleChange) {
			code = http.StatusUnprocessableEntity
		}
		apiErr(w, code, "could not open policy PR: "+err.Error())
		return
	}
	if err := s.AuditStrict(r.Context(), p.ID, "toggle.propose", name, map[string]string{"change": summary, "reason": in.Reason, "prUrl": pr}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed+" (PR "+pr+" was opened)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"prURL": pr})
}
