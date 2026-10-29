package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

const governanceYAML = `governance:
  freezes:
    - name: weekend
      reason: no weekend deploys
      weekly: {from: "Sat 00:00", to: "Mon 00:00"}
  approvals:
    - name: two-person
      quorum: 2
      groups: [sre, mgr]
      distinctGroups: true
      ticket: 'CHG[0-9]+'
`

var (
	sre1 = Principal{ID: "sre1@acme.example", Groups: []string{"platform-admins", "sre"}}
	sre2 = Principal{ID: "sre2@acme.example", Groups: []string{"platform-admins", "sre"}}
	mgr1 = Principal{ID: "mgr1@acme.example", Groups: []string{"platform-admins", "mgr"}}
)

func govEnv(t *testing.T) *env {
	t.Helper()
	return newEnv(t, func(c *Config) {
		p := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(b, governanceYAML...), 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

func auditCount(t *testing.T, e *env, action string) int {
	t.Helper()
	return len(decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?action="+action, "")).Entries)
}

// TestRequestQuorumAndSeparationOfDuties: a covered request needs a ticket,
// approvers from the rule's groups (each from a different group), never the
// requester, and opens its PR only when the quorum is met.
func TestRequestQuorumAndSeparationOfDuties(t *testing.T) {
	e := govEnv(t)
	body := `{"kind":"mcp-server","item":"jira","justification":"triage"}`
	if w := e.as(dev, "POST", "/api/v1/requests", body); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "ticket") {
		t.Fatalf("no ticket: %d %s", w.Code, w.Body)
	}
	if w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage","ticket":"OPS-1"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-matching ticket: %d %s", w.Code, w.Body)
	}
	w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage","ticket":"CHG0012345"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	id := decode[Request](t, w).ID
	approve := func(p Principal) *decisionView {
		t.Helper()
		w := e.as(p, "POST", "/api/v1/requests/"+id+"/approve", "")
		if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
			t.Fatalf("approve as %s: %d %s", p.ID, w.Code, w.Body)
		}
		v := decode[decisionView](t, w)
		return &v
	}
	if c := e.as(admin, "POST", "/api/v1/requests/"+id+"/approve", "").Code; c != http.StatusForbidden {
		t.Fatalf("admin outside the approver groups: %d", c)
	}
	if v := approve(sre1); v.Status != StatusPending || v.Quorum == nil || v.Quorum.Rules[0].Have != 1 {
		t.Fatalf("first approval: %+v", v)
	}
	if c := e.as(sre1, "POST", "/api/v1/requests/"+id+"/approve", "").Code; c != http.StatusConflict {
		t.Fatalf("repeat approval: %d", c)
	}
	if v := approve(sre2); v.Status != StatusPending || v.Quorum.Rules[0].Have != 1 {
		t.Fatalf("second sre must not count (distinct groups): %+v", v.Quorum)
	}
	if len(e.w.calls) != 0 {
		t.Fatalf("PR opened before quorum: %+v", e.w.calls)
	}
	v := approve(mgr1)
	if v.Status != StatusApproved || !v.Quorum.Met || len(e.w.calls) != 1 {
		t.Fatalf("quorum met: %+v calls=%d", v, len(e.w.calls))
	}
	if c := e.w.calls[0]; c.Ticket != "CHG0012345" || len(c.Approvals) != 3 {
		t.Fatalf("PR request: %+v", c)
	}
	if n := auditCount(t, e, "request.approval"); n != 3 {
		t.Fatalf("request.approval audit entries = %d, want 3", n)
	}

	// The requester can never approve their own request, whatever groups they hold.
	self := Principal{ID: "sre3@acme.example", Groups: []string{"platform-admins", "sre"}}
	w = e.as(self, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"x","ticket":"CHG1"}`)
	id = decode[Request](t, w).ID
	if c := e.as(self, "POST", "/api/v1/requests/"+id+"/approve", "").Code; c != http.StatusForbidden {
		t.Fatalf("self approval: %d", c)
	}
}

func TestRolloutApprovals(t *testing.T) {
	e := govEnv(t)
	const name = "claude-code-2.1.300"
	path := "/api/v1/rollouts/" + name
	if c := e.as(dev, "POST", path+"/approve", `{}`).Code; c != http.StatusForbidden {
		t.Fatalf("developer: %d", c)
	}
	if c := e.as(admin, "POST", path+"/approve", `{}`).Code; c != http.StatusForbidden {
		t.Fatalf("admin outside the approver groups: %d", c)
	}
	if c := e.as(sre1, "POST", path+"/approve", `{"ticket":"OPS-1"}`).Code; c != http.StatusUnprocessableEntity {
		t.Fatalf("ticket off pattern: %d", c)
	}
	if c := e.as(sre1, "POST", path+"/approve", `{"ticket":"<b>x</b>"}`).Code; c != http.StatusUnprocessableEntity {
		t.Fatalf("ticket shape: %d", c)
	}
	w := e.as(sre1, "POST", path+"/approve", `{"ticket":"CHG7"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if v := decode[RolloutApprovals](t, w); v.Quorum == nil || v.Quorum.Met || len(v.Approvals) != 1 || v.Approvals[0].Ticket != "CHG7" {
		t.Fatalf("after one: %+v", v)
	}
	if c := e.as(sre1, "POST", path+"/approve", `{}`).Code; c != http.StatusConflict {
		t.Fatalf("repeat: %d", c)
	}
	if c := e.as(mgr1, "POST", path+"/approve", `{}`).Code; c != http.StatusOK {
		t.Fatalf("mgr: %d", c)
	}
	if c := e.as(dev, "GET", path+"/approvals", "").Code; c != http.StatusForbidden {
		t.Fatalf("developer read: %d", c)
	}
	v := decode[RolloutApprovals](t, e.as(admin, "GET", path+"/approvals", ""))
	if !v.Quorum.Met || v.Quorum.Ticket != "CHG7" {
		t.Fatalf("quorum: %+v", v.Quorum)
	}
	org, err := e.s.Policy()
	if err != nil {
		t.Fatal(err)
	}
	var ro *policy.Rollout
	for _, r := range org.Rollouts {
		if r.Name == name {
			ro = r
		}
	}
	g, err := e.s.RolloutGovernance(t.Context(), org, ro)
	if err != nil || len(g.Approvals) != 2 || g.Incident != nil {
		t.Fatalf("controller view: %+v %v", g, err)
	}
	// Editing the approved change (same rollout and step) drops the approvals.
	edited := *ro
	edited.Change.Release = "sha256:" + strings.Repeat("e", 64)
	if g, err := e.s.RolloutGovernance(t.Context(), org, &edited); err != nil || len(g.Approvals) != 0 {
		t.Fatalf("approvals carried over to an edited change: %+v %v", g, err)
	}
	if n := auditCount(t, e, "rollout.approve"); n != 2 {
		t.Fatalf("rollout.approve audit entries = %d", n)
	}
}

// TestIncidentFreeze: admins toggle it with a reason, every toggle is in the
// audit log, it covers every ring, and it never reaches a kill list.
func TestIncidentFreeze(t *testing.T) {
	e := govEnv(t)
	viewer := Principal{ID: "v@acme.example"}
	for _, c := range []struct {
		who  Principal
		body string
		want int
	}{
		{dev, `{"frozen":true,"reason":"x"}`, http.StatusForbidden},
		{sre1, `{"frozen":true}`, http.StatusUnprocessableEntity},
		{sre1, `{"reason":"x"}`, http.StatusBadRequest},
		{viewer, `{"frozen":true,"reason":"x"}`, http.StatusForbidden},
	} {
		if got := e.as(c.who, "POST", "/api/v1/freeze", c.body).Code; got != c.want {
			t.Errorf("%s %s: %d want %d", c.who.ID, c.body, got, c.want)
		}
	}
	if w := e.as(admin, "POST", "/api/v1/freeze", `{"frozen":true,"reason":"SEV1 checkout"}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changed":true`) {
		t.Fatalf("freeze: %d %s", w.Code, w.Body)
	}
	v := decode[FreezeView](t, e.as(admin, "GET", "/api/v1/freeze", ""))
	if v.Incident == nil || v.Incident.By != admin.ID || v.Incident.Reason != "SEV1 checkout" || len(v.Rings) == 0 {
		t.Fatalf("view: %+v", v)
	}
	for ring, st := range v.Rings {
		if !st.Frozen || !st.NextOpen.IsZero() {
			t.Fatalf("ring %s not frozen until lifted: %+v", ring, st)
		}
	}
	if recs, _, err := e.s.kills.Killed(); err != nil || len(recs) != 0 {
		t.Fatalf("the freeze reached the kill list: %+v %v", recs, err)
	}
	if w := e.as(admin, "POST", "/api/v1/freeze", `{"frozen":false,"reason":"resolved"}`); w.Code != http.StatusOK {
		t.Fatalf("lift: %d %s", w.Code, w.Body)
	}
	if n := auditCount(t, e, "freeze.on") + auditCount(t, e, "freeze.off"); n != 2 {
		t.Fatalf("freeze audit entries = %d, want 2", n)
	}
	// The policy window: 2026-01-03 is a Saturday.
	*e.now = time.Date(2026, 1, 3, 12, 0, 0, 0, time.UTC)
	v = decode[FreezeView](t, e.as(admin, "GET", "/api/v1/freeze", ""))
	for ring, st := range v.Rings {
		if v.Incident != nil || !st.Frozen || st.Active[0].Name != "weekend" || !st.NextOpen.Equal(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("ring %s on Saturday: %+v", ring, st)
		}
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), "no weekend deploys") {
		t.Fatalf("reason missing: %s", b)
	}
}

// appendFailShared fails appends to the requests log while fail is set.
type appendFailShared struct {
	*memShared
	fail *atomic.Bool
}

func (f appendFailShared) OpenLog(ctx context.Context, name string, replay func([]byte)) (storage.Log, error) {
	l, err := f.memShared.OpenLog(ctx, name, replay)
	if name != "requests" {
		return l, err
	}
	return appendFailLog{l, f.fail}, err
}

type appendFailLog struct {
	storage.Log
	fail *atomic.Bool
}

func (l appendFailLog) Append(ctx context.Context, key string, rec []byte) error {
	if l.fail.Load() {
		return errors.New("store down")
	}
	return l.Log.Append(ctx, key, rec)
}

// TestApprovalRolledBackWhenSaveFails: when the approval that meets the quorum
// cannot be persisted (the decision after an opened PR, or the approvals after
// a failed PR), the in-memory request drops it too, so a retry does not see a
// quorum the store never recorded; the approver approves again (audited again).
func TestApprovalRolledBackWhenSaveFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prErr error
		code  int
	}{
		{"decision save fails after the PR opened", nil, http.StatusInternalServerError},
		{"approvals save fails after the PR failed", errors.New("gh down"), http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fail atomic.Bool
			e := newEnv(t, func(c *Config) {
				c.Backend = appendFailShared{newMemShared(), &fail}
				p := filepath.Join(c.PolicyDir, "halos.yaml")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, append(b, governanceYAML...), 0o600); err != nil {
					t.Fatal(err)
				}
			})
			w := e.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"triage","ticket":"CHG1"}`)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body)
			}
			id := decode[Request](t, w).ID
			if w := e.as(sre1, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != http.StatusAccepted {
				t.Fatalf("first approval: %d %s", w.Code, w.Body)
			}
			fail.Store(true)
			e.w.err = tc.prErr
			if w := e.as(mgr1, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != tc.code {
				t.Fatalf("quorum approval with the store failing: %d %s", w.Code, w.Body)
			}
			fail.Store(false)
			e.w.err = nil
			var got *Request
			for _, r := range decode[[]Request](t, e.as(admin, "GET", "/api/v1/requests", "")) {
				if r.ID == id {
					got = &r
				}
			}
			if got == nil || got.Status != StatusPending || len(got.Approvals) != 1 {
				t.Fatalf("in-memory request after the failed save = %+v, want pending with the 1 persisted approval", got)
			}
			if w := e.as(mgr1, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != http.StatusOK {
				t.Fatalf("retry: %d %s", w.Code, w.Body)
			}
			if n := auditCount(t, e, "request.approval"); n != 3 {
				t.Fatalf("request.approval audit entries = %d, want 3 (the failed attempt's stays, the retry is audited)", n)
			}
		})
	}
}
