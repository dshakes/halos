package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

func dlpEnv(t *testing.T) *env {
	t.Helper()
	return newEnv(t, func(c *Config) { c.GatewayDLPToken = "dlp-tok" })
}

func dlpEvent() gateway.DLPEvent {
	return gateway.DLPEvent{At: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), Gateway: "halo-proxy", Subject: "alice@acme.example",
		Ring: "ga", Unit: "payments", Protocol: gateway.ProtoAnthropic, Direction: gateway.DLPRequest, Action: "redact",
		DLPFinding: gateway.DLPFinding{Kind: gateway.DLPSecret, Detector: "github-token", Hash: "0a1b2c3d", Location: "messages[2].content[0].content", ToolData: true}}
}

func TestGatewayDLPEventsAudited(t *testing.T) {
	e := dlpEnv(t)
	inj := dlpEvent()
	inj.Kind, inj.Detector, inj.Hash, inj.Action, inj.Score, inj.Signals = gateway.DLPInjection, gateway.DLPInjection, "", "block", 5, []string{"instruction-override", "fake-turn"}
	body := mustJSON(t, gateway.DLPBatch{Batch: "b-1", Events: []gateway.DLPEvent{dlpEvent(), inj}})
	if w := do(e.h, "POST", "/api/v1/gateway/dlp/events", "Bearer dlp-tok", body); w.Code != 200 || !strings.Contains(w.Body.String(), `"duplicate":false`) {
		t.Fatalf("post: %d %s", w.Code, w.Body)
	}
	if w := do(e.h, "POST", "/api/v1/gateway/dlp/events", "Bearer dlp-tok", body); w.Code != 200 || !strings.Contains(w.Body.String(), `"duplicate":true`) {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	r := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit", ""))
	var got []AuditEntry
	for _, a := range r.Entries {
		if strings.HasPrefix(a.Action, "dlp.") {
			got = append(got, a)
		}
	}
	if !r.Verified || len(got) != 2 {
		t.Fatalf("audit: verified=%v dlp entries %+v", r.Verified, got)
	}
	s, i := got[0], got[1]
	if s.Action != "dlp.secret" || s.Actor != "gateway:halo-proxy" || s.Target != "alice@acme.example" || s.Details["detector"] != "github-token" ||
		s.Details["hash"] != "0a1b2c3d" || s.Details["ring"] != "ga" || s.Details["unit"] != "payments" || s.Details["action"] != "redact" || s.Details["batch"] != "b-1" {
		t.Fatalf("secret entry %+v", s)
	}
	if i.Action != "dlp.injection" || i.Details["score"] != "5" || i.Details["signals"] != "instruction-override,fake-turn" || i.Details["action"] != "block" {
		t.Fatalf("injection entry %+v", i)
	}
}

func TestGatewayDLPEventsRejects(t *testing.T) {
	e := dlpEnv(t)
	bad := func(f func(*gateway.DLPEvent)) string {
		ev := dlpEvent()
		f(&ev)
		return mustJSON(t, gateway.DLPBatch{Batch: "x", Events: []gateway.DLPEvent{ev}})
	}
	many := make([]gateway.DLPEvent, gateway.MaxDLPEvents+1)
	for i := range many {
		many[i] = dlpEvent()
	}
	for _, tc := range []struct {
		name, auth, body string
		want             int
	}{
		{"no token", "", `{}`, 401},
		{"shared token is not the dlp token", "Bearer gw-tok", `{}`, 401},
		{"bad json", "Bearer dlp-tok", `{`, 400},
		{"no batch", "Bearer dlp-tok", `{"events":[]}`, 422},
		{"too many", "Bearer dlp-tok", mustJSON(t, gateway.DLPBatch{Batch: "x", Events: many}), 422},
		{"a secret where the hash goes", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Hash = "ghp_" + strings.Repeat("a", 36) }), 422},
		{"unknown kind", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Kind = "pii" }), 422},
		{"unknown action", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Action = "allow" }), 422},
		{"detector with spaces", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Detector = "a b" }), 422},
		{"newline in location", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Location = "a\nb" }), 422},
		{"long subject", "Bearer dlp-tok", bad(func(e *gateway.DLPEvent) { e.Subject = strings.Repeat("s", 257) }), 422},
	} {
		if w := do(e.h, "POST", "/api/v1/gateway/dlp/events", tc.auth, tc.body); w.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, w.Code, w.Body, tc.want)
		}
	}
	if w := do(newEnv(t, nil).h, "POST", "/api/v1/gateway/dlp/events", "Bearer x", `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured: %d", w.Code)
	}
}
