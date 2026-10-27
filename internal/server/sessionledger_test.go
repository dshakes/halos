package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/ledger"
)

func ledgerRecs(t *testing.T, recs ...ledger.Record) string {
	t.Helper()
	out, err := ledger.Normalize(recs, ledger.Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(SessionsIngest{Records: out})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSessionLedger(t *testing.T) {
	dir := t.TempDir()
	e := scimEnv(t, false, func(c *Config) { c.DataDir = dir })
	e.createSCIMUser(t, "dev@acme.example", true)
	e.createSCIMUser(t, "gone@acme.example", false)
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	rec := func(sid, vendorUser, forged string, d time.Duration, tools ...string) ledger.Record {
		return ledger.Record{SessionID: sid, Harness: "claude-code", Who: ledger.Who{VendorUser: vendorUser, User: forged}, Ring: "ring1",
			Tools: tools, Start: at.Add(d), Sources: []string{ledger.SourceOTel}}
	}
	auditN := func() int { return len(e.auditActions(t)) }

	// Fail closed: one bad record refuses the batch, nothing is stored.
	before := auditN()
	ok := ledgerRecs(t, rec("s-ok", "dev@acme.example", "", 0, "Bash"))
	for name, body := range map[string]string{
		"unhashed path":  strings.Replace(ok, `"sources"`, `"files":["/home/dev/plan.md"],"sources"`, 1),
		"prose":          strings.Replace(ok, `"ring":"ring1"`, `"ring":"please summarise this"`, 1),
		"unknown field":  strings.Replace(ok, `"sources"`, `"prompt":"hi","sources"`, 1),
		"forged id":      strings.Replace(ok, `"id":"`, `"id":"0`, 1),
		"empty batch":    `{"records":[]}`,
		"trailing value": ok + `{}`,
	} {
		if w := e.as(admin, "POST", "/api/v1/sessions", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if n := auditN(); n != before {
		t.Fatalf("a refused batch wrote %d audit entries", n-before)
	}

	// Store three sessions: Who.User comes from the directory only, whatever
	// a client (not halo sessions import) puts in the body.
	body := ledgerRecs(t,
		rec("s-1", "dev@acme.example", "", 0, "Bash", "mcp__github__x"),
		rec("s-2", "stranger@else.example", "", time.Hour, "Edit"),
		rec("s-3", "gone@acme.example", "", 2*time.Hour))
	forgedBody := strings.Replace(body, `{"vendorUser":"stranger@else.example"}`, `{"user":"ceo@acme.example","vendorUser":"stranger@else.example"}`, 1)
	if forgedBody == body {
		t.Fatal("fixture: no record to forge")
	}
	w := e.as(admin, "POST", "/api/v1/sessions", forgedBody)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", w.Code, w.Body)
	}
	got := decode[SessionsIngest](t, w).Records
	if users := []string{got[0].Who.User, got[1].Who.User, got[2].Who.User}; !slices.Equal(users, []string{"dev@acme.example", "", ""}) {
		t.Fatalf("identity join: %q (forged and deactivated identities must stay unresolved)", users)
	}
	last := e.auditActions(t)[auditN()-1]
	if last.Action != actionSessionRecord || last.Actor != admin.ID || last.Target != got[2].ID || !strings.Contains(last.Details["record"], `"sessionId":"s-3"`) {
		t.Fatalf("audit entry: %+v", last)
	}
	// SIEM export (ADR-0016) carries the record as it carries any audit entry.
	if o := ocsfEvent(auditEvent{e: last}); o.API.Operation != actionSessionRecord || o.Unmapped.Details["record"] != last.Details["record"] ||
		len(o.Resources) != 1 || o.Resources[0].Name != got[2].ID {
		t.Fatalf("OCSF event: %+v", o)
	}

	// A newer version of s-1 supersedes the old one.
	if w := e.as(admin, "POST", "/api/v1/sessions", ledgerRecs(t, rec("s-1", "dev@acme.example", "", 0, "Bash", "Write"))); w.Code != http.StatusOK {
		t.Fatalf("re-ingest: %d %s", w.Code, w.Body)
	}

	list := func(q string) SessionsResponse {
		t.Helper()
		w := e.as(admin, "GET", "/api/v1/sessions"+q, "")
		if w.Code != http.StatusOK {
			t.Fatalf("list %s: %d %s", q, w.Code, w.Body)
		}
		return decode[SessionsResponse](t, w)
	}
	all := list("")
	if all.Total != 3 || !all.Verified || all.Head == "" || all.Sessions[0].SessionID != "s-3" || all.Sessions[2].SessionID != "s-1" ||
		!slices.Equal(all.Sessions[2].Tools, []string{"Bash", "Write"}) || all.Sessions[2].AuditSeq == 0 || all.Sessions[2].AuditHash == "" {
		t.Fatalf("list: %+v", all)
	}
	for q, want := range map[string][]string{
		"?user=dev@acme.example":      {"s-1"},
		"?user=stranger@else.example": {"s-2"}, // unresolved: matches the vendor identity
		"?tool=Edit":                  {"s-2"},
		"?tool=mcp__github__x":        nil, // the older version had it; the latest does not
		"?harness=codex":              nil,
		"?ring=ring1&limit=1":         {"s-3"},
		"?since=2026-10-26T10:30:00Z": {"s-3", "s-2"},
		"?until=2026-10-26T10:30:00Z": {"s-1"},
	} {
		var ids []string
		for _, s := range list(q).Sessions {
			ids = append(ids, s.SessionID)
		}
		if !slices.Equal(ids, want) {
			t.Errorf("%s: %q, want %q", q, ids, want)
		}
	}
	for _, q := range []string{"?since=yesterday", "?limit=0", "?limit=5001"} {
		if w := e.as(admin, "GET", "/api/v1/sessions"+q, ""); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	if one := decode[SessionsResponse](t, e.as(admin, "GET", "/api/v1/sessions/s-2", "")); len(one.Sessions) != 1 || one.Sessions[0].ID != got[1].ID {
		t.Fatalf("show by session id: %+v", one)
	}
	if one := decode[SessionsResponse](t, e.as(admin, "GET", "/api/v1/sessions/"+got[1].ID, "")); len(one.Sessions) != 1 {
		t.Fatalf("show by ledger id: %+v", one)
	}
	if w := e.as(admin, "GET", "/api/v1/sessions/nope", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d", w.Code)
	}

	// Tamper with a stored record on disk: the chain no longer verifies, and
	// both the ledger read and `halo audit verify` say so.
	p := filepath.Join(dir, auditActive)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(b, []byte(`\"Edit\"`), []byte(`\"Edyt\"`), 1)
	if bytes.Equal(forged, b) {
		t.Fatal("fixture: no record to tamper with")
	}
	if err := os.WriteFile(p, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := list(""); r.Verified || !strings.Contains(r.VerifyError, "modified") {
		t.Fatalf("tampered ledger verified: %+v", r)
	}
	if v, err := VerifyAuditDir(dir); err == nil && v.Error == "" {
		t.Fatalf("VerifyAuditDir missed the tamper: %+v", v)
	}
}
