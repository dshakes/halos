package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
)

func TestAuditChainAndEndpoint(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) { c.DataDir = dir })

	for _, c := range []struct {
		who  Principal
		want int
	}{{Principal{}, 401}, {dev, 403}, {admin, 200}} {
		if got := e.as(c.who, "GET", "/api/v1/audit", "").Code; got != c.want {
			t.Errorf("audit as %q: %d want %d", c.who.ID, got, c.want)
		}
	}

	// real actions land in the log with actor, ip and request id
	rq := decode[Request](t, e.as(dev, "POST", "/api/v1/requests", `{"kind":"ring-opt-in","item":"`+optInRing(t, e)+`","justification":"please"}`))
	if c := e.as(admin, "POST", "/api/v1/requests/"+rq.ID+"/approve", "").Code; c != 200 {
		t.Fatalf("approve: %d", c)
	}
	dt := enrollDevice(t, e, dev)
	_ = dt
	devs := decode[[]Device](t, e.as(admin, "GET", "/api/v1/devices", ""))
	e.as(admin, "POST", "/api/v1/devices/"+devs[0].ID+"/revoke", "")
	e.as(admin, "POST", "/api/v1/users/"+dev.ID+"/revoke-sessions", "")
	e.s.Audit(context.Background(), "x", "experiment.kill", "exp1", map[string]string{"reason": "test"})

	resp := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?limit=500", ""))
	var actions []string
	for _, en := range resp.Entries {
		actions = append(actions, en.Action)
	}
	want := "request.create,request.approve,device.enroll,device.revoke,session.revoke,experiment.kill"
	if got := strings.Join(actions, ","); got != want || !resp.Verified || resp.Total != 6 {
		t.Fatalf("actions %s verified=%v total=%d (%s)", got, resp.Verified, resp.Total, resp.VerifyError)
	}
	if ap := resp.Entries[1]; ap.Actor != admin.ID || ap.Details["prUrl"] != "https://git.example/pr/1" || ap.RequestID == "" {
		t.Errorf("approve entry: %+v", ap)
	}

	// pagination: newest page without since, then forward by cursor
	p1 := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?limit=2", ""))
	if len(p1.Entries) != 2 || p1.Entries[0].Seq != 5 || p1.Next != 6 {
		t.Fatalf("tail page: %+v", p1)
	}
	p2 := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?since=2&limit=2", ""))
	if len(p2.Entries) != 2 || p2.Entries[0].Seq != 3 || p2.Next != 4 {
		t.Fatalf("forward page: %+v", p2)
	}
	if f := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?action=device.revoke", "")); len(f.Entries) != 1 {
		t.Errorf("action filter: %+v", f.Entries)
	}
	if f := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit?since="+e.now.Add(time.Hour).Format(time.RFC3339), "")); len(f.Entries) != 0 {
		t.Errorf("time cursor: %+v", f.Entries)
	}
	for _, bad := range []string{"limit=0", "limit=501", "limit=x", "since=yesterday"} {
		if c := e.as(admin, "GET", "/api/v1/audit?"+bad, "").Code; c != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, c)
		}
	}

	// tampering on disk is detected by the running server, and by restart + verify
	path := filepath.Join(dir, "audit.jsonl")
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]string{
		"edit":   strings.Replace(string(orig), `"actor":"x"`, `"actor":"y"`, 1),
		"delete": strings.Join(strings.SplitAfter(string(orig), "\n")[1:], ""), // drop first line
		"garble": strings.Replace(string(orig), `"seq":3,`, `"seq":3`, 1),
	} {
		if mut == string(orig) {
			t.Fatalf("%s: mutation was a no-op", name)
		}
		if err := os.WriteFile(path, []byte(mut), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit", "")); r.Verified || r.VerifyError == "" {
			t.Errorf("%s not detected", name)
		}
	}
	// middle deletion
	lines := strings.SplitAfter(string(orig), "\n")
	if err := os.WriteFile(path, []byte(lines[0]+strings.Join(lines[2:], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := decode[AuditResponse](t, e.as(admin, "GET", "/api/v1/audit", "")); r.Verified {
		t.Error("middle deletion not detected")
	}
}

func TestAuditPersistsAcrossRestartAndTornLine(t *testing.T) {
	dir := t.TempDir()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.close() }) // Windows cannot delete an open file
	for _, a := range []string{"a", "b"} {
		if err := l.append(AuditEntry{Actor: "u", Action: a}); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":3,"act`) // crash mid-write
	_ = f.Close()
	l2, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l2.close() }) // Windows cannot delete an open file
	if err := l2.append(AuditEntry{Actor: "u", Action: "c"}); err != nil {
		t.Fatal(err)
	}
	all, _ := l2.all()
	if len(all) != 3 || VerifyAuditChain(all) != nil {
		t.Fatalf("chain after torn line: %d entries, %v", len(all), VerifyAuditChain(all))
	}
}

func TestAuditIPTrustedProxy(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	from := func(remote, xff string) string {
		r := httptest.NewRequest("POST", "/api/v1/users/u/revoke-sessions", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix()})})
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", xff)
		e.h.ServeHTTP(httptest.NewRecorder(), r)
		all, _ := e.s.auditLog.all()
		return all[len(all)-1].IP
	}
	if ip := from("10.1.1.1:5", "203.0.113.9"); ip != "203.0.113.9" {
		t.Errorf("trusted proxy: %q", ip)
	}
	if ip := from("198.51.100.7:5", "203.0.113.9"); ip != "198.51.100.7" {
		t.Errorf("untrusted peer must ignore XFF: %q", ip)
	}
}

func optInRing(t *testing.T, e *env) string {
	t.Helper()
	org, _, _ := e.s.pol.Get()
	for _, r := range org.Rings {
		if r.Membership.OptIn {
			return r.Name
		}
	}
	t.Fatal("no opt-in ring")
	return ""
}

func TestReleases(t *testing.T) {
	e := newEnv(t, nil)
	org, _, _ := e.s.pol.Get()
	ring := org.Rings[0].Name
	cur := strings.Repeat("a", 64)
	ptr := bundle.Pointer{Org: "acme-corp", Ring: ring, Digest: cur, Seq: 7, IssuedAt: e.now.Add(-24 * time.Hour), ExpiresAt: e.now.Add(47 * time.Hour)}
	calls := 0
	var ferr error
	e.s.relChannels = func(context.Context, bundle.Pointer) ([]string, error) { return nil, nil }
	e.s.relFetch = func(_ context.Context, r string) (bundle.Pointer, bool, error) {
		calls++
		if ferr != nil {
			return bundle.Pointer{}, false, ferr
		}
		if r != ring {
			return bundle.Pointer{}, false, nil
		}
		return ptr, true, nil
	}
	put := func(host, dig string, drift ...string) {
		if err := e.s.cfg.Store.Put(Host{Report: Report{Hostname: host, Ring: ring, Digest: dig, Drift: drift}, LastSeen: *e.now}); err != nil {
			t.Fatal(err)
		}
	}
	put("h1", cur)
	put("h2", cur)
	put("h3", strings.Repeat("b", 64), "claude: version")

	for _, c := range []struct {
		who  Principal
		want int
	}{{Principal{}, 401}, {dev, 403}, {admin, 200}} {
		if got := e.as(c.who, "GET", "/api/v1/releases", "").Code; got != c.want {
			t.Errorf("releases as %q: %d want %d", c.who.ID, got, c.want)
		}
	}
	calls = 0
	get := func() ReleasesResponse {
		return decode[ReleasesResponse](t, e.as(admin, "GET", "/api/v1/releases", ""))
	}
	row := func(r ReleasesResponse) RingRelease {
		for _, x := range r.Rings {
			if x.Ring == ring {
				return x
			}
		}
		t.Fatal("ring row missing")
		return RingRelease{}
	}
	r := get()
	rr := row(r)
	if !rr.Published || rr.Digest != cur || rr.Seq != 7 || !rr.ExpiringSoon || rr.Expired || rr.Stale || r.Stale {
		t.Fatalf("row: %+v", rr)
	}
	if c := rr.Convergence; c.Total != 3 || c.OnDigest != 2 || c.Other != 1 || rr.Drift != 1 {
		t.Errorf("convergence: %+v drift=%d", c, rr.Drift)
	}
	if len(r.Rings) != len(org.Rings) {
		t.Errorf("rings %d want %d", len(r.Rings), len(org.Rings))
	}

	// cached for 30s: no second registry round-trip
	n := calls
	get()
	if calls != n {
		t.Errorf("registry hit again within TTL: %d -> %d", n, calls)
	}

	// registry down after TTL: last verified state, flagged stale
	*e.now = e.now.Add(31 * time.Second)
	ferr = errors.New("dial tcp: connection refused")
	r = get()
	if rr = row(r); !r.Stale || !rr.Stale || !rr.Published || rr.Digest != cur || rr.Error == "" {
		t.Fatalf("stale row: %+v", rr)
	}
	// ...and expiry is computed live against the clock, not cached
	*e.now = e.now.Add(48 * time.Hour)
	if rr = row(get()); !rr.Expired || rr.ExpiringSoon {
		t.Errorf("expiry: %+v", rr)
	}

	// never-fetched + failing: no pointer data at all (nothing unverified is shown)
	e2 := newEnv(t, nil) // production fetch: registry key "x" is not a valid key
	rr = decode[ReleasesResponse](t, e2.as(admin, "GET", "/api/v1/releases", "")).Rings[0]
	if rr.Published || rr.Digest != "" || rr.Error == "" || rr.Stale {
		t.Errorf("unverifiable: %+v", rr)
	}
}

func TestDeviceDetail(t *testing.T) {
	e := newEnv(t, nil)
	dt := enrollDevice(t, e, dev)
	devs := decode[[]Device](t, e.as(admin, "GET", "/api/v1/devices", ""))
	id := devs[0].ID
	for i := 0; i < MaxHistory+5; i++ {
		body := `{"hostname":"lap","ring":"r","digest":"d` + string(rune('a'+i%26)) + `","harnesses":{"claude":{"want":"1","installed":"1"}},"errorCode":"e` + strings.Repeat("x", i%3) + `"}`
		if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+dt, body).Code; c != 204 {
			t.Fatalf("report: %d", c)
		}
	}
	for _, c := range []struct {
		who  Principal
		path string
		want int
	}{{Principal{}, id, 401}, {dev, id, 403}, {admin, id, 200}, {admin, "nope", 404}} {
		if got := e.as(c.who, "GET", "/api/v1/devices/"+c.path, "").Code; got != c.want {
			t.Errorf("detail %s as %q: %d want %d", c.path, c.who.ID, got, c.want)
		}
	}
	w := e.as(admin, "GET", "/api/v1/devices/"+id, "")
	if strings.Contains(w.Body.String(), `"hash"`) {
		t.Error("hash leaked")
	}
	d := decode[DeviceDetail](t, w)
	if d.Device.ID != id || d.Last == nil || len(d.History) != MaxHistory || d.Last.Harnesses["claude"].Installed != "1" {
		t.Fatalf("detail: last=%v history=%d", d.Last, len(d.History))
	}
	if d.History[0].Digest != "d"+string(rune('a'+(MaxHistory+4)%26)) { // newest first
		t.Errorf("order: %s", d.History[0].Digest)
	}
}

func TestExperimentStatus(t *testing.T) {
	e := newEnv(t, nil)
	org, _, _ := e.s.pol.Get()
	var name, status string
	for _, x := range org.Experiments {
		name, status = x.Name, x.Status
		break
	}
	if name == "" {
		t.Skip("fixture has no experiment")
	}
	next := "running"
	if status == "running" {
		next = "paused"
	}
	path := "/api/v1/experiments/" + name + "/status"
	for _, c := range []struct {
		who  Principal
		body string
		want int
	}{
		{Principal{}, `{"status":"` + next + `"}`, 401},
		{dev, `{"status":"` + next + `"}`, 403},
		{admin, `{"status":"draft"}`, 422},
		{admin, `{"status":"bogus"}`, 422},
		{admin, `nope`, 422},
		{admin, `{"status":"` + next + `"}`, 200},
	} {
		if got := e.as(c.who, "POST", path, c.body).Code; got != c.want {
			t.Errorf("%q as %q: %d want %d", c.body, c.who.ID, got, c.want)
		}
	}
	if len(e.w.calls) != 1 || e.w.calls[0].Kind != experimentStatusKind || e.w.calls[0].Item != name || e.w.calls[0].Note != next {
		t.Fatalf("writer calls: %+v", e.w.calls)
	}
	if c := e.as(admin, "POST", "/api/v1/experiments/missing/status", `{"status":"paused"}`).Code; c != 404 {
		t.Errorf("unknown experiment: %d", c)
	}
	if c := e.as(admin, "POST", path, `{"status":"`+status+`"}`).Code; status != "" && status != "draft" && c != 409 {
		t.Errorf("no-op status: %d", c)
	}
	all, _ := e.s.auditLog.all()
	if last := all[len(all)-1]; last.Action != "experiment.status" || last.Details["prUrl"] == "" {
		t.Errorf("audit: %+v", last)
	}
	e.w.err = errors.New("gh down")
	if c := e.as(admin, "POST", path, `{"status":"concluded"}`).Code; c != 502 {
		t.Errorf("writer failure: %d", c)
	}
	e2 := newEnv(t, func(c *Config) { c.Writer = nil })
	if c := e2.as(admin, "POST", path, `{"status":"`+next+`"}`).Code; c != 501 {
		t.Errorf("no writer: %d", c)
	}
}

func TestCapabilities(t *testing.T) {
	e := newEnv(t, nil)
	if c := e.as(Principal{}, "GET", "/api/v1/capabilities", "").Code; c != 401 {
		t.Errorf("anon: %d", c)
	}
	if w := e.as(admin, "GET", "/api/v1/capabilities", ""); w.Code != 200 {
		t.Errorf("admin: %d %s", w.Code, w.Body.String())
	}
	m := http.NewServeMux()
	m.HandleFunc("/api/", func(http.ResponseWriter, *http.Request) {})
	if routeRegistered(m, "POST", "/api/v1/experiments/x/kill") {
		t.Error("catch-all counted as a route")
	}
	m.HandleFunc("POST /api/v1/experiments/{name}/kill", func(http.ResponseWriter, *http.Request) {})
	if !routeRegistered(m, "POST", "/api/v1/experiments/x/kill") {
		t.Error("registered route not detected")
	}
}

func TestAppendAuditOffline(t *testing.T) {
	dir := t.TempDir()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.close() }) // Windows cannot delete an open file
	if err := l.append(AuditEntry{Actor: "u", Action: "a"}); err != nil {
		t.Fatal(err)
	}
	_ = l.f.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ { // each call reopens: head must come from disk
		if err := AppendAuditOffline(dir, "controller", "experiment.kill", "exp", map[string]string{"reason": "r"}, now); err != nil {
			t.Fatal(err)
		}
	}
	l2, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l2.close() }) // Windows cannot delete an open file
	all, _ := l2.all()
	if len(all) != 3 || VerifyAuditChain(all) != nil || all[2].Action != "experiment.kill" {
		t.Fatalf("chain: %+v, %v", all, VerifyAuditChain(all))
	}
}

// A privileged action whose audit append fails answers 500; login stays best-effort.
func TestPrivilegedActionFailsWhenAuditFails(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.DataDir = t.TempDir() })
	_ = e.s.auditLog.f.Close() // every append now errors
	if c := e.as(admin, "POST", "/api/v1/users/"+dev.ID+"/revoke-sessions", "").Code; c != http.StatusInternalServerError {
		t.Fatalf("revoke-sessions with broken audit log: %d, want 500", c)
	}
	if err := e.s.AuditStrict(context.Background(), "u", "x", "", nil); err == nil {
		t.Fatal("AuditStrict must return the append error")
	}
	e.s.Audit(context.Background(), "u", "login", "", nil) // best-effort: must not panic or block
}
