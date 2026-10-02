package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// fuzzEndpoint is one JSON-decoding API endpoint and what makes a 2xx legitimate.
type fuzzEndpoint struct {
	path  string
	limit int
	admin bool // cookie endpoints: admin role required (else any user)
	// ok reports whether body is well-formed enough that a 2xx is legitimate.
	ok func(body []byte, enrollTok string) bool
}

func decodeFirst(body []byte, v any) bool {
	err := json.NewDecoder(bytes.NewReader(body)).Decode(v)
	return err == nil || (err == io.EOF && len(bytes.TrimSpace(body)) == 0)
}

var fuzzEndpoints = []fuzzEndpoint{
	{"/api/v1/fleet/report", MaxReportBytes, false, func(b []byte, _ string) bool {
		var r Report
		return json.Unmarshal(b, &r) == nil && r.Hostname != "" && len(r.Hostname) <= 253
	}},
	{"/api/v1/enroll", 4096, false, func(b []byte, tok string) bool {
		var in struct{ Token string }
		return decodeFirst(b, &in) && in.Token == tok
	}},
	{"/api/v1/experiments/opus-5-5-canary/kill", 2048, true, func(b []byte, _ string) bool {
		var in struct{ Reason string }
		return decodeFirst(b, &in) && strings.TrimSpace(in.Reason) != "" && len(strings.TrimSpace(in.Reason)) <= 500
	}},
	{"/api/v1/experiments/opus-5-5-canary/unkill", 2048, true, func(b []byte, _ string) bool {
		var in struct{ Reason string }
		return decodeFirst(b, &in) && len(strings.TrimSpace(in.Reason)) <= 500
	}},
	{"/api/v1/toggles/github-mcp/kill", 2048, true, func(b []byte, _ string) bool {
		var in struct{ Reason string }
		return decodeFirst(b, &in) && strings.TrimSpace(in.Reason) != "" && len(strings.TrimSpace(in.Reason)) <= 500
	}},
	// No rollout-capable writer is configured: never 2xx, but the body is still decoded and validated first.
	{"/api/v1/toggles/github-mcp/propose", 8192, true, func([]byte, string) bool { return false }},
	{"/api/v1/requests", 8192, false, func(b []byte, _ string) bool {
		var in Request
		return decodeFirst(b, &in) && strings.TrimSpace(in.Justification) != "" && len(strings.TrimSpace(in.Justification)) <= 1000 &&
			slices.Contains([]string{"mcp-server", "ring-opt-in", "harness"}, in.Kind)
	}},
	{"/api/v1/experiments/opus-5-5-canary/status", 1024, true, func(b []byte, _ string) bool {
		var in struct{ Status string }
		return decodeFirst(b, &in) && slices.Contains(settableStatuses, in.Status)
	}},
}

// Auth modes for the fuzzed request.
const (
	fuzzNone        = iota // no credential
	fuzzDev                // developer session (or the fleet token for /fleet/report)
	fuzzAdmin              // admin session (or a device token for /fleet/report)
	fuzzCrossOrigin        // admin session, cross-origin browser request
	fuzzFetchMeta          // admin session, Sec-Fetch-Site: cross-site
	fuzzForged             // admin cookie with a tampered signature (or a wrong bearer)
	fuzzModes
)

// FuzzAPIJSONDecoders drives every JSON-decoding endpoint through the real
// handler (auth, same-origin, size limits, decoders). Properties: no panic, no
// 500, and a 2xx only for an authorized, same-origin, in-limit, well-formed body.
func FuzzAPIJSONDecoders(f *testing.F) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	e := newEnv(f, func(c *Config) { c.KillKey, c.GatewayToken = priv, gwTok })
	dt := enrollDevice(f, e, dev)
	seeds := map[int][]string{
		0: {report("h1", "ring1-canary", "2.1.0", false), `{"hostname":""}`, `{"hostname":"h","harnesses":{"":{}}}`},
		1: {`{"token":"TOKEN"}`, `{"token":"TOKEN","os":"windows"}`, `{"token":""}`, `{}`},
		2: {`{"reason":"error spike"}`, `{"reason":"  "}`, ``, `{`},
		3: {`{"reason":"fixed"}`, ``, `null`},
		4: {`{"reason":"bad MCP"}`},
		5: {`{"reason":"x","default":true}`},
		6: {`{"kind":"mcp-server","item":"jira","justification":"need it"}`, `{"kind":"ring-opt-in","item":"ring1-canary","justification":"x"}`},
		7: {`{"status":"paused"}`, `{"status":"draft"}`, `{"status":"running"}`},
	}
	for ep, bodies := range seeds {
		for _, b := range bodies {
			for mode := range uint8(fuzzModes) {
				f.Add(uint8(ep), mode, []byte(b))
			}
		}
	}
	forged := e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix()})
	forged = forged[:len(forged)-2] + "AA"
	f.Fuzz(func(t *testing.T, epi, mode uint8, body []byte) {
		ep := fuzzEndpoints[int(epi)%len(fuzzEndpoints)]
		mode %= fuzzModes
		for _, l := range []*authLimiter{&e.s.authFails, &e.s.loginFails} { // each input starts with a clean budget
			l.mu.Lock()
			l.m = nil
			l.mu.Unlock()
		}
		enrollTok := ""
		if bytes.Contains(body, []byte("TOKEN")) {
			enrollTok = decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
			body = bytes.ReplaceAll(body, []byte("TOKEN"), []byte(enrollTok))
		}
		r := httptest.NewRequest("POST", ep.path, bytes.NewReader(body))
		cookie := func(p Principal) {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Exp: e.now.Add(time.Hour).Unix()})})
		}
		bearerAuth := ep.path == "/api/v1/fleet/report"
		switch {
		case bearerAuth && mode == fuzzDev:
			r.Header.Set("Authorization", "Bearer "+tok)
		case bearerAuth && mode == fuzzAdmin:
			r.Header.Set("Authorization", "Bearer "+dt)
		case bearerAuth && mode != fuzzNone:
			r.Header.Set("Authorization", "Bearer "+dt+"x")
		case mode == fuzzDev:
			cookie(dev)
		case mode == fuzzAdmin:
			cookie(admin)
		case mode == fuzzCrossOrigin:
			cookie(admin)
			r.Header.Set("Origin", "https://evil.example")
		case mode == fuzzFetchMeta:
			cookie(admin)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		case mode == fuzzForged:
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: forged})
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)

		if w.Code == http.StatusInternalServerError {
			t.Fatalf("%s mode %d: 500 %s", ep.path, mode, w.Body)
		}
		if w.Code/100 != 2 {
			return
		}
		authorized := false
		switch {
		case ep.path == "/api/v1/enroll":
			authorized = true // the token in the body is the credential, checked by ok
		case bearerAuth:
			authorized = mode == fuzzDev || mode == fuzzAdmin
		case ep.admin:
			authorized = mode == fuzzAdmin
		default:
			authorized = mode == fuzzDev || mode == fuzzAdmin
		}
		switch {
		case !authorized:
			t.Fatalf("%s mode %d: %d for an unauthorized or cross-site request", ep.path, mode, w.Code)
		case len(body) > ep.limit:
			t.Fatalf("%s: %d for a %d-byte body (limit %d)", ep.path, w.Code, len(body), ep.limit)
		case !ep.ok(body, enrollTok):
			t.Fatalf("%s mode %d: %d for malformed body %q", ep.path, mode, w.Code, body)
		}
		if ep.path == "/api/v1/enroll" && bytes.Contains(w.Body.Bytes(), []byte(enrollTok)) {
			t.Fatal("enrollment response echoes the enrollment token")
		}
	})
}

// FuzzKillListSigned: kills and unkills through the admin API, then the signed
// list from the gateway endpoint. The list verifies under the kill key, names
// exactly what was killed, and any change to payload, signature, key, token or
// freshness is refused. A 2xx kill only ever happens for a valid, known name.
func FuzzKillListSigned(f *testing.F) {
	org, err := policy.Load("../../examples/acme-corp")
	if err != nil {
		f.Fatal(err)
	}
	var exps, toggles []string
	for _, x := range org.Experiments {
		exps = append(exps, x.Name)
	}
	for _, x := range org.Toggles {
		toggles = append(toggles, x.Name)
	}
	f.Add("", []byte{0, 1, 2, 3}, "error spike", uint32(0), byte(1))
	f.Add("opus-5-5-canary,gone,toggle:github-mcp,Bad Name", []byte{0x10, 0x01, 0x22, 0x33, 0x40}, "r", uint32(7), byte('x'))
	f.Add("a/b,..,-x,"+strings.Repeat("a", 70), []byte{0x04, 0x05, 0x06, 0x07}, " ", uint32(99), byte(0))
	f.Fuzz(func(t *testing.T, nameCSV string, ops []byte, reason string, tamperAt uint32, tamperByte byte) {
		if len(ops) > 16 {
			ops = ops[:16]
		}
		clock := &testClock{}
		clock.ns.Store(ksNow.UnixNano())
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now: clock.Now, DevUser: "alice@test", DevAdmin: true, KillKey: priv, GatewayToken: gwTok})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		h := s.Handler()
		names := strings.Split(nameCSV, ",")
		killedExp, killedTog := map[string]bool{}, map[string]bool{}
		for _, op := range ops {
			kill, toggle := op&1 == 0, op&2 != 0
			pool := exps
			if toggle {
				pool = toggles
			}
			name := pool[int(op>>3)%len(pool)]
			if op&4 != 0 {
				name = names[int(op>>3)%len(names)]
			}
			kind, verb := "experiments", "unkill"
			if toggle {
				kind = "toggles"
			}
			if kill {
				verb = "kill"
			}
			body, _ := json.Marshal(map[string]string{"reason": reason})
			w := do(h, "POST", "/api/v1/"+kind+"/"+url.PathEscape(name)+"/"+verb, "", string(body))
			if w.Code == http.StatusInternalServerError {
				t.Fatalf("%s %s %q: 500 %s", verb, kind, name, w.Body)
			}
			if w.Code != 200 {
				continue
			}
			known := slices.Contains(pool, name)
			if !policy.ValidName(name) || (kill && (!known || strings.TrimSpace(reason) == "")) {
				t.Fatalf("%s %s %q (reason %q): 200", verb, kind, name, reason)
			}
			set := killedExp
			if toggle {
				set = killedTog
			}
			if kill {
				set[name] = true
			} else {
				delete(set, name)
			}
		}
		clock.Advance(time.Second)
		if c := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok+"x", "").Code; c != http.StatusUnauthorized {
			t.Fatalf("wrong gateway token: %d", c)
		}
		w := do(h, "GET", "/api/v1/gateway/killswitch", "Bearer "+gwTok, "")
		var env gateway.KillEnvelope
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &env) != nil {
			t.Fatalf("gateway list: %d %s", w.Code, w.Body)
		}
		now := clock.Now()
		l, err := gateway.VerifyKillList(pub, env, now, gateway.DefaultKillMaxAge)
		if err != nil {
			t.Fatalf("server-signed list does not verify: %v", err)
		}
		asSet := func(xs []string) map[string]bool {
			m := map[string]bool{}
			for _, x := range xs {
				m[x] = true
			}
			return m
		}
		if got := asSet(l.Experiments); len(got) != len(l.Experiments) || !mapsEqual(got, killedExp) {
			t.Fatalf("experiments %v, want %v", l.Experiments, killedExp)
		}
		if got := asSet(l.Toggles); len(got) != len(l.Toggles) || !mapsEqual(got, killedTog) {
			t.Fatalf("toggles %v, want %v", l.Toggles, killedTog)
		}
		// Tampering with any byte of payload or signature, another key, or a stale clock: refused.
		for _, part := range [][]byte{env.Payload, env.Signature} {
			i := int(tamperAt) % len(part)
			if part[i] == tamperByte {
				continue
			}
			old := part[i]
			part[i] = tamperByte
			if _, err := gateway.VerifyKillList(pub, env, now, gateway.DefaultKillMaxAge); err == nil {
				t.Fatalf("tampered envelope verified (byte %d %q->%q)", i, old, tamperByte)
			}
			part[i] = old
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := gateway.VerifyKillList(other, env, now, gateway.DefaultKillMaxAge); err == nil {
			t.Fatal("verified under another key")
		}
		if _, err := gateway.VerifyKillList(pub, env, now.Add(gateway.DefaultKillMaxAge+time.Second), gateway.DefaultKillMaxAge); err == nil {
			t.Fatal("stale list verified")
		}
	})
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// FuzzAuditChainTamper: a chain written by the server, with one byte of the
// file changed, verifies only if what it reads back is semantically the
// original (or a prefix of it: tail truncation is the documented limit), and
// appending after reopen keeps a verifying chain.
func FuzzAuditChainTamper(f *testing.F) {
	f.Add("alice@acme.example,halo-controller", "error spike", uint8(2), uint32(10), byte('X'), int64(0))
	f.Add("boss@acme.example", "", uint8(0), uint32(0), byte('\n'), int64(1))
	f.Add("a,b,c,d", "<script>& ", uint8(4), uint32(300), byte('"'), int64(-123456789))
	f.Add("a", "\xff\xfe", uint8(1), uint32(77), byte('A'), int64(999999999))
	f.Fuzz(func(t *testing.T, actors, detail string, n uint8, pos uint32, b byte, tOff int64) {
		dir := t.TempDir()
		l := &auditLog{} // same hashing as on disk, without an fsync per entry
		names := strings.Split(actors, ",")
		base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(tOff % int64(50*365*24*time.Hour)))
		count := 1 + int(n%5)
		for i := range count {
			e := AuditEntry{Time: base.Add(time.Duration(i) * time.Second), Actor: names[i%len(names)], Action: "experiment.kill",
				Target: "exp", IP: "192.0.2.1", RequestID: "rid", Details: map[string]string{"reason": detail}}
			if err := l.append(e); err != nil {
				t.Fatal(err)
			}
		}
		var file bytes.Buffer // exactly what append writes: one JSON entry per line
		for _, e := range l.mem {
			b, _ := json.Marshal(e)
			file.Write(append(b, '\n'))
		}
		p := filepath.Join(dir, "audit.jsonl")
		if err := os.WriteFile(p, file.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		orig := readAudit(t, dir)
		if err := VerifyAuditChain(orig); err != nil || len(orig) != count {
			t.Fatalf("untampered chain: %d/%d entries, %v", len(orig), count, err)
		}

		data := file.Bytes()
		i := int(pos) % len(data)
		if data[i] == b {
			return
		}
		data[i] = b
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		got := readAudit(t, dir)
		if VerifyAuditChain(got) != nil {
			return
		}
		if len(got) > len(orig) {
			t.Fatalf("tampered chain verified with %d entries (had %d)", len(got), len(orig))
		}
		for k := range got {
			if got[k].Hash != orig[k].Hash || got[k].sum() != orig[k].Hash {
				t.Fatalf("byte %d %q->%q: entry %d changed yet the chain verifies:\n%+v\n%+v", i, data[i], b, k+1, orig[k], got[k])
			}
		}
		// Reopen (the server's restart path) and append: still one verifying chain.
		l2, err := openAuditLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := l2.append(AuditEntry{Time: base, Actor: "x", Action: "login"}); err != nil {
			t.Fatal(err)
		}
		_ = l2.close()
		if after := readAudit(t, dir); VerifyAuditChain(after) != nil || len(after) != len(got)+1 {
			t.Fatalf("append after reopen broke the chain: %d entries, %v", len(after), VerifyAuditChain(after))
		}
	})
}

// FuzzAuditChainParse: any audit.jsonl content opens and verifies without
// panicking; if it verifies, an append continues it (seq+1, prev = head).
func FuzzAuditChainParse(f *testing.F) {
	seedDir := f.TempDir()
	l, err := openAuditLog(seedDir)
	if err != nil {
		f.Fatal(err)
	}
	for i, a := range []string{"login", "experiment.kill", "device.enroll"} {
		if err := l.append(AuditEntry{Time: ksNow.Add(time.Duration(i) * time.Second), Actor: "alice", Action: a, Details: map[string]string{"reason": "r"}}); err != nil {
			f.Fatal(err)
		}
	}
	_ = l.close()
	valid, err := os.ReadFile(filepath.Join(seedDir, "audit.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)-5])                                        // torn tail
	f.Add(append([]byte("{}\n"), valid...))                            // junk first line
	f.Add(append(append([]byte{}, valid...), []byte("null\n[]\n")...)) // junk after
	f.Add([]byte(`{"seq":1,"prev":"","hash":""}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := openAuditLog(dir)
		if err != nil {
			return // e.g. a line over the scanner's 1 MiB cap: refused at startup, never misread
		}
		before, err := l.all()
		if err != nil {
			t.Fatal(err)
		}
		if VerifyAuditChain(before) != nil {
			_ = l.close()
			return
		}
		if err := l.append(AuditEntry{Time: ksNow, Actor: "x", Action: "login"}); err != nil {
			t.Fatal(err)
		}
		after, err := l.all()
		_ = l.close()
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyAuditChain(after); err != nil {
			t.Fatalf("append to a verified chain broke it: %v", err)
		}
		last := after[len(after)-1]
		if last.Seq != uint64(len(before))+1 || (len(before) > 0 && last.Prev != before[len(before)-1].Hash) {
			t.Fatalf("append did not continue the chain: seq %d prev %q", last.Seq, last.Prev)
		}
	})
}

func readAudit(t *testing.T, dir string) []AuditEntry {
	t.Helper()
	l, err := openAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.close() }()
	out, err := l.all()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
