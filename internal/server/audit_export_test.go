package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/controller"
)

// receiver is an HTTPS sink that records what it accepted.
type receiver struct {
	mu     sync.Mutex
	bodies [][]byte
	hdrs   []http.Header
	fail   int // answer 503 to this many requests first
	status int // when set, answer every request with it
}

func (rc *receiver) count() int { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.bodies) }

func (rc *receiver) start(t *testing.T) (url, caFile string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		defer rc.mu.Unlock()
		switch {
		case rc.status != 0:
			w.WriteHeader(rc.status)
		case rc.fail > 0:
			rc.fail--
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			rc.bodies, rc.hdrs = append(rc.bodies, b), append(rc.hdrs, r.Header.Clone())
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, caPEM(t, srv)
}

func caPEM(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// exporting starts RunAuditExport and stops it at cleanup (or when stop is called).
func exporting(t *testing.T, s *Server) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.RunAuditExport(ctx) }()
	stop = sync.OnceFunc(func() { cancel(); <-done })
	t.Cleanup(stop)
	return stop
}

// storedLines are the audit lines exactly as on disk, across segments.
func storedLines(t *testing.T, s *Server) [][]byte {
	t.Helper()
	snap, err := s.auditLog.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer snap.close()
	var out [][]byte
	if err := snap.from(0, func(raw []byte, _ AuditEntry) bool { out = append(out, bytes.Clone(raw)); return true }); err != nil {
		t.Fatal(err)
	}
	return out
}

var hashField = regexp.MustCompile(`"hash":"([0-9a-f]{64})"}$`)

// recomputeHash is the SIEM-side recipe from the guide: blank the trailing
// hash field of the raw line and sha256 it.
func recomputeHash(t *testing.T, raw []byte) (stated, computed string) {
	t.Helper()
	m := hashField.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("no trailing hash in %s", raw)
	}
	sum := sha256.Sum256(hashField.ReplaceAll(raw, []byte(`"hash":""}`)))
	return string(m[1]), hex.EncodeToString(sum[:])
}

func metrics(s *Server) string {
	var b strings.Builder
	s.WriteMetrics(&b)
	return b.String()
}

func TestAuditExportWebhook(t *testing.T) {
	var rc receiver
	u, ca := rc.start(t)
	secretFile := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(secretFile, []byte("hmac-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HALO_TEST_DD_KEY", "dd-api-key-value")
	dir := t.TempDir()
	e := newEnv(t, func(c *Config) {
		c.DataDir = dir
		c.Audit = AuditConfig{Rotation: AuditRotation{MaxBytes: 4096}, Export: AuditExport{BatchSize: 2, PollIntervalSeconds: 60, Sinks: []AuditSink{{
			Name: "dd", Type: "webhook", URL: u, CAFile: ca,
			Headers: map[string]SecretRef{"DD-API-KEY": {Env: "HALO_TEST_DD_KEY"}}, HMACSecret: &SecretRef{File: secretFile},
		}}}}
	})
	for i := range 3 {
		e.s.Audit(t.Context(), "alice", "experiment.kill", fmt.Sprint("exp", i), map[string]string{"reason": "r"})
	}
	exporting(t, e.s)
	waitFor(t, "3 entries", func() bool { return rc.count() == 2 }) // batches of 2: [1,2] [3]
	for i := 3; i < 30; i++ {                                       // wakes on append (poll is 60s) and crosses a rotation
		e.s.Audit(t.Context(), "alice", "experiment.kill", fmt.Sprint("exp", i), map[string]string{"reason": strings.Repeat("r", 100)})
	}
	if segs := segFiles(t, dir); len(segs) == 0 {
		t.Fatal("expected a rotation")
	}
	var got [][]byte
	waitFor(t, "30 entries", func() bool {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		got = got[:0]
		for i, b := range rc.bodies {
			if err := controller.Verify([]byte("hmac-secret-value"), rc.hdrs[i], b, time.Now(), controller.WebhookTolerance); err != nil {
				t.Errorf("signature: %v", err)
			}
			if rc.hdrs[i].Get("DD-API-KEY") != "dd-api-key-value" || rc.hdrs[i].Get("Content-Type") != "application/json" {
				t.Errorf("headers: %v", rc.hdrs[i])
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(b, &arr); err != nil {
				t.Fatalf("body is not a JSON array: %s", b)
			}
			for _, r := range arr {
				got = append(got, r)
			}
		}
		return len(got) >= 30
	})
	want := storedLines(t, e.s)
	if len(got) != len(want) {
		t.Fatalf("delivered %d, stored %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("event %d is not the stored line:\n%s\n%s", i, got[i], want[i])
		}
		if stated, computed := recomputeHash(t, got[i]); stated != computed {
			t.Fatalf("event %d: SIEM-side hash recipe %s != %s", i, computed, stated)
		}
	}
	cur, _ := os.ReadFile(filepath.Join(dir, "audit-forward", "dd.json"))
	var c auditCursor
	if json.Unmarshal(cur, &c) != nil || c.Seq != 30 || c.Hash != e.s.auditLog.head {
		t.Fatalf("cursor %s", cur)
	}
	m := metrics(e.s)
	for _, w := range []string{`halo_server_audit_forward_sent_total{sink="dd"} 30`, `halo_server_audit_forward_lag_entries{sink="dd"} 0`,
		`halo_server_audit_forward_failed_total{sink="dd"} 0`, "halo_server_audit_rotate_errors_total 0"} {
		if !strings.Contains(m, w) {
			t.Errorf("metrics missing %q:\n%s", w, m)
		}
	}
}

func TestAuditExportRetriesThenResumesWithoutResending(t *testing.T) {
	rc := receiver{fail: 2}
	u, ca := rc.start(t)
	dir := t.TempDir()
	sink := AuditSink{Name: "hook", Type: "webhook", URL: u, CAFile: ca}
	cfg := func(c *Config) {
		c.DataDir = dir
		c.Audit.Export = AuditExport{MaxBackoffSeconds: 1, PollIntervalSeconds: 60, Sinks: []AuditSink{sink}}
	}
	e := newEnv(t, cfg)
	for i := range 3 {
		e.s.Audit(t.Context(), "alice", "device.revoke", fmt.Sprint(i), nil)
	}
	if m := metrics(e.s); !strings.Contains(m, `halo_server_audit_forward_lag_entries{sink="hook"} 3`) {
		t.Fatalf("lag before export:\n%s", m)
	}
	stop := exporting(t, e.s)
	waitFor(t, "delivery after retries", func() bool { return rc.count() == 1 })
	stop()
	if m := metrics(e.s); !strings.Contains(m, `halo_server_audit_forward_failed_total{sink="hook"} 2`) ||
		!strings.Contains(m, `halo_server_audit_forward_sent_total{sink="hook"} 3`) {
		t.Fatalf("metrics after retries:\n%s", m)
	}
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}

	// restart on the same data dir: the cursor resumes after seq 3
	e2 := newEnv(t, cfg)
	e2.s.Audit(t.Context(), "alice", "device.revoke", "3", nil)
	exporting(t, e2.s)
	waitFor(t, "post-restart delivery", func() bool { return rc.count() == 2 })
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var evs []AuditEntry
	if err := json.Unmarshal(rc.bodies[1], &evs); err != nil || len(evs) != 1 || evs[0].Seq != 4 || evs[0].Prev == "" {
		t.Fatalf("after restart sent %s (%v)", rc.bodies[1], err)
	}
}

func TestAuditExportSplunkHECOCSF(t *testing.T) {
	var rc receiver
	u, ca := rc.start(t)
	t.Setenv("HALO_TEST_HEC", "hec-token-value")
	e := newEnv(t, func(c *Config) {
		c.DataDir = t.TempDir()
		c.Audit.Export.Sinks = []AuditSink{{Name: "splunk", Type: "splunk-hec", Format: "ocsf", URL: u + "/services/collector/event", CAFile: ca,
			Token: &SecretRef{Env: "HALO_TEST_HEC"}, Index: "security"}}
	})
	e.s.Audit(withReqMeta(t.Context(), reqMeta{ip: "203.0.113.9", id: "req-1"}), "boss@acme.example", "experiment.kill", "exp1", map[string]string{"reason": "spike"})
	e.s.Audit(t.Context(), "boss@acme.example", "session.revoke", "", nil)
	exporting(t, e.s)
	waitFor(t, "HEC delivery", func() bool { return rc.count() == 1 })
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if a := rc.hdrs[0].Get("Authorization"); a != "Splunk hec-token-value" {
		t.Fatalf("authorization %q", a)
	}
	type hec struct {
		Time       float64         `json:"time"`
		Source     string          `json:"source"`
		SourceType string          `json:"sourcetype"`
		Index      string          `json:"index"`
		Event      ocsfAPIActivity `json:"event"`
	}
	dec := json.NewDecoder(bytes.NewReader(rc.bodies[0]))
	var evs []hec
	for dec.More() {
		var h hec
		if err := dec.Decode(&h); err != nil {
			t.Fatalf("HEC body %s: %v", rc.bodies[0], err)
		}
		evs = append(evs, h)
	}
	if len(evs) != 2 {
		t.Fatalf("%d HEC events", len(evs))
	}
	h, o := evs[0], evs[0].Event
	if h.Source != "halo-server" || h.SourceType != "halo:audit" || h.Index != "security" || int64(h.Time) != e.now.Unix() {
		t.Errorf("HEC envelope %+v", h)
	}
	if o.ClassUID != 6003 || o.CategoryUID != 6 || o.TypeUID != 600399 || o.ActivityName != "experiment.kill" || o.Time != e.now.UnixMilli() ||
		o.Actor.User.UID != "boss@acme.example" || o.API.Operation != "experiment.kill" || o.API.Request == nil || o.API.Request.UID != "req-1" ||
		o.SrcEndpoint == nil || o.SrcEndpoint.IP != "203.0.113.9" || len(o.Resources) != 1 || o.Resources[0].Name != "exp1" ||
		o.Metadata.Sequence != 1 || o.Metadata.UID != o.Unmapped.Hash || o.Unmapped.Prev != "" || o.Unmapped.Details["reason"] != "spike" {
		t.Errorf("OCSF mapping %+v", o)
	}
	if o2 := evs[1].Event; o2.Unmapped.Prev != o.Unmapped.Hash || o2.SrcEndpoint != nil || o2.Resources != nil || o2.API.Request != nil {
		t.Errorf("second event does not chain or carries empty objects: %+v", o2)
	}
	if stated, computed := recomputeHash(t, []byte(o.RawData)); stated != computed || stated != o.Unmapped.Hash {
		t.Errorf("raw_data hash %s, recomputed %s", stated, computed)
	}
}

func TestAuditExportSyslogTLS(t *testing.T) {
	borrow := httptest.NewTLSServer(http.NotFoundHandler()) // for its localhost certificate
	t.Cleanup(borrow.Close)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: borrow.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	msgs := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				for {
					n, err := br.ReadString(' ')
					if err != nil {
						return
					}
					size, err := strconv.Atoi(strings.TrimSpace(n))
					if err != nil {
						msgs <- "bad frame: " + n
						return
					}
					b := make([]byte, size)
					if _, err := io.ReadFull(br, b); err != nil {
						return
					}
					msgs <- string(b)
				}
			}()
		}
	}()
	e := newEnv(t, func(c *Config) {
		c.DataDir = t.TempDir()
		c.Audit.Export.Sinks = []AuditSink{{Name: "syslog", Type: "syslog", Address: ln.Addr().String(), CAFile: caPEM(t, borrow)}}
	})
	e.s.Audit(t.Context(), "alice", "experiment.kill", "exp1", map[string]string{"reason": "r"})
	e.s.Audit(t.Context(), "alice", "experiment.unkill", "exp1", nil)
	exporting(t, e.s)
	want := storedLines(t, e.s)
	for i := range 2 {
		select {
		case m := <-msgs:
			prefix := "<110>1 2026-01-02T03:04:05Z "
			if !strings.HasPrefix(m, prefix) || !strings.Contains(m, " halo-server - audit - ") || !strings.HasSuffix(m, " - "+string(want[i])) {
				t.Fatalf("syslog message %d: %q", i, m)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("no syslog message")
		}
	}
}

func TestAuditExportHaltsOnBrokenChain(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(t *testing.T, dir string)
		sent   int
	}{
		{"edited entry", func(t *testing.T, dir string) {
			p := filepath.Join(dir, auditActive)
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, bytes.Replace(b, []byte(`"target":"1"`), []byte(`"target":"X"`), 1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"deleted entry", func(t *testing.T, dir string) {
			p := filepath.Join(dir, auditActive)
			b, _ := os.ReadFile(p)
			lines := bytes.SplitAfter(b, []byte("\n"))
			if err := os.WriteFile(p, bytes.Join(append(lines[:1:1], lines[2:]...), nil), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"cursor ahead of a restored log", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "audit-forward", "hook.json"), []byte(`{"seq":3,"hash":"elsewhere"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var rc receiver
			u, ca := rc.start(t)
			dir := t.TempDir()
			cfg := func(cf *Config) {
				cf.DataDir = dir
				cf.Audit.Export = AuditExport{MaxBackoffSeconds: 1, PollIntervalSeconds: 1, Sinks: []AuditSink{{Name: "hook", Type: "webhook", URL: u, CAFile: ca}}}
			}
			e := newEnv(t, cfg)
			for i := range 3 {
				e.s.Audit(t.Context(), "alice", "device.revoke", fmt.Sprint(i), nil)
			}
			if err := e.s.Close(); err != nil {
				t.Fatal(err)
			}
			if c.name == "cursor ahead of a restored log" {
				// the restored log is shorter than what was delivered, then grows past it with other entries
				if err := os.Remove(filepath.Join(dir, auditActive)); err != nil {
					t.Fatal(err)
				}
				l, err := openAuditLog(dir)
				if err != nil {
					t.Fatal(err)
				}
				appendN(t, l, 0, 2, func(int) time.Time { return ksNow })
				_ = l.close()
			}
			c.tamper(t, dir)
			e2 := newEnv(t, cfg)
			exporting(t, e2.s)
			waitFor(t, "a failed attempt", func() bool { return e2.s.forwarders[0].failed.Load() >= 1 })
			if c.name == "cursor ahead of a restored log" {
				e2.s.Audit(t.Context(), "alice", "device.revoke", "3", nil) // head == cursor seq, different hash
				f := e2.s.forwarders[0].failed.Load()
				waitFor(t, "another failed attempt", func() bool { return e2.s.forwarders[0].failed.Load() > f })
			}
			var sent int
			rc.mu.Lock()
			for _, b := range rc.bodies {
				var evs []AuditEntry
				_ = json.Unmarshal(b, &evs)
				sent += len(evs)
			}
			rc.mu.Unlock()
			if sent != c.sent {
				t.Fatalf("sent %d entries past a broken chain, want %d", sent, c.sent)
			}
		})
	}
}

func TestAuditExportSecretsNeverLogged(t *testing.T) {
	rc := receiver{status: http.StatusUnauthorized}
	u, ca := rc.start(t)
	t.Setenv("HALO_TEST_HDR", "header-secret-value")
	t.Setenv("HALO_TEST_HEC", "hec-secret-value")
	hm := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(hm, []byte("hmac-secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	var mu sync.Mutex
	e := newEnv(t, func(c *Config) {
		c.DataDir = t.TempDir()
		c.Log = slog.New(slog.NewTextHandler(lockedWriter{&mu, &logs}, nil))
		c.Audit.Export = AuditExport{MaxBackoffSeconds: 1, Sinks: []AuditSink{
			{Name: "hook", Type: "webhook", URL: u + "/in?token=url-secret-value", CAFile: ca, Headers: map[string]SecretRef{"X-Api-Key": {Env: "HALO_TEST_HDR"}}, HMACSecret: &SecretRef{File: hm}},
			{Name: "hec", Type: "splunk-hec", URL: u, CAFile: ca, Token: &SecretRef{Env: "HALO_TEST_HEC"}},
		}}
	})
	e.s.Audit(t.Context(), "alice", "device.revoke", "d", nil)
	exporting(t, e.s)
	waitFor(t, "failures on both sinks", func() bool { return e.s.forwarders[0].failed.Load() >= 1 && e.s.forwarders[1].failed.Load() >= 1 })
	mu.Lock()
	out := logs.String() + metrics(e.s)
	mu.Unlock()
	if !strings.Contains(out, "HTTP 401") {
		t.Fatalf("failure not logged:\n%s", out)
	}
	for _, s := range []string{"header-secret-value", "hec-secret-value", "hmac-secret-value", "url-secret-value"} {
		if strings.Contains(out, s) {
			t.Errorf("secret %q leaked:\n%s", s, out)
		}
	}
	// config and resolution errors name the reference, never the value
	bad := AuditSink{Name: "x", Type: "webhook", URL: "http://h/?token=url-secret-value"}
	if err := bad.validate(); err == nil || strings.Contains(err.Error(), "url-secret-value") {
		t.Errorf("validate: %v", err)
	}
	if _, err := (SecretRef{Env: "HALO_TEST_UNSET_VAR"}).resolve("token"); err == nil || !strings.Contains(err.Error(), "HALO_TEST_UNSET_VAR") {
		t.Errorf("unset env: %v", err)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestAuditConfigValidate(t *testing.T) {
	hook := func(mut func(*AuditSink)) AuditConfig {
		s := AuditSink{Name: "hook", Type: "webhook", URL: "https://siem.example/in"}
		mut(&s)
		return AuditConfig{Export: AuditExport{Sinks: []AuditSink{s}}}
	}
	env := &SecretRef{Env: "X"}
	for _, c := range []struct {
		name string
		cfg  AuditConfig
		err  string
	}{
		{"empty", AuditConfig{}, ""},
		{"webhook", hook(func(s *AuditSink) { s.Headers = map[string]SecretRef{"DD-API-KEY": *env}; s.HMACSecret = env }), ""},
		{"hec", hook(func(s *AuditSink) { s.Type, s.Token, s.Format, s.Index = "splunk-hec", env, "ocsf", "main" }), ""},
		{"syslog", hook(func(s *AuditSink) { s.Type, s.URL, s.Address, s.Facility = "syslog", "", "siem.example:6514", 10 }), ""},
		{"mtls", hook(func(s *AuditSink) { s.CertFile, s.KeyFile = "c", "k" }), ""},
		{"rotation", AuditConfig{Rotation: AuditRotation{MaxBytes: 64 << 20, MaxAgeSeconds: 86400}}, ""},
		{"tiny rotation", AuditConfig{Rotation: AuditRotation{MaxBytes: 10}}, "at least 4096"},
		{"negative rotation", AuditConfig{Rotation: AuditRotation{MaxAgeSeconds: -1}}, ">= 0"},
		{"batch", AuditConfig{Export: AuditExport{BatchSize: 5000}}, "batchSize"},
		{"bad name", hook(func(s *AuditSink) { s.Name = "Bad/Name" }), "name must match"},
		{"duplicate", AuditConfig{Export: AuditExport{Sinks: []AuditSink{hook(func(*AuditSink) {}).Export.Sinks[0], hook(func(*AuditSink) {}).Export.Sinks[0]}}}, "duplicate"},
		{"type", hook(func(s *AuditSink) { s.Type = "kafka" }), "type must be"},
		{"format", hook(func(s *AuditSink) { s.Format = "cef" }), "format must be"},
		{"cleartext", hook(func(s *AuditSink) { s.URL = "http://siem.example/in" }), "https"},
		{"no host", hook(func(s *AuditSink) { s.URL = "https:///in" }), "https"},
		{"hec without token", hook(func(s *AuditSink) { s.Type = "splunk-hec" }), "needs token"},
		{"hec with hmac", hook(func(s *AuditSink) { s.Type, s.Token, s.HMACSecret = "splunk-hec", env, env }), "webhook-only"},
		{"webhook with token", hook(func(s *AuditSink) { s.Token = env }), "splunk-hec-only"},
		{"webhook with address", hook(func(s *AuditSink) { s.Address = "h:1" }), "syslog-only"},
		{"reserved header", hook(func(s *AuditSink) { s.Headers = map[string]SecretRef{"x-halo-signature": *env} }), "reserved"},
		{"content-type header", hook(func(s *AuditSink) { s.Headers = map[string]SecretRef{"content-type": *env} }), "reserved"},
		{"bad header", hook(func(s *AuditSink) { s.Headers = map[string]SecretRef{"a b": *env} }), "invalid"},
		{"secret both", hook(func(s *AuditSink) { s.HMACSecret = &SecretRef{Env: "X", File: "f"} }), "exactly one"},
		{"secret none", hook(func(s *AuditSink) { s.Headers = map[string]SecretRef{"K": {}} }), "exactly one"},
		{"cert without key", hook(func(s *AuditSink) { s.CertFile = "c" }), "together"},
		{"syslog address", hook(func(s *AuditSink) { s.Type, s.URL, s.Address = "syslog", "", "siem.example" }), "host:port"},
		{"syslog url", hook(func(s *AuditSink) { s.Type, s.Address = "syslog", "h:1" }), "address"},
		{"syslog facility", hook(func(s *AuditSink) { s.Type, s.URL, s.Address, s.Facility = "syslog", "", "h:1", 24 }), "facility"},
		{"timeout", hook(func(s *AuditSink) { s.TimeoutSeconds = -1 }), "timeoutSeconds"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
				t.Fatalf("Validate() = %v, want %q", err, c.err)
			}
		})
	}
}

func TestParseAuditConfig(t *testing.T) {
	c, err := ParseAuditConfig(strings.NewReader(`{"rotation":{"maxBytes":67108864},"export":{"sinks":[{"name":"s","type":"splunk-hec","url":"https://h/services/collector/event","token":{"file":"/t"}}]}}`))
	if err != nil || c.Rotation.MaxBytes != 64<<20 || c.Export.Sinks[0].Token.File != "/t" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{`{"rotation":{"maxbytes":1}}`, `{"export":{"sinks":[{"name":"s","type":"webhook","url":"https://h","token":"literal"}]}}`, `[]`} {
		if _, err := ParseAuditConfig(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSecretRefResolve(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "s")
	empty := filepath.Join(dir, "e")
	_ = os.WriteFile(f, []byte("  value\n"), 0o600)
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	t.Setenv("HALO_TEST_SECRET", "env-value")
	t.Setenv("HALO_TEST_EMPTY", "")
	for _, c := range []struct {
		ref       SecretRef
		want, err string
	}{
		{SecretRef{Env: "HALO_TEST_SECRET"}, "env-value", ""},
		{SecretRef{File: f}, "value", ""},
		{SecretRef{Env: "HALO_TEST_EMPTY"}, "", "empty"},
		{SecretRef{File: empty}, "", "empty"},
		{SecretRef{Env: "HALO_TEST_NOPE"}, "", "not set"},
		{SecretRef{File: filepath.Join(dir, "missing")}, "", "no such file"},
	} {
		got, err := c.ref.resolve("token")
		if got != c.want || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%+v: %q, %v", c.ref, got, err)
		}
	}
}

func TestAuditExportNeedsDataDirAndResolvableSecrets(t *testing.T) {
	base := Config{Token: tok, DevUser: "u"}
	sink := AuditSink{Name: "s", Type: "splunk-hec", URL: "https://h/x", Token: &SecretRef{Env: "HALO_TEST_NOPE"}}
	base.Audit.Export.Sinks = []AuditSink{sink}
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "data dir") {
		t.Fatalf("export without data dir: %v", err)
	}
	base.DataDir = t.TempDir()
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "HALO_TEST_NOPE") {
		t.Fatalf("unresolvable secret: %v", err)
	}
	sink.Token, sink.CAFile = &SecretRef{Env: "HOME"}, filepath.Join(base.DataDir, "nope.pem")
	base.Audit.Export.Sinks = []AuditSink{sink}
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "caFile") {
		t.Fatalf("missing CA: %v", err)
	}
}

func TestSyslogHost(t *testing.T) {
	for in, want := range map[string]string{"": "-", "web 1": "web1", "h\u00e9st": "hst", strings.Repeat("a", 300): strings.Repeat("a", 255)} {
		if got := syslogHost(in); got != want {
			t.Errorf("syslogHost(%q) = %q", in, got)
		}
	}
}
