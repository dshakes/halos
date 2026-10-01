package shadow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/policy"
)

type memStore struct {
	mu    sync.Mutex
	pairs []Pair
}

func (m *memStore) Append(ctx context.Context, p Pair) error {
	if err := ctx.Err(); err != nil { // same contract as FileStore
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pairs = append(m.pairs, p)
	return nil
}
func (m *memStore) n() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.pairs) }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

// rec is what a fake upstream saw.
type rec struct {
	mu     sync.Mutex
	hits   int
	hdr    http.Header
	path   string
	stream any
}

func (r *rec) get() (int, http.Header, string, any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits, r.hdr, r.path, r.stream
}

// upstream echoes the model it saw and reports usage.
func upstream(t *testing.T, in, out int) (*httptest.Server, *rec) {
	t.Helper()
	rc := &rec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		rc.mu.Lock()
		rc.hits++
		rc.hdr, rc.path, rc.stream = r.Header.Clone(), r.URL.EscapedPath(), b["stream"]
		rc.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"model": b["model"], "usage": map[string]any{"input_tokens": in, "output_tokens": out}})
	}))
	t.Cleanup(srv.Close)
	return srv, rc
}

// testOrg: alias "sonnet" -> ctl upstream (ctl-model); shadow experiment
// "exp" variant "cand" -> cand upstream (cand-model).
func testOrg(ctlURL, candURL string) *policy.Org {
	return &policy.Org{
		Gateway: &policy.Gateway{
			Models:    map[string]policy.ModelRoute{"sonnet": {Upstream: "ctl", Model: "ctl-model"}},
			Upstreams: map[string]policy.Upstream{"ctl": {URL: ctlURL}, "cand": {URL: candURL}},
		},
		Experiments: []*policy.Experiment{{
			Meta: policy.Meta{Name: "exp"}, Type: policy.ExperimentShadow, Status: "running",
			Variants: []policy.Variant{{Name: "control", Control: true}, {Name: "cand", Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "cand", Model: "cand-model"}}}},
		}},
	}
}

func orgFn(o *policy.Org) func() (*policy.Org, error) {
	return func() (*policy.Org, error) { return o, nil }
}

func postRaw(h http.Handler, tok string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/mirror", bytes.NewReader(body))
	r.Header.Set(TokenHeader, tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func post(h http.Handler, tok string, j Job) *httptest.ResponseRecorder {
	b, _ := json.Marshal(j)
	return postRaw(h, tok, b)
}

func job() Job {
	return Job{Experiment: "exp", Variant: "cand", Protocol: "anthropic-messages", Method: "POST", Path: "/v1/messages", SessionID: "s",
		Headers: map[string]string{"Anthropic-Version": "2023-06-01", "Authorization": "Bearer leaked", "X-Api-Key": "leak"},
		Body:    json.RawMessage(`{"model":"sonnet","stream":true,"messages":[{"role":"user","content":"hi"}]}`)}
}

func metrics(t *testing.T, h http.Handler, tok string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set(TokenHeader, tok)
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String()
}

func TestPairCaptured(t *testing.T) {
	ctl, ctlSeen := upstream(t, 10, 20)
	cand, candSeen := upstream(t, 11, 22)
	st := &memStore{}
	s := New(Config{Token: "tok", Policy: orgFn(testOrg(ctl.URL, cand.URL)),
		UpstreamHeaders: map[string]map[string]string{"ctl": {"X-Api-Key": "ctl-key"}, "cand": {"X-Api-Key": "cand-key"}},
		PriceInPerMTok:  1e6, PriceOutPerMTok: 0, BudgetUSD: 1e12}, st)
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	if w := post(s.Handler(), "tok", job()); w.Code != http.StatusAccepted {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	waitFor(t, func() bool { return st.n() == 1 })
	cancel()
	s.Wait()
	p := st.pairs[0]
	if !strings.Contains(string(p.Control.Response), "ctl-model") || !strings.Contains(string(p.Candidate.Response), "cand-model") {
		t.Fatalf("models not rewritten: %s / %s", p.Control.Response, p.Candidate.Response)
	}
	if p.Control.Target.Upstream != "ctl" || p.Candidate.Target != (Target{Variant: "cand", Upstream: "cand", Model: "cand-model"}) {
		t.Fatalf("targets %+v / %+v", p.Control.Target, p.Candidate.Target)
	}
	_, hdr, path, stream := ctlSeen.get()
	if stream != false || path != "/v1/messages" {
		t.Fatalf("stream=%v path=%s", stream, path)
	}
	if hdr.Get("Authorization") != "" || hdr.Get("X-Api-Key") != "ctl-key" || hdr.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("header handling: %v", hdr)
	}
	// Per-upstream credentials: each host only ever sees its own key.
	if _, ch, _, _ := candSeen.get(); ch.Get("X-Api-Key") != "cand-key" {
		t.Fatalf("candidate got key %q", ch.Get("X-Api-Key"))
	}
	// The pair records actual cost; spend is charged at max(actual, reserved
	// estimate) so a response without usage can't make a job free.
	est := 2 * s.estimate(job().Body)
	if p.CostUSD != 21 || p.Candidate.OutputTokens != 22 || s.Spent() != max(21, est) {
		t.Fatalf("cost=%v spent=%v est=%v", p.CostUSD, s.Spent(), est)
	}
	if !strings.Contains(string(p.Request), `"sonnet"`) {
		t.Fatal("request should keep original body")
	}
}

func TestJobValidation(t *testing.T) {
	ctl, ctlSeen := upstream(t, 1, 1)
	cand, candSeen := upstream(t, 1, 1)
	org := testOrg(ctl.URL, cand.URL)
	s := New(Config{Token: "tok", Policy: orgFn(org)}, &memStore{})
	mut := func(f func(*Job)) Job { j := job(); f(&j); return j }
	for name, tc := range map[string]struct {
		tok  string
		j    Job
		want int
	}{
		"bad token":         {"nope", job(), 401},
		"empty job":         {"tok", Job{}, 400},
		"GET":               {"tok", mut(func(j *Job) { j.Method = "GET" }), 400},
		"userinfo path":     {"tok", mut(func(j *Job) { j.Path = "@evil.tld/v1/messages" }), 400},
		"absolute url path": {"tok", mut(func(j *Job) { j.Path = "http://evil.tld/v1/messages" }), 400},
		"dotdot path":       {"tok", mut(func(j *Job) { j.Path = "/v1/messages/../../x" }), 400},
		"count_tokens":      {"tok", mut(func(j *Job) { j.Path = "/v1/messages/count_tokens" }), 400},
		"protocol mismatch": {"tok", mut(func(j *Job) { j.Protocol = "openai-responses" }), 400},
		"unknown alias":     {"tok", mut(func(j *Job) { j.Body = json.RawMessage(`{"model":"opus","messages":[]}`) }), 400},
		"unknown exp":       {"tok", mut(func(j *Job) { j.Experiment = "nope" }), 400},
		"control variant":   {"tok", mut(func(j *Job) { j.Variant = "control" }), 400},
		"unknown variant":   {"tok", mut(func(j *Job) { j.Variant = "nope" }), 400},
	} {
		if w := post(s.Handler(), tc.tok, tc.j); w.Code != tc.want {
			t.Errorf("%s: %d want %d (%s)", name, w.Code, tc.want, w.Body)
		}
	}
	// Attacker-supplied upstream fields (the old job shape) are refused outright.
	evil, evilSeen := upstream(t, 1, 1)
	b, _ := json.Marshal(job())
	b = bytes.Replace(b, []byte(`{"experiment"`), []byte(fmt.Sprintf(`{"control":{"upstream":%q,"model":"x"},"candidate":{"upstream":%q},"experiment"`, evil.URL, evil.URL)), 1)
	if w := postRaw(s.Handler(), "tok", b); w.Code != 400 {
		t.Fatalf("job with upstream fields: %d", w.Code)
	}
	if w := post(New(Config{Policy: orgFn(org)}, &memStore{}).Handler(), "", job()); w.Code != 401 {
		t.Errorf("empty configured token must fail closed, got %d", w.Code)
	}
	if w := post(New(Config{Token: "tok"}, &memStore{}).Handler(), "tok", job()); w.Code != 503 {
		t.Errorf("no policy: %d want 503", w.Code)
	}
	for _, r := range []*rec{ctlSeen, candSeen, evilSeen} {
		if n, _, _, _ := r.get(); n != 0 {
			t.Fatal("rejected job reached an upstream")
		}
	}
}

// A bedrock path's model segment is attacker-controlled; it must not be able
// to steer the request off the policy host.
func TestBedrockPathStaysOnPolicyHost(t *testing.T) {
	ctl, ctlSeen := upstream(t, 1, 1)
	cand, _ := upstream(t, 1, 1)
	org := testOrg(ctl.URL, cand.URL)
	org.Gateway.Models["x@evil.tld"] = policy.ModelRoute{Upstream: "ctl", Model: "us.anthropic.m:0"}
	org.Experiments[0].Variants[1].Routes["x@evil.tld"] = policy.ModelRoute{Upstream: "cand", Model: "c"}
	st := &memStore{}
	s := New(Config{Token: "tok", Policy: orgFn(org)}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	j := job()
	j.Protocol, j.Path = "bedrock-invoke", "/model/x@evil.tld/invoke-with-response-stream"
	if w := post(s.Handler(), "tok", j); w.Code != 202 {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	waitFor(t, func() bool { return st.n() == 1 })
	if _, _, path, _ := ctlSeen.get(); path != "/model/us.anthropic.m%3A0/invoke" {
		t.Fatalf("path %q", path)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		if r.Header.Get("X-Api-Key") != "" {
			leaked.Add(100)
		}
	}))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	cand, _ := upstream(t, 1, 1)
	st := &memStore{}
	s := New(Config{Token: "tok", Policy: orgFn(testOrg(redir.URL, cand.URL)),
		UpstreamHeaders: map[string]map[string]string{"ctl": {"X-Api-Key": "ctl-key"}}}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	post(s.Handler(), "tok", job())
	waitFor(t, func() bool { return st.n() == 1 })
	if leaked.Load() != 0 {
		t.Fatalf("redirect followed (leaked=%d)", leaked.Load())
	}
	if p := st.pairs[0]; p.Control.Status != http.StatusTemporaryRedirect || p.Control.Error == "" {
		t.Fatalf("control side %+v", p.Control)
	}
}

func TestQueueFullDrops(t *testing.T) {
	s := New(Config{Token: "tok", Queue: 2, Policy: orgFn(testOrg("http://a", "http://b"))}, &memStore{}) // workers not started
	var codes []int
	for i := 0; i < 5; i++ {
		codes = append(codes, post(s.Handler(), "tok", job()).Code)
	}
	want := []int{202, 202, 429, 429, 429}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("codes %v", codes)
		}
	}
	if code, _ := metrics(t, s.Handler(), ""); code != 401 {
		t.Fatalf("metrics without token: %d", code)
	}
	if _, m := metrics(t, s.Handler(), "tok"); !strings.Contains(m, "halo_shadow_dropped_total 3\n") {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestDefaultBudgetFinite(t *testing.T) {
	if s := New(Config{}, &memStore{}); s.cfg.BudgetUSD != DefaultBudgetUSD {
		t.Fatalf("budget %v", s.cfg.BudgetUSD)
	}
}

// Many concurrent jobs: reservations are taken before anything is sent, so
// accepted work never exceeds the cap even though no job has settled yet.
func TestConcurrentBudgetRespectsCap(t *testing.T) {
	ctl, _ := upstream(t, 0, 1000)
	cand, _ := upstream(t, 0, 1000)
	st := &memStore{}
	// Per job estimate: 2 sides * 1000 max_tokens * $1000/MTok = $2 (input priced 0).
	s := New(Config{Token: "tok", Queue: 100, Workers: 8, BudgetUSD: 9, PriceOutPerMTok: 1000, Policy: orgFn(testOrg(ctl.URL, cand.URL))}, st)
	j := job()
	j.Body = json.RawMessage(`{"model":"sonnet","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}`)
	h := s.Handler()
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if post(h, "tok", j).Code == 202 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 4 {
		t.Fatalf("accepted %d jobs, want 4 ($2 each, $9 cap)", ok.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	waitFor(t, func() bool { return st.n() == 4 })
	if s.Spent() > 9 {
		t.Fatalf("spent %v over cap", s.Spent())
	}
	// Settled at actual ($2/job here) => still no room for a fifth.
	if w := post(h, "tok", j); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("after budget: %d", w.Code)
	}
}

func TestUpstreamErrorsCounted(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", 500) }))
	defer bad.Close()
	ok, _ := upstream(t, 1, 1)
	st := &memStore{}
	s := New(Config{Token: "tok", Policy: orgFn(testOrg(ok.URL, bad.URL))}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	post(s.Handler(), "tok", job())
	s2org := testOrg("http://127.0.0.1:1", ok.URL) // connection refused
	s.cfg.Policy = orgFn(s2org)
	post(s.Handler(), "tok", job())
	waitFor(t, func() bool { return st.n() == 2 })
	if _, m := metrics(t, s.Handler(), "tok"); !strings.Contains(m, "halo_shadow_errors_total 2\n") {
		t.Fatalf("metrics:\n%s", m)
	}
}

func TestMirrorerNonBlockingDrop(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	m, err := NewMirrorer(srv.URL, "tok", 2)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 20; i++ {
		m.Submit(Job{})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Submit blocked")
	}
	if m.Dropped() < 15 {
		t.Fatalf("dropped=%d", m.Dropped())
	}
}

func TestFileStore(t *testing.T) {
	fs, err := NewFileStore(t.TempDir()+"/p.jsonl", StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := fs.Append(context.Background(), Pair{ID: "a", Request: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	ctx, c := context.WithCancel(context.Background())
	c()
	if fs.Append(ctx, Pair{}) == nil {
		t.Fatal("cancelled ctx should fail")
	}
	if _, err := NewFileStore(t.TempDir()+"/p.jsonl", StoreOptions{Key: []byte("short")}); err == nil {
		t.Fatal("short key must be refused")
	}
}

func TestFileStoreEncryptedAndPruned(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	path := t.TempDir() + "/p.jsonl"
	fs, err := NewFileStore(path, StoreOptions{Key: key, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	now := time.Now().UTC()
	for _, p := range []Pair{
		{ID: "old", Time: now.Add(-2 * time.Hour), Request: json.RawMessage(`{"secret":"prompt-old"}`)},
		{ID: "new", Time: now, Request: json.RawMessage(`{"secret":"prompt-new"}`)},
	} {
		if err := fs.Append(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("prompt-")) {
		t.Fatalf("plaintext at rest: %s", raw)
	}
	if n, err := fs.Prune(now); err != nil || n != 1 {
		t.Fatalf("prune removed %d err %v", n, err)
	}
	if err := fs.Append(context.Background(), Pair{ID: "after", Time: now}); err != nil {
		t.Fatalf("append after prune: %v", err)
	}
	raw, _ = os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("rows %d", len(lines))
	}
	p, err := DecodePair(lines[0], key)
	if err != nil || p.ID != "new" || !strings.Contains(string(p.Request), "prompt-new") {
		t.Fatalf("decode %+v %v", p, err)
	}
	if _, err := DecodePair(lines[0], bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key must fail")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestMirrorerURLValidation(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://halo-shadow:8090/mirror":     true,
		"https://halo-shadow.example/mirror": true,
		"http://127.0.0.1:8090/mirror":       true,
		"":                                   false,
		"halo-shadow:8090/mirror":            false,
		"ftp://halo-shadow/mirror":           false,
		"http:///mirror":                     false,
		"http://user:pw@halo-shadow/mirror":  false,
		"http://bad host/%zz":                false,
	} {
		m, err := NewMirrorer(raw, "tok", 1)
		if (err == nil) != ok || (m != nil) != ok {
			t.Errorf("%q: m=%v err=%v want ok=%v", raw, m != nil, err, ok)
		}
		if _, err := SharedMirrorer(raw, "tok"); (err == nil) != ok {
			t.Errorf("shared %q: err=%v want ok=%v", raw, err, ok)
		}
	}
}

func TestMirrorerSendsJob(t *testing.T) {
	got := make(chan Job, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TokenHeader) != "tok" {
			w.WriteHeader(401)
			return
		}
		var j Job
		_ = json.NewDecoder(r.Body).Decode(&j)
		got <- j
		w.WriteHeader(202)
	}))
	defer srv.Close()
	m, err := NewMirrorer(srv.URL, "tok", 1)
	if err != nil {
		t.Fatal(err)
	}
	m.Submit(Job{Experiment: "e"})
	if j := <-got; j.Experiment != "e" {
		t.Fatalf("job %+v", j)
	}
	bad, _ := NewMirrorer(srv.URL, "wrong", 1)
	bad.Submit(Job{})
	waitFor(t, func() bool { return bad.Failed() == 1 })
}

func TestParseUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		body    string
		in, out int64
	}{
		"anthropic":        {`{"usage":{"input_tokens":3,"output_tokens":4}}`, 3, 4},
		"openai responses": {`{"output":[],"usage":{"input_tokens":5,"output_tokens":6,"total_tokens":11}}`, 5, 6},
		"openai chat":      {`{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":8}}`, 7, 8},
		"bedrock converse": {`{"output":{},"usage":{"inputTokens":9,"outputTokens":10,"totalTokens":19}}`, 9, 10},
		"no usage":         {`{"id":"x"}`, 0, 0},
		"not json":         {`upstream exploded`, 0, 0},
	} {
		if in, out := parseUsage([]byte(tc.body)); in != tc.in || out != tc.out {
			t.Errorf("%s: %d/%d want %d/%d", name, in, out, tc.in, tc.out)
		}
	}
}

// An upstream that reports no usage still costs the reserved estimate.
func TestUnparseableUsageChargesEstimate(t *testing.T) {
	blank := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ok":true}`)) }))
	defer blank.Close()
	st := &memStore{}
	s := New(Config{Token: "tok", PriceInPerMTok: 3, PriceOutPerMTok: 15, Policy: orgFn(testOrg(blank.URL, blank.URL))}, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	if w := post(s.Handler(), "tok", job()); w.Code != 202 {
		t.Fatalf("code %d", w.Code)
	}
	waitFor(t, func() bool { return st.n() == 1 })
	if est := 2 * s.estimate(job().Body); est <= 0 || s.Spent() != est {
		t.Fatalf("spent %v want estimate %v", s.Spent(), est)
	}
}

// Shutdown mid-job: the worker's ctx is cancelled while the upstream call is
// in flight, and the pair must still be stored.
func TestShutdownKeepsInFlightPair(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
	}))
	defer hang.Close()
	defer close(release)
	st := &memStore{}
	s := New(Config{Token: "tok", Workers: 1, Policy: orgFn(testOrg(hang.URL, hang.URL))}, st)
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	if w := post(s.Handler(), "tok", job()); w.Code != 202 {
		t.Fatalf("code %d", w.Code)
	}
	<-started
	cancel()
	s.Wait()
	if st.n() != 1 {
		t.Fatalf("in-flight pair lost on shutdown (stored %d)", st.n())
	}
}

func TestMetricsHandlerUnauthenticated(t *testing.T) {
	s := New(Config{Token: "tok"}, &memStore{})
	w := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "halo_shadow_mirrored_total 0\n") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(w, httptest.NewRequest("POST", "/mirror", nil))
	if w.Code == http.StatusAccepted {
		t.Fatal("metrics listener must not accept jobs")
	}
}
