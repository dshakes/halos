package shadow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// The mirror sender carries the shadow token and the prompt: a redirect from
// the shadow URL must not carry either to another host.
func TestMirrorerDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	m, err := NewMirrorer(redir.URL+"/mirror", "shadow-secret", 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.send(job()); err == nil {
		t.Fatal("a 3xx from the shadow URL must count as a failed send")
	}
	if leaked.Load() != 0 {
		t.Fatalf("mirror job followed a redirect to another host (%d hits)", leaked.Load())
	}
}

// recordRT answers every request locally and records where it was sent.
type recordRT struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (r *recordRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"usage":{}}`)), Header: http.Header{}, Request: req}, nil
}

// FuzzShadowReplayStaysOnPolicyHost: a token holder controls the whole job
// (path, body, headers, experiment, variant). Property: every replay goes
// only to a policy upstream's scheme+host, under its base path, with the
// policy model, and carries only allowlisted client headers plus that
// upstream's own credential, never another upstream's.
func FuzzShadowReplayStaysOnPolicyHost(f *testing.F) {
	const ctlURL, candURL = "https://ctl.example:8443/base", "http://cand.example"
	org := testOrg(ctlURL, candURL)
	org.Gateway.Models["x@evil.tld"] = policy.ModelRoute{Upstream: "ctl", Model: "us.anthropic.m:0"}
	org.Experiments[0].Variants[1].Routes["x@evil.tld"] = policy.ModelRoute{Upstream: "cand", Model: "c/../../evil"}
	creds := map[string]map[string]string{"ctl": {"X-Api-Key": "ctl-key"}, "cand": {"Authorization": "Bearer cand-key"}}
	allowed := map[string]*url.URL{"ctl": mustURL(ctlURL), "cand": mustURL(candURL)}

	j := job()
	f.Add(j.Path, j.Protocol, []byte(j.Body), "Anthropic-Version", "2023-06-01", "cand")
	f.Add("/model/x@evil.tld/invoke-with-response-stream", gateway.ProtoBedrock, []byte(`{}`), "Host", "evil.tld", "cand")
	f.Add("/model/x%40evil.tld%2F..%2F..%2Fsteal/invoke", gateway.ProtoBedrock, []byte(`{}`), "X-Api-Key", "client", "cand")
	f.Add("/v1/responses", gateway.ProtoResponses, []byte(`{"model":"sonnet","input":"hi"}`), "openai-beta", "x", "cand")
	f.Add("//evil.tld/v1/messages", gateway.ProtoAnthropic, []byte(j.Body), "", "", "cand")
	f.Add("/v1beta/models/sonnet:generateContent", gateway.ProtoGemini, []byte(`{"contents":[]}`), "", "", "control")

	f.Fuzz(func(t *testing.T, path, proto string, body []byte, hk, hv, variant string) {
		rt := &recordRT{}
		s := New(Config{Token: "tok", Policy: orgFn(org), UpstreamHeaders: creds, HTTP: &http.Client{Transport: rt}}, &memStore{})
		jb := Job{Experiment: "exp", Variant: variant, Protocol: proto, Method: http.MethodPost, Path: path, Body: body,
			Headers: map[string]string{hk: hv, "Authorization": "Bearer client-token", "X-Api-Key": "client-key"}}
		if !json.Valid(body) {
			return // Job.Body is a json.RawMessage: not representable on the wire
		}
		tk, _, err := s.resolve(jb)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.call(ctx, tk.j, tk.ctl)
		s.call(ctx, tk.j, tk.cand)
		for _, r := range rt.reqs {
			var name string
			for n, u := range allowed {
				if r.URL.Scheme == u.Scheme && r.URL.Host == u.Host && strings.HasPrefix(r.URL.Path, u.Path) {
					name = n
				}
			}
			if name == "" {
				t.Fatalf("replay left the policy hosts: %s", r.URL)
			}
			if r.Host != "" && r.Host != r.URL.Host {
				t.Fatalf("Host override %q", r.Host)
			}
			for k := range r.Header {
				lk := strings.ToLower(k)
				if lk == "content-type" || ReplayHeaders[lk] {
					continue
				}
				if _, own := creds[name][k]; !own {
					t.Fatalf("header %s sent to %s (%s)", k, name, r.URL)
				}
			}
			for n, hs := range creds {
				for k, v := range hs {
					if n != name && r.Header.Get(k) == v {
						t.Fatalf("%s's credential sent to %s", n, name)
					}
				}
			}
			if b, _ := io.ReadAll(r.Body); bytes.Contains(b, []byte("client-token")) {
				t.Fatal("client credential in replay body")
			}
		}
	})
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
