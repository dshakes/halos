package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// checkSSE asserts out is a sequence of "event: T\ndata: JSON\n\n" blocks with
// no stray CR/LF inside a field, i.e. a client sees exactly the events the
// converter meant to emit.
func checkSSE(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	if bytes.ContainsRune(out, '\r') {
		return errors.New("CR in SSE output")
	}
	s := string(out)
	if !strings.HasSuffix(s, "\n\n") {
		return errors.New("SSE output does not end with a blank line")
	}
	for _, blk := range strings.Split(strings.TrimSuffix(s, "\n\n"), "\n\n") {
		lines := strings.Split(blk, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
			return fmt.Errorf("malformed SSE event %q", blk)
		}
		if !json.Valid([]byte(strings.TrimPrefix(lines[1], "data: "))) {
			return fmt.Errorf("SSE data is not JSON: %q", lines[1])
		}
	}
	return nil
}

// FuzzEventStreamToSSE: arbitrary bytes, or an arbitrary event JSON inside a
// valid (CRC-correct) frame. Property: no panic, the stream ends, and whatever
// was emitted is well-formed SSE (no event/data injection).
func FuzzEventStreamToSSE(f *testing.F) {
	exc := frame([][2]string{{":message-type", "exception"}, {":exception-type", "throttlingException"}}, []byte("slow down"))
	bad := chunk(`{"type":"ping"}`)
	bad[len(bad)-1] ^= 0xff
	for _, s := range [][]byte{
		chunk(`{"type":"message_start","message":{"id":"m"}}`), exc, bad, bytes.Join([][]byte{chunk(`{"type":"a"}`), exc}, nil),
		frame([][2]string{{":message-type", "event"}}, []byte(`{"p":"initial-response"}`)), {}, {0, 0, 0, 16},
	} {
		f.Add(s, false)
	}
	for _, s := range []string{`{"type":"message_start"}`, `{"type":"a\nb"}`, "{\n}", `null`, `"x"`, `[]`, `{"type":1}`} {
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, data []byte, wrap bool) {
		if wrap {
			data = chunk(string(data))
		}
		out, _ := io.ReadAll(io.LimitReader(EventStreamToSSE(io.NopCloser(bytes.NewReader(data))), int64(64*len(data)+4096)))
		if err := checkSSE(out); err != nil {
			t.Fatalf("%v\ninput %q\noutput %q", err, data, out)
		}
	})
}

var fuzzKillNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// FuzzVerifyKillList: property: a list is accepted only with a valid ed25519
// signature over the domain-separated payload by the configured key, only when
// fresh, and only with exactly the signed contents. signIt=true signs the
// fuzzed payload with the real key so freshness and decoding are exercised
// past the signature check.
func FuzzVerifyKillList(f *testing.F) {
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	pub := seed.Public().(ed25519.PublicKey)
	signed := map[string]bool{} // payload||sig pairs produced by the real key
	add := func(l KillList) {
		env, err := SignKillList(seed, l)
		if err != nil {
			f.Fatal(err)
		}
		signed[string(env.Payload)+"\x00"+string(env.Signature)] = true
		f.Add(env.Payload, env.Signature, false)
		f.Add(env.Payload, env.Signature, true)
	}
	add(KillList{Version: 3, Experiments: []string{"a"}, IssuedAt: fuzzKillNow})
	add(KillList{Version: 1, Toggles: []string{"t"}, IssuedAt: fuzzKillNow.Add(-time.Minute)})
	add(KillList{IssuedAt: fuzzKillNow.Add(-time.Hour)})
	add(KillList{IssuedAt: fuzzKillNow.Add(5 * time.Minute)})
	f.Add([]byte(`{"version":9,"experiments":[],"issuedAt":"2026-09-01T12:00:00Z"}`), make([]byte, 64), false)
	f.Add([]byte(`{"issuedAt":"2026-09-01T12:00:30Z","experiments":null}`), []byte{}, true)
	f.Fuzz(func(t *testing.T, payload, sig []byte, signIt bool) {
		if signIt {
			sig = ed25519.Sign(seed, append([]byte(killDomain), payload...))
		}
		l, err := VerifyKillList(pub, KillEnvelope{Payload: payload, Signature: sig}, fuzzKillNow, DefaultKillMaxAge)
		if err != nil {
			return
		}
		if !signIt && !signed[string(payload)+"\x00"+string(sig)] {
			t.Fatalf("accepted an envelope the key never signed: payload %q sig %x", payload, sig)
		}
		if !ed25519.Verify(pub, append([]byte(killDomain), payload...), sig) {
			t.Fatal("accepted with an invalid signature")
		}
		if age := fuzzKillNow.Sub(l.IssuedAt); age > DefaultKillMaxAge || age < -time.Minute {
			t.Fatalf("accepted stale/future list issued %s", l.IssuedAt)
		}
		var want KillList
		if json.Unmarshal(payload, &want) != nil || !slices.Equal(want.Experiments, l.Experiments) || !slices.Equal(want.Toggles, l.Toggles) {
			t.Fatalf("returned list %+v differs from the signed payload %q", l, payload)
		}
	})
}

type bodyRT []byte

func (b bodyRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}}, nil
}

// FuzzKillSwitchRefresh feeds arbitrary response bodies to a poller that has
// already accepted a kill of exp-a. Property: a failed refresh keeps exactly
// the last accepted list (fail toward keeping kills); a successful one only
// installs a validly signed, fresh, strictly newer list.
func FuzzKillSwitchRefresh(f *testing.F) {
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	pub := seed.Public().(ed25519.PublicKey)
	prev := KillList{Version: 1, Experiments: []string{"exp-a"}, IssuedAt: fuzzKillNow.Add(-time.Minute)}
	envJSON := func(l KillList) []byte {
		env, _ := SignKillList(seed, l)
		b, _ := json.Marshal(env)
		return b
	}
	f.Add(envJSON(KillList{Version: 2, IssuedAt: fuzzKillNow}))                       // newer unkill: accepted
	f.Add(envJSON(KillList{Version: 0, IssuedAt: fuzzKillNow.Add(-2 * time.Minute)})) // replay: refused
	f.Add(envJSON(KillList{Version: 2, IssuedAt: fuzzKillNow.Add(-time.Hour)}))       // stale
	f.Add(envJSON(KillList{Version: 2, Experiments: []string{"b"}, IssuedAt: fuzzKillNow.Add(time.Second)}))
	f.Add([]byte(`{"payload":"e30=","signature":""}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.Fuzz(func(t *testing.T, body []byte) {
		k := &KillSwitch{URL: "https://halo.example/k", Token: "t", PubKey: pub, Log: log,
			Now: func() time.Time { return fuzzKillNow }, Client: &http.Client{Transport: bodyRT(body)}}
		k.Restore(prev)
		err := k.Refresh(context.Background())
		got := k.Killed()
		if err != nil {
			if !slices.Equal(got.Experiments, prev.Experiments) || !got.IssuedAt.Equal(prev.IssuedAt) {
				t.Fatalf("failed refresh changed the list: %+v (err %v)", got, err)
			}
			return
		}
		var env KillEnvelope
		if json.NewDecoder(bytes.NewReader(body)).Decode(&env) != nil {
			t.Fatal("accepted an undecodable body")
		}
		if !ed25519.Verify(pub, append([]byte(killDomain), env.Payload...), env.Signature) {
			t.Fatal("accepted an unsigned list")
		}
		if !got.IssuedAt.After(prev.IssuedAt) {
			t.Fatalf("accepted a list not newer than the current one: %s", got.IssuedAt)
		}
		if age := fuzzKillNow.Sub(got.IssuedAt); age > DefaultKillMaxAge || age < -time.Minute {
			t.Fatalf("accepted stale/future list %s", got.IssuedAt)
		}
	})
}

// FuzzPrepareVerified: arbitrary path, body, one arbitrary header and an
// optional verified subject. Properties: every client x-halo-* name is
// cleared; the decision ignores client headers; an anonymous caller is never
// enrolled; a forwarded model call names exactly one model, the policy's; a
// forwarded non-model path is an allowlisted passthrough; rewrite failures are
// never forwarded; rejections render as JSON.
func FuzzPrepareVerified(f *testing.F) {
	org := testOrg()
	org.Gateway.Models["claude-sonnet-4-5"] = policy.ModelRoute{Upstream: "anthropic", Model: "claude-sonnet-4-5"} // identity alias: no rewrite needed
	org.Gateway.Models["gem"] = policy.ModelRoute{Upstream: "anthropic", Model: "gemini-2.5-pro"}
	first := `{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`
	for _, s := range []struct{ path, body, hn, hv, user string }{
		{PathMessages, first, "X-Halo-Ring", "ring0", "alice"},
		{PathMessages, first, "x-HALO-experiment", "sonnet-canary", ""},
		{PathMessages, `{"model":"claude-opus-4","Model":"claude-sonnet-4-5"}`, "x-claude-code-session-id", "s1", "bob"},
		{PathMessages, `{"model":"claude-opus-4","model":"claude-sonnet-4-5"}`, "", "", "bob"},
		{PathCountTokens, first, "", "", "alice"},
		{PathResponses, `{"model":"sonnet","input":"hi"}`, "", "", "carol"},
		{"/model/sonnet/invoke-with-response-stream", `{}`, "", "", "dave"},
		{"/model/claude-sonnet-4-5/converse", `{"model":"x"}`, "", "", ""},
		{"/v1beta/models/gem:streamGenerateContent", `{"contents":[]}`, "", "", "erin"},
		{"/v1/messages/batches", first, "", "", "alice"},
		{"/v1/models/%2e%2e", "", "", "", "alice"},
		{"/v1/models", "", "x-halo-anything", "1", ""},
		{"/v1//messages", first, "", "", "alice"},
	} {
		f.Add(s.path, []byte(s.body), s.hn, s.hv, s.user)
	}
	f.Fuzz(func(t *testing.T, path string, body []byte, hn, hv, user string) {
		h := http.Header{}
		if hn != "" {
			h[hn] = []string{hv} // raw key: as a non-canonicalizing host (Kong) could pass it
		}
		var sub *policy.Subject
		if user != "" {
			sub = &policy.Subject{ID: user, Groups: []string{"ai-platform"}}
		}
		res := PrepareVerified(org, sub, h, path, body)
		d := res.Decision

		for n := range h {
			if l := strings.ToLower(n); strings.HasPrefix(l, HaloPrefix) && !slices.Contains(res.ClearHeaders, l) {
				t.Fatalf("x-halo header %q not cleared: %v", n, res.ClearHeaders)
			}
		}
		if strings.HasPrefix(strings.ToLower(hn), HaloPrefix) { // UA/session headers may legitimately matter; x-halo-* never
			if clean := PrepareVerified(org, sub, http.Header{}, path, body).Decision; fmt.Sprint(clean) != fmt.Sprint(d) {
				t.Fatalf("client header %s changed the decision:\n%+v\n%+v", hn, clean, d)
			}
		}
		if sub == nil && (d.Experiment != "" || d.Variant != "" || len(d.Shadow) != 0 || d.Ring != RingUnknown) {
			t.Fatalf("anonymous caller enrolled: %+v", d)
		}
		if res.RewriteErr != nil && res.Reject == nil {
			t.Fatal("rewrite failure not rejected")
		}
		if res.Reject != nil {
			if !json.Valid(res.Reject.JSON()) {
				t.Fatalf("rejection body not JSON: %s", res.Reject.JSON())
			}
			return
		}
		if res.Protocol == "" {
			if !passthrough(path) {
				t.Fatalf("non-model path %q admitted", path)
			}
			return
		}
		if d.UpstreamModel == "" {
			t.Fatalf("model call admitted without a policy model: %+v", d)
		}
		switch res.Protocol {
		case ProtoAnthropic, ProtoResponses:
			ms := forwardedModels(t, res.Body)
			if len(ms) != 1 || ms[0] != [2]string{"model", d.UpstreamModel} {
				t.Fatalf("forwarded body %q names models %v, policy chose %q", res.Body, ms, d.UpstreamModel)
			}
		case ProtoBedrock, ProtoGemini:
			if m, _ := Inspect(res.Protocol, res.Path, nil); m != d.UpstreamModel {
				t.Fatalf("forwarded path %q names model %q, policy chose %q", res.Path, m, d.UpstreamModel)
			}
		}
	})
}
