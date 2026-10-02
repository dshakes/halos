package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func TestParseUA(t *testing.T) {
	for ua, want := range map[string][2]string{
		// recorded: Claude Code 2.1.287 `claude -p` against a capturing listener
		"claude-cli/2.1.287 (external, sdk-cli)": {"claude-code", "2.1.287"},
		// interactive entrypoint (anthropics/claude-code#72879)
		"claude-cli/2.1.280 (external, cli)": {"claude-code", "2.1.280"},
		// codex-rs login/src/auth/default_client.rs get_codex_user_agent
		"codex_cli_rs/0.99.0 (Mac OS 15.1.0; arm64) iTerm.app/3.5.10": {"codex", "0.99.0"},
		"codex_cli_rs/0.100.0-alpha.2 (Ubuntu 24.04; x86_64) unknown": {"codex", "0.100.0-alpha.2"},
		// recorded: Gemini CLI 0.26.0; format from packages/core/src/core/contentGenerator.ts
		"GeminiCLI/0.26.0/gemini-2.5-pro (darwin; x64)":         {"gemini-cli", "0.26.0"},
		"GeminiCLI-acp/0.34.0/gemini-pro (linux; x64; my-tool)": {"gemini-cli", "0.34.0"},
		"claude-cli/latest": {"claude-code", ""},
		"claude-cli":        {"claude-code", ""},
		"curl/8.7.1":        {"", ""},
		"":                  {"", ""},
		"Mozilla/5.0 (Macintosh) claude-cli/2.1.287 (external, cli)": {"", ""}, // prefix match only
	} {
		h, v := ParseUA(ua)
		if h != want[0] || v != want[1] {
			t.Errorf("ParseUA(%q) = %q, %q; want %q, %q", ua, h, v, want[0], want[1])
		}
	}
}

func gateOrg(posture, version string) *policy.Org {
	return &policy.Org{
		Profiles: map[string]*policy.Profile{
			"base": {Meta: policy.Meta{Name: "base"}, Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.1.280"}, "codex": {Version: "0.99.0"}}},
			"next": {Meta: policy.Meta{Name: "next"}, Extends: "base", Harnesses: map[string]policy.HarnessSpec{"codex": {Version: "0.100.0"}}},
		},
		Rings: []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Profile: "base", Posture: posture, VersionGate: version}},
		Experiments: []*policy.Experiment{{Meta: policy.Meta{Name: "codex-next"}, Axis: policy.AxisClient, Status: "running", Rings: []string{"ga"},
			Variants: []policy.Variant{{Name: "control", Weight: 1, Control: true, Profile: "base"}, {Name: "next", Weight: 1, Profile: "next"}}}},
	}
}

func TestCheckVersion(t *testing.T) {
	for _, tc := range []struct {
		mode, ua, wantMode, reason string
	}{
		{"", "claude-cli/2.1.280 (external, cli)", "", ""},
		{"", "claude-cli/2.1.279 (external, cli)", "warn", "claude-code 2.1.279; ring ga pins 2.1.280"},
		{"enforce", "claude-cli/2.1.279 (external, cli)", "enforce", "claude-code 2.1.279"},
		{"enforce", "codex_cli_rs/0.100.0 (Mac OS 15.1.0; arm64) iTerm.app", "", ""}, // client-axis variant's pin
		{"enforce", "codex_cli_rs/0.98.0 (Mac OS 15.1.0; arm64) iTerm.app", "enforce", "pins 0.100.0 or 0.99.0"},
		{"enforce", "GeminiCLI/0.26.0/gemini-2.5-pro (darwin; x64)", "", ""}, // ring pins no gemini-cli: nothing to compare
		{"enforce", "", "enforce", "unrecognised or missing User-Agent"},
		{"", "curl/8.7.1", "warn", "unrecognised"},
		{"enforce", "claude-cli/latest", "enforce", "carries no version"},
		{"off", "", "", ""},
	} {
		f := CheckVersion(gateOrg("", tc.mode), "ga", tc.ua)
		if tc.wantMode == "" {
			if f != nil {
				t.Errorf("%s/%q: unexpected finding %+v", tc.mode, tc.ua, f)
			}
			continue
		}
		if f == nil || f.Mode != tc.wantMode || f.Gate != GateVersion || !strings.Contains(f.Reason, tc.reason) {
			t.Errorf("%s/%q: finding %+v, want mode %s reason ~%q", tc.mode, tc.ua, f, tc.wantMode, tc.reason)
		}
	}
	if f := CheckVersion(gateOrg("", "enforce"), "no-such-ring", ""); f != nil {
		t.Errorf("unknown ring gated: %+v", f)
	}
}

func TestFindingReject(t *testing.T) {
	f := &Finding{Gate: GatePosture, Mode: policy.GateWarn, Reason: "drift"}
	if f.Reject(ProtoAnthropic) != nil {
		t.Fatal("warn mode rejected")
	}
	f.Mode = policy.GateEnforce
	for _, proto := range []string{ProtoAnthropic, ProtoResponses, ProtoGemini, ProtoBedrock} {
		r := f.Reject(proto)
		if r == nil || r.Status != http.StatusForbidden || !strings.Contains(string(r.JSON()), "halod status") {
			t.Fatalf("%s: %+v %s", proto, r, r.JSON())
		}
	}
	var v struct{ Error struct{ Code string } }
	if err := json.Unmarshal(f.Reject(ProtoResponses).JSON(), &v); err != nil || v.Error.Code != "posture_check_failed" {
		t.Fatalf("responses code %q (%v)", v.Error.Code, err)
	}
}

type postureSrv struct {
	*httptest.Server
	verdict atomic.Value // PostureVerdict
	down    atomic.Bool
	calls   atomic.Int32
}

func newPostureSrv(t *testing.T) *postureSrv {
	s := &postureSrv{}
	s.verdict.Store(PostureVerdict{Compliant: true})
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if s.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.Header.Get("Authorization") != "Bearer gw" || r.URL.Query().Get("subject") != "dev@acme.com" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(s.verdict.Load())
	}))
	t.Cleanup(s.Close)
	return s
}

func TestPostureClient(t *testing.T) {
	srv := newPostureSrv(t)
	now := time.Unix(1_700_000_000, 0)
	c, err := NewPostureClient(srv.URL, "gw", time.Minute, 10*time.Minute, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return now }
	ctx := context.Background()
	sub := &policy.Subject{ID: "dev@acme.com"}
	org := gateOrg("enforce", "")

	if f, unk := CheckPosture(ctx, c, org, "ga", sub); f != nil || unk {
		t.Fatalf("compliant: %+v %v", f, unk)
	}
	srv.verdict.Store(PostureVerdict{Reason: "device d1 reported drift"})
	if f, _ := CheckPosture(ctx, c, org, "ga", sub); f != nil || srv.calls.Load() != 1 {
		t.Fatalf("within TTL the cached verdict serves: %+v calls %d", f, srv.calls.Load())
	}
	now = now.Add(2 * time.Minute)
	f, _ := CheckPosture(ctx, c, org, "ga", sub)
	if f == nil || f.Mode != policy.GateEnforce || f.Reject(ProtoAnthropic) == nil || !strings.Contains(f.Reason, "drift") {
		t.Fatalf("non-compliant verdict: %+v", f)
	}

	// halo-server unreachable: the last verdict (non-compliant) holds for the grace window...
	srv.down.Store(true)
	now = now.Add(5 * time.Minute)
	if f, unk := CheckPosture(ctx, c, org, "ga", sub); f == nil || unk {
		t.Fatalf("grace window: %+v %v", f, unk)
	}
	// ...then posture is unknown: the request passes (fail closed only on a server verdict).
	now = now.Add(10 * time.Minute)
	if f, unk := CheckPosture(ctx, c, org, "ga", sub); f != nil || !unk {
		t.Fatalf("past grace: %+v %v", f, unk)
	}

	if f, unk := CheckPosture(ctx, c, org, "ga", nil); f != nil || !unk {
		t.Fatalf("anonymous caller: %+v %v", f, unk)
	}
	if f, unk := CheckPosture(ctx, c, gateOrg("off", ""), "ga", sub); f != nil || unk {
		t.Fatalf("posture off: %+v %v", f, unk)
	}
	if f, unk := CheckPosture(ctx, nil, org, "ga", sub); f != nil || unk {
		t.Fatalf("no client configured: %+v %v", f, unk)
	}

	if _, err := NewPostureClient("http://halo-server.example/x", "gw", 0, 0, nil, false); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
	if _, err := NewPostureClient(srv.URL, "", 0, 0, nil, false); err == nil {
		t.Fatal("empty token accepted")
	}
}
