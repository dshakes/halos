package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/gateway"
)

// killServer serves a signed kill list the way halo-server's
// /api/v1/fleet/killswitch does; tests swap the list, key or failure mode.
type killServer struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	list    []string
	toggles []string  // killed feature toggles
	issued  time.Time // zero: time.Now() per request
	fail    bool
	replay  []byte // served verbatim when set
	last    []byte
	srv     *httptest.Server
	pub     ed25519.PublicKey
	fetches int
}

func newKillServer(t *testing.T) *killServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &killServer{key: priv, pub: pub, list: []string{}}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.fetches++
		if k.fail || r.Header.Get("Authorization") != "Bearer dev-tok" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		b := k.replay
		if b == nil {
			at := k.issued
			if at.IsZero() {
				at = time.Now()
			}
			env, err := gateway.SignKillList(k.key, gateway.KillList{Experiments: k.list, Toggles: k.toggles, IssuedAt: at})
			if err != nil {
				t.Error(err)
			}
			b, _ = json.Marshal(env)
		}
		k.last = b
		_, _ = w.Write(b)
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *killServer) set(f func(k *killServer)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f(k)
}

// switchFor is the kill-list poller a fresh halod process would build.
func (k *killServer) switchFor(t *testing.T) *gateway.KillSwitch {
	t.Helper()
	ks, err := gateway.NewKillSwitch(k.srv.URL, "dev-tok", k.pub, 0, quietLog(), false)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// noRegistry fails any registry access: a kill must apply the cached ring release.
func noRegistry(t *testing.T) func(context.Context) (oras.ReadOnlyTarget, error) {
	return func(context.Context) (oras.ReadOnlyTarget, error) {
		t.Error("registry opened on a kill poll")
		return nil, errors.New("registry disabled")
	}
}

func TestKillSwitchRevertsClientExperiment(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log, e.a.Cfg.Subject = false, quietLog(), userIn(t)
	e.publishRing(t, "1", "running")
	ks := newKillServer(t)
	e.a.Kill = ks.switchFor(t)
	open := e.a.Open
	status := func() Status { return e.a.loadState().Status }
	onTreatment := func(what string) {
		t.Helper()
		if s := status(); pinOf(e) != pinTreatment || s.Experiment != "cli-upgrade" || s.Variant != "treatment" || s.Killed {
			t.Fatalf("%s: want treatment, got %s %+v", what, pinOf(e), s)
		}
	}
	onControl := func(what string) {
		t.Helper()
		if s := status(); pinOf(e) != pinControl || s.Experiment != "cli-upgrade" || s.Variant != "" || !s.Killed || s.ErrorCode != "" {
			t.Fatalf("%s: want killed/control, got %s %+v", what, pinOf(e), s)
		}
	}

	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	onTreatment("before kill")
	if err := e.a.PollKill(ctx); err != nil { // nothing changed: no apply, no registry
		t.Fatal(err)
	}

	// killed -> control from the cached ring release, no pull
	ks.set(func(k *killServer) { k.list = []string{"cli-upgrade"} })
	e.a.Open = noRegistry(t)
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	onControl("after kill")
	if err := e.a.PollKill(ctx); err != nil { // steady state: still no registry
		t.Fatal(err)
	}
	e.a.Open = open

	// a full cycle keeps honoring the kill (does not re-select the variant)
	if st, err := e.a.Once(ctx); err != nil || !st.Killed {
		t.Fatalf("full cycle while killed: %v %+v", err, st)
	}
	onControl("full cycle")

	for _, tc := range []struct {
		name string
		set  func(k *killServer)
	}{
		{"forged signature", func(k *killServer) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			k.key, k.list = other, []string{}
		}},
		{"stale list", func(k *killServer) { k.list, k.issued = []string{}, time.Now().Add(-time.Hour) }},
		{"future list", func(k *killServer) { k.list, k.issued = []string{}, time.Now().Add(time.Hour) }},
		{"fetch failure", func(k *killServer) { k.list, k.fail = []string{}, true }},
	} {
		key := ks.key
		ks.set(tc.set)
		if err := e.a.PollKill(ctx); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		onControl(tc.name + " keeps the last-known list")
		ks.set(func(k *killServer) {
			k.key, k.issued, k.fail, k.list = key, time.Time{}, false, []string{"cli-upgrade"}
		})
	}

	// replay: an unkilled envelope issued before the kill is refused
	ks.set(func(k *killServer) { k.list = []string{} })
	var early []byte
	{ // capture an unkill envelope with an old (but fresh-enough) issuedAt
		ks.set(func(k *killServer) { k.issued = time.Now().Add(-2 * time.Minute) })
		probe := ks.switchFor(t)
		_ = probe.Refresh(ctx)
		ks.set(func(k *killServer) { early, k.issued, k.list = k.last, time.Time{}, []string{"cli-upgrade"} })
	}
	ks.set(func(k *killServer) { k.replay = early })
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	onControl("replayed older envelope")

	// restart: a new process restores the persisted list and refuses the replay too
	e.a.Kill, e.a.ringRel = ks.switchFor(t), nil
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	onControl("replay after restart")
	if l := e.a.loadState().Kill; len(l.Experiments) != 1 || l.IssuedAt.IsZero() {
		t.Fatalf("kill list not persisted: %+v", l)
	}

	// unkill -> back to the variant channel on the next kill poll
	ks.set(func(k *killServer) { k.replay, k.list = nil, []string{} })
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	onTreatment("after unkill")

	// killed after a restart (nothing cached): pulls the ring release
	e.a.Kill, e.a.ringRel = ks.switchFor(t), nil
	ks.set(func(k *killServer) { k.list = []string{"cli-upgrade"} })
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	onControl("kill without a cached release")
}

// A kill for another experiment, or none, leaves the device alone; a
// never-fetched list kills nothing.
func TestKillSwitchUnrelatedOrUnreachable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.a.Install, e.a.Log, e.a.Cfg.Subject = false, quietLog(), userIn(t)
	e.publishRing(t, "1", "running")
	ks := newKillServer(t)
	ks.set(func(k *killServer) { k.fail = true })
	e.a.Kill = ks.switchFor(t)
	if st, err := e.a.Once(ctx); err != nil || st.Variant != "treatment" || st.Killed {
		t.Fatalf("unreachable kill list must kill nothing: %v %+v", err, st)
	}
	ks.set(func(k *killServer) { k.fail, k.list = false, []string{"other-exp"} })
	e.a.Open = noRegistry(t)
	if err := e.a.PollKill(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.a.loadState().Status; s.Variant != "treatment" || s.Killed || pinOf(e) != pinTreatment {
		t.Fatalf("unrelated kill changed the device: %+v", s)
	}
}

// Kill polls run between release pulls on the same loop, without pulling.
func TestLoopPollsKillSwitch(t *testing.T) {
	ks := newKillServer(t)
	opens := 0
	a := &Agent{Cfg: Config{Ring: "canary", OS: "linux"}, Root: t.TempDir(), StatePath: "/state.json", Now: time.Now,
		Stdout: &strings.Builder{}, Log: quietLog(), HTTP: http.DefaultClient, Kill: ks.switchFor(t), KillEvery: 5 * time.Second,
		Open: func(context.Context) (oras.ReadOnlyTarget, error) { opens++; return nil, context.DeadlineExceeded }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		c := make(chan time.Time, 1)
		switch {
		case d == time.Hour: // the release interval never fires here
		case len(waits) <= 3:
			c <- time.Now()
		default:
			cancel()
		}
		return c
	}
	a.loop(ctx, time.Hour, after)
	var fetches int
	ks.set(func(k *killServer) { fetches = k.fetches })
	if opens != 1 || fetches != 3 { // Once + two kill polls
		t.Fatalf("opens=%d kill fetches=%d waits=%v", opens, fetches, waits)
	}
}

func TestKillSwitchConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		url  string
		err  string
	}{
		{"disabled", Config{}, "", ""},
		{"default url from ringEndpoint", Config{RingEndpoint: "https://halo.acme.example/api/v1/fleet/ring", KillSwitch: KillSwitchConfig{PubKey: "/k"}},
			"https://halo.acme.example/api/v1/fleet/killswitch", ""},
		{"explicit url", Config{Ring: "r", KillSwitch: KillSwitchConfig{PubKey: "/k", URL: "https://x.example/ks", Interval: "30s"}}, "https://x.example/ks", ""},
		{"url without pubkey", Config{KillSwitch: KillSwitchConfig{URL: "https://x.example/ks"}}, "", "pubkey is required"},
		{"no url, no ringEndpoint", Config{Ring: "r", KillSwitch: KillSwitchConfig{PubKey: "/k"}}, "", "url is required"},
		{"plain http", Config{KillSwitch: KillSwitchConfig{PubKey: "/k", URL: "http://x.example/ks"}}, "", "https"},
		{"bad interval", Config{KillSwitch: KillSwitchConfig{PubKey: "/k", URL: "https://x.example/ks", Interval: "10ms"}}, "", "interval"},
	} {
		c := tc.cfg
		err := c.checkKillSwitch()
		if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) || c.KillSwitch.URL != tc.url && err == nil {
			t.Errorf("%s: url=%q err=%v", tc.name, c.KillSwitch.URL, err)
		}
	}
	if d, _ := (Config{}).KillIntervalD(); d != DefaultKillInterval {
		t.Errorf("default interval %s", d)
	}
}
