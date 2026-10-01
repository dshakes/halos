package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/bundle"
)

func TestReleasesPointerChecksAndChannels(t *testing.T) {
	e := newEnv(t, nil)
	org, _, _ := e.s.pol.Get()
	ring := org.Rings[0].Name
	dig := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	ctl, trt := ring+".x-cli.control", ring+".x-cli.treatment"
	ptrs := map[string]bundle.Pointer{
		ring: {Org: org.Name, Ring: ring, Digest: dig("a"), Seq: 10, ExpiresAt: e.now.Add(time.Hour)},
		ctl:  {Org: org.Name, Ring: ctl, Digest: dig("c"), Seq: 10, ExpiresAt: e.now.Add(time.Hour)},
		trt:  {Org: org.Name, Ring: trt, Digest: dig("t"), Seq: 10, ExpiresAt: e.now.Add(-time.Minute)},
	}
	chanCalls := 0
	e.s.relChannels = func(_ context.Context, p bundle.Pointer) ([]string, error) {
		chanCalls++
		if p.Ring != ring {
			return nil, errors.New("unexpected ring")
		}
		return []string{ctl, trt}, nil
	}
	e.s.relFetch = func(_ context.Context, r string) (bundle.Pointer, bool, error) {
		p, ok := ptrs[r]
		return p, ok, nil
	}
	for i, d := range []string{dig("a"), dig("c"), dig("c"), dig("t"), dig("z")} {
		if err := e.s.cfg.Store.Put(Host{Report: Report{Hostname: "h" + string(rune('0'+i)), Ring: ring, Digest: d}, LastSeen: *e.now}); err != nil {
			t.Fatal(err)
		}
	}
	get := func() (ReleasesResponse, RingRelease) {
		t.Helper()
		r := decode[ReleasesResponse](t, e.as(admin, "GET", "/api/v1/releases", ""))
		for _, x := range r.Rings {
			if x.Ring == ring {
				return r, x
			}
		}
		t.Fatal("ring row missing")
		return r, RingRelease{}
	}
	tick := func() { *e.now = e.now.Add(releaseCacheTTL) }

	_, rr := get()
	if rr.Suspicious || rr.Stale || rr.Error != "" || len(rr.Channels) != 2 {
		t.Fatalf("row: %+v", rr)
	}
	if c := rr.Convergence; c.Total != 5 || c.OnDigest != 4 || c.Other != 1 {
		t.Fatalf("treatment/control devices must count as converged: %+v", c)
	}
	if c := rr.Channels[0]; c.Channel != ctl || c.Devices != 2 || c.Digest != dig("c") || c.Expired {
		t.Fatalf("control: %+v", c)
	}
	if c := rr.Channels[1]; c.Channel != trt || c.Devices != 1 || !c.Expired {
		t.Fatalf("treatment: %+v", c)
	}

	tests := []struct {
		name string
		key  string
		p    bundle.Pointer
		gone bool
		want string
	}{
		{"foreign org", ring, bundle.Pointer{Org: "evil", Ring: ring, Digest: dig("e"), Seq: 99}, false, "org"},
		{"seq regression", ring, bundle.Pointer{Org: org.Name, Ring: ring, Digest: dig("o"), Seq: 9}, false, "regressed"},
		{"seq reuse", ring, bundle.Pointer{Org: org.Name, Ring: ring, Digest: dig("o"), Seq: 10}, false, "reuses seq"},
		{"vanished", ring, bundle.Pointer{}, true, "disappeared"},
		{"channel regression", ctl, bundle.Pointer{Org: org.Name, Ring: ctl, Digest: dig("o"), Seq: 3}, false, "regressed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			good := ptrs[tt.key]
			t.Cleanup(func() { ptrs[tt.key] = good })
			if tt.gone {
				delete(ptrs, tt.key)
			} else {
				ptrs[tt.key] = tt.p
			}
			tick()
			r, rr := get()
			errs := rr.Error
			for _, c := range rr.Channels {
				errs += c.Error
			}
			if !rr.Suspicious || !rr.Stale || !r.Stale || !strings.Contains(errs, tt.want) {
				t.Fatalf("not flagged: %+v", rr)
			}
			if rr.Digest != dig("a") || rr.Seq != 10 || rr.Channels[0].Digest != dig("c") { // last good kept
				t.Fatalf("last good not kept: %+v", rr)
			}
		})
	}
	// genuine newer pointer: accepted, flags clear
	ptrs[ring] = bundle.Pointer{Org: org.Name, Ring: ring, Digest: dig("a"), Seq: 11, ExpiresAt: e.now.Add(time.Hour)}
	tick()
	if _, rr = get(); rr.Suspicious || rr.Stale || rr.Seq != 11 {
		t.Fatalf("recovery: %+v", rr)
	}
	if chanCalls != 1 {
		t.Errorf("channel list refetched for an immutable release: %d calls", chanCalls)
	}

	// foreign-org pointer on first sight: nothing shown
	e2 := newEnv(t, nil)
	e2.s.relChannels = e.s.relChannels
	e2.s.relFetch = func(_ context.Context, r string) (bundle.Pointer, bool, error) {
		return bundle.Pointer{Org: "evil", Ring: r, Digest: dig("e"), Seq: 1}, true, nil
	}
	rr = decode[ReleasesResponse](t, e2.as(admin, "GET", "/api/v1/releases", "")).Rings[0]
	if rr.Published || rr.Digest != "" || !rr.Suspicious || rr.Stale {
		t.Fatalf("foreign org first sight: %+v", rr)
	}
}
