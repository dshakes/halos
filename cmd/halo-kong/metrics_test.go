package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAccessHeaderCap: Kong hands the plugin at most maxHeaders header lines
// and truncates silently, so a request at the cap is a 431 before identity is
// derived: a duplicate identity header or an x-halo-* name past the cap would
// otherwise be invisible.
func TestAccessHeaderCap(t *testing.T) {
	pol := testPolicy(t)
	for _, c := range []struct {
		name  string
		extra int
		exit  int
	}{{"below the cap", maxHeaders - 2, 0}, {"at the cap", maxHeaders - 1, http.StatusRequestHeaderFieldsTooLarge}} {
		hdrs := map[string][]string{"x-acme-user": {"alice"}}
		for i := range c.extra {
			hdrs[fmt.Sprintf("x-pad-%d", i)] = []string{"v"}
		}
		k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: hdrs}
		trustedCfg(pol).access(k)
		if k.exitStatus != c.exit {
			t.Fatalf("%s: exit %d %s", c.name, k.exitStatus, k.exitBody)
		}
		if c.exit != 0 && len(k.set) != 0 {
			t.Fatalf("%s: headers set on a refused request: %v", c.name, k.set)
		}
	}
	// Repeated values count as header lines, as Kong counts them.
	k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn),
		hdrs: map[string][]string{"x-acme-user": {"alice"}, "x-pad": make([]string, maxHeaders-1)}}
	trustedCfg(pol).access(k)
	if k.exitStatus != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("repeated header at the cap: exit %d", k.exitStatus)
	}
	var b strings.Builder
	kmetrics.write(&b)
	if strings.Contains(b.String(), "halo_kong_header_cap_rejections_total 0\n") {
		t.Fatalf("header cap rejection not counted:\n%s", b.String())
	}
}

func TestDumpOnly(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{{nil, false}, {[]string{"-dump"}, true}, {[]string{"--dump"}, true}, {[]string{"-kong-prefix", "/k"}, false}} {
		if got := dumpOnly(c.args); got != c.want {
			t.Errorf("dumpOnly(%v) = %v", c.args, got)
		}
	}
}

func TestServeMetrics(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	kmetrics.agentDenied()
	serveMetrics(addr)
	var resp *http.Response
	for range 50 { // the listener starts in the background
		if resp, err = http.Get("http://" + addr + "/metrics"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"# TYPE halo_kong_agent_denials_total counter", "halo_kong_directory_resolutions_total", "halo_kong_header_cap_rejections_total"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("metrics lack %q:\n%s", want, b)
		}
	}
}
