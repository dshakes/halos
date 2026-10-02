package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

func TestGatewayPosture(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.GatewayToken = "gw-tok" })
	org, _, _ := e.s.pol.Get()
	ring := org.ResolveRing(policy.Subject{ID: dev.ID}).Name
	dig := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	ch := ring + ".x-cli.treatment"
	ptrs := map[string]bundle.Pointer{
		ring: {Org: org.Name, Ring: ring, Digest: dig("a"), Seq: 1, ExpiresAt: e.now.Add(time.Hour)},
		ch:   {Org: org.Name, Ring: ch, Digest: dig("t"), Seq: 1, ExpiresAt: e.now.Add(time.Hour)},
	}
	e.s.relFetch = func(_ context.Context, r string) (bundle.Pointer, bool, error) { p, ok := ptrs[r]; return p, ok, nil }
	e.s.relChannels = func(context.Context, bundle.Pointer) ([]string, error) { return []string{ch}, nil }

	get := func(auth, subject string) (int, gateway.PostureVerdict) {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/gateway/posture?subject="+subject, nil)
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			return w.Code, gateway.PostureVerdict{}
		}
		return w.Code, decode[gateway.PostureVerdict](t, w)
	}
	want := func(name string, compliant bool, reason string) {
		t.Helper()
		code, v := get("gw-tok", dev.ID)
		if code != 200 || v.Compliant != compliant || !strings.Contains(v.Reason, reason) {
			t.Fatalf("%s: %d %+v, want compliant=%v reason ~%q", name, code, v, compliant, reason)
		}
	}
	report := func(devTok, digest string, drift ...string) {
		t.Helper()
		body := `{"hostname":"laptop-1","ring":"` + ring + `","digest":"` + digest + `","drift":["` + strings.Join(drift, `","`) + `"]}`
		if len(drift) == 0 {
			body = strings.Replace(body, `"drift":[""]`, `"drift":[]`, 1)
		}
		if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+devTok, body).Code; c != 204 {
			t.Fatalf("report: %d", c)
		}
	}

	if code, _ := get("", dev.ID); code != 401 {
		t.Fatalf("no gateway token: %d", code)
	}
	if code, _ := get("gw-tok", ""); code != 400 {
		t.Fatalf("no subject: %d", code)
	}
	want("no device", false, "no enrolled device")

	tok1, d1, err := e.s.devices.mint(dev, *e.now)
	if err != nil {
		t.Fatal(err)
	}
	want("never reported", false, "never reported")
	report(tok1, dig("a"))
	want("on the ring release", true, "")
	report(tok1, dig("t"))
	want("on an experiment channel of the ring release", true, "")
	report(tok1, dig("z"))
	want("off release", false, "not ring "+ring)
	report(tok1, dig("a"), "/etc/claude-code/managed-settings.json")
	want("drift", false, "drift in /etc/claude-code/managed-settings.json")
	report(tok1, dig("a"))
	*e.now = e.now.Add(DefaultPostureMaxAge + time.Minute)
	want("stale", false, "last reported 46m0s ago")
	report(tok1, dig("a"))
	want("fresh again", true, "")

	// a second device that never reports makes the subject non-compliant:
	// a healthy machine cannot cover for one where halod was stopped
	tok2, _, err := e.s.devices.mint(dev, *e.now)
	if err != nil {
		t.Fatal(err)
	}
	want("second device silent", false, "never reported")
	report(tok2, dig("a"))
	want("both healthy", true, "")

	if _, err := e.s.devices.revoke(d1.ID); err != nil {
		t.Fatal(err)
	}
	report(tok2, dig("a"))
	want("revoked device ignored", true, "")

	// Without a registry the release cannot be checked; the rest still is.
	e.s.cfg.Portal.Registry = ""
	report(tok2, dig("z"))
	want("no registry: release unchecked", true, "")

	off := newEnv(t, nil)
	if code := do(off.h, "GET", "/api/v1/gateway/posture?subject=x", "Bearer gw-tok", "").Code; code != 404 {
		t.Fatalf("posture without a gateway token configured: %d", code)
	}
}
