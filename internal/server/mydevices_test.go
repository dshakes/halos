package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A developer sees only their own devices, with the posture verdict the gateway would give.
func TestMyDevices(t *testing.T) {
	e := newEnv(t, nil)
	other := Principal{ID: "other@acme.example"}
	get := func(p Principal) MyDevices {
		t.Helper()
		w := e.as(p, "GET", "/api/v1/me/devices", "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET /me/devices as %s: %d %s", p.ID, w.Code, w.Body)
		}
		return decode[MyDevices](t, w)
	}
	if w := e.as(Principal{}, "GET", "/api/v1/me/devices", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}

	md := get(dev)
	if len(md.Devices) != 0 || md.Posture.Compliant || !strings.Contains(md.Posture.Reason, "no enrolled device") {
		t.Fatalf("before enrollment: %+v", md)
	}

	tok, d, err := e.s.devices.mint(dev, *e.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.s.devices.mint(other, *e.now); err != nil {
		t.Fatal(err)
	}
	md = get(dev)
	if len(md.Devices) != 1 || md.Devices[0].Device.ID != d.ID || md.Devices[0].Last != nil || md.Devices[0].Expired {
		t.Fatalf("enrolled, not reported: %+v", md)
	}
	if md.Posture.Compliant || !strings.Contains(md.Posture.Reason, "never reported") {
		t.Fatalf("posture before first report: %+v", md.Posture)
	}
	if len(get(other).Devices) != 1 {
		t.Fatal("other user's list leaked or missed its own device")
	}

	if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+tok, `{"hostname":"laptop-1","ring":"ring3-ga","digest":"sha256:x","drift":[]}`).Code; c != 204 {
		t.Fatalf("report: %d", c)
	}
	md = get(dev)
	if md.Devices[0].Last == nil || md.Devices[0].Last.Hostname != "laptop-1" || !md.Posture.Compliant {
		t.Fatalf("after report: %+v posture=%+v", md.Devices[0], md.Posture)
	}

	*e.now = e.now.Add(DefaultDeviceTTL + time.Minute)
	md = get(dev)
	if !md.Devices[0].Expired || md.Posture.Compliant {
		t.Fatalf("after ttl: %+v posture=%+v", md.Devices[0], md.Posture)
	}
}

func TestPortalValidateSupportURL(t *testing.T) {
	for _, u := range []string{"https://acme.slack.com/archives/C1", "http://help.local/x", ""} {
		if err := (Portal{SupportURL: u}).Validate(true); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"javascript:alert(1)", "help", "ftp://x/y"} {
		if err := (Portal{SupportURL: u}).Validate(true); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
