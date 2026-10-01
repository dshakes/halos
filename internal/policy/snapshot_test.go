package policy

import (
	"bytes"
	"strings"
	"testing"
)

func snapOrg() *Org {
	return &Org{
		Name:     "acme",
		Identity: Identity{Issuer: "https://idp.example", Audience: "halo"},
		Gateway: &Gateway{Models: map[string]ModelRoute{"b": {Upstream: "u", Model: "m2"}, "a": {Upstream: "u", Model: "m1"}},
			Upstreams: map[string]Upstream{"u": {URL: "https://x", Kind: "openai"}}},
		Rings: []*Ring{{Meta: Meta{Name: "ga"}, Membership: Membership{Default: true, OptIn: true}}},
	}
}

func TestCompileDeterministicRoundTrip(t *testing.T) {
	a, err := Compile(snapOrg())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // map order must not leak
		b, _ := Compile(snapOrg())
		if !bytes.Equal(a, b) {
			t.Fatal("Compile is not deterministic")
		}
	}
	o, err := ParseSnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "acme" || o.Identity.Issuer != "https://idp.example" || o.Gateway.Models["a"].Model != "m1" || !o.Rings[0].Membership.OptIn {
		t.Fatalf("round trip lost data: %+v", o)
	}
}

func TestParseSnapshotRejects(t *testing.T) {
	good, _ := Compile(snapOrg())
	tests := map[string][]byte{
		"tampered org":  []byte(strings.Replace(string(good), `"Name":"acme"`, `"Name":"evil"`, 1)),
		"bad version":   []byte(strings.Replace(string(good), SnapshotVersion, "halos.dev/snapshot/v9", 1)),
		"not json":      []byte("{"),
		"digest absent": []byte(`{"version":"` + SnapshotVersion + `","org":{}}`),
	}
	for name, b := range tests {
		if _, err := ParseSnapshot(b); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := Compile(nil); err == nil {
		t.Error("nil org must error")
	}
}

func TestParseSnapshotBareOrg(t *testing.T) { // legacy: json.Marshal(*Org)
	o, err := ParseSnapshot([]byte(`{"Name":"legacy"}`))
	if err != nil || o.Name != "legacy" {
		t.Fatalf("%v %+v", err, o)
	}
}
