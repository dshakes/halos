package policy

import "testing"

func TestResolveRingUsersBeatGroups(t *testing.T) {
	o := &Org{Rings: []*Ring{
		{Meta: Meta{Name: "a"}, Membership: Membership{Groups: []string{"g"}}},
		{Meta: Meta{Name: "b"}, Membership: Membership{Users: []string{"u@x"}}},
		{Meta: Meta{Name: "ga"}, Membership: Membership{Default: true}},
	}}
	if r := o.ResolveRing(Subject{ID: "u@x", Groups: []string{"g"}}); r == nil || r.Name != "b" {
		t.Fatalf("user list must precede groups, got %v", r)
	}
	if r := o.ResolveRing(Subject{ID: "v@x", Groups: []string{"g"}}); r == nil || r.Name != "a" {
		t.Fatalf("group fallback, got %v", r)
	}
}
