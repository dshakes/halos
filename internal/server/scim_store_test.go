package server

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestSCIMStoreMembershipIndex: Lookup's groups follow every membership change
// (group put, replace, user delete, group delete), live and on replay.
func TestSCIMStoreMembershipIndex(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenSCIMStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"u1", "u2", "u3"} {
		must(st.PutUser(SCIMUser{ID: id, UserName: id + "@x.example", Active: true}))
	}
	must(st.PutGroup(SCIMGroup{ID: "g1", DisplayName: "eng", Members: []string{"u1", "u2"}}))
	must(st.PutGroup(SCIMGroup{ID: "g2", DisplayName: "ops", Members: []string{"u1", "u3"}}))
	must(st.PutGroup(SCIMGroup{ID: "g1", DisplayName: "eng", Members: []string{"u2"}})) // u1 removed from eng
	must(st.DeleteUser("u3"))
	must(st.PutGroup(SCIMGroup{ID: "g3", DisplayName: "tmp", Members: []string{"u2"}}))
	must(st.DeleteGroup("g3"))

	want := map[string][]string{"u1@x.example": {"ops"}, "U2@X.example": {"eng"}}
	check := func(st SCIMStore, when string) {
		t.Helper()
		for name, groups := range want {
			if _, got, ok := st.Lookup(name); !ok || !slices.Equal(got, groups) {
				t.Errorf("%s: Lookup(%s) = %v %v, want %v", when, name, got, ok, groups)
			}
		}
		if _, _, ok := st.Lookup("u3@x.example"); ok {
			t.Errorf("%s: deleted user still resolves", when)
		}
		if g, _ := st.Group("g2"); !slices.Equal(g.Members, []string{"u1"}) {
			t.Errorf("%s: deleted user still a member of ops: %v", when, g.Members)
		}
	}
	check(st, "live")
	must(st.Close())
	re, err := OpenSCIMStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = re.Close() })
	check(re, "replay")
}

// largeSCIM provisions users users and memberships memberships (spread over
// groups of 20) straight into the store of a SCIM-enabled env.
func largeSCIM(t testing.TB, users, memberships int) (*env, []string) {
	e := scimEnv(t, false, nil)
	ids := make([]string, users)
	for i := range ids {
		ids[i] = fmt.Sprintf("u%05d", i)
		if err := e.s.scim.store.PutUser(SCIMUser{ID: ids[i], UserName: ids[i] + "@x.example", Active: true}); err != nil {
			t.Fatal(err)
		}
	}
	const per = 20
	for g := 0; g*per < memberships; g++ {
		m := make([]string, per)
		for j := range m {
			m[j] = ids[(g*per+j)%users]
		}
		if err := e.s.scim.store.PutGroup(SCIMGroup{ID: fmt.Sprintf("g%05d", g), DisplayName: fmt.Sprintf("group-%05d", g), Members: m}); err != nil {
			t.Fatal(err)
		}
	}
	return e, ids
}

func patchAddAll(t testing.TB, e *env, gid string, ids []string) {
	refs := make([]string, len(ids))
	for i, id := range ids {
		refs[i] = `{"value":"` + id + `"}`
	}
	body := `{"Operations":[{"op":"add","path":"members","value":[` + strings.Join(refs, ",") + `]}]}`
	if w := e.scim("PATCH", "/scim/v2/Groups/"+gid, body); w.Code != 200 {
		t.Fatalf("patch add %d members: %d %s", len(ids), w.Code, w.Body)
	}
}

// TestSCIMScalesLinearly: at 20k users x 30k memberships a gateway-directory
// lookup for every user and one PATCH adding 20k members finish well inside a
// budget a quadratic implementation (every group scanned per lookup, a linear
// Contains per added member) cannot meet.
func TestSCIMScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	e, ids := largeSCIM(t, 20_000, 30_000)
	gid := e.createSCIMGroup(t, "everyone")
	start := time.Now()
	for _, id := range ids {
		if _, _, ok := e.s.scim.store.Lookup(id + "@x.example"); !ok {
			t.Fatalf("lookup %s", id)
		}
	}
	patchAddAll(t, e, gid, ids)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("20k lookups + a 20k-member PATCH add took %v; want < 5s (quadratic membership handling?)", d)
	}
	if _, groups, _ := e.s.scim.store.Lookup(ids[0] + "@x.example"); !slices.Contains(groups, "everyone") {
		t.Fatalf("PATCH add not indexed: %v", groups)
	}
}

func BenchmarkSCIMLookup(b *testing.B) {
	e, ids := largeSCIM(b, 20_000, 30_000)
	i := 0
	for b.Loop() {
		e.s.scim.store.Lookup(ids[i%len(ids)] + "@x.example")
		i++
	}
}

func BenchmarkSCIMPatchAddMembers(b *testing.B) {
	e, ids := largeSCIM(b, 20_000, 30_000)
	for b.Loop() {
		b.StopTimer()
		gid := e.createSCIMGroup(b, fmt.Sprintf("bench-%d", time.Now().UnixNano()))
		b.StartTimer()
		patchAddAll(b, e, gid, ids)
	}
}
