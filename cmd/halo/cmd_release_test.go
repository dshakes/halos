package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
)

// Every in-process halo run defaults its signer state under XDG_STATE_HOME:
// never touch the developer's real ~/.local/state.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "halo-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Setenv("XDG_STATE_HOME", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// A registry-level attacker retags ring-<from>, v<ver> and the ring pointer;
// promote, rollback and refresh must not sign what the tags now name.
func TestReleaseRegistryRetagAttack(t *testing.T) {
	ex := buildable(t)
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Cleanup(func() { dialRegistry = old })
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()

	keys := t.TempDir()
	if code, _, errs := halo(t, "keys", "generate", "--out", keys); code != 0 {
		t.Fatalf("keys: %d %s", code, errs)
	}
	key := filepath.Join(keys, "halo.key")
	reg := "registry.test/acme/halos"
	sign := []string{"--registry", reg, "--key", key}
	digests := map[string]string{}
	var oldPtr ocispec.Descriptor
	for _, v := range []string{"1.0.0", "1.1.0"} {
		code, out, errs := halo(t, append([]string{"--output", "json", "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", v}, sign...)...)
		if code != 0 {
			t.Fatalf("publish %s: %d %s", v, code, errs)
		}
		var res struct{ Digest string }
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatal(err)
		}
		digests[v] = res.Digest
		if !strings.Contains(errs, "Signing ring ring3-ga → version "+v+" (digest "+res.Digest) {
			t.Fatalf("publish did not announce the pointer before signing: %s", errs)
		}
		if v == "1.0.0" {
			oldPtr = resolve(t, store, bundle.PointerTag("ring3-ga"))
		}
	}
	v1 := resolve(t, store, "v1.0.0")

	// attacker: ring-ring3-ga and v1.1.0 now name the (genuinely signed) 1.0.0
	for _, tag := range []string{bundle.RingTag("ring3-ga"), "v1.1.0"} {
		if err := store.Tag(ctx, v1, tag); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errs := halo(t, append([]string{"--output", "json", "release", "promote", "--from-ring", "ring3-ga", "--to-ring", "ring2-early"}, sign...)...)
	if code != 0 {
		t.Fatalf("promote: %d %s", code, errs)
	}
	var res struct{ Ring, Version, Digest string }
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("promote json: %v\n%s", err, out)
	}
	if res.Ring != "ring2-early" || res.Version != "1.1.0" || res.Digest != digests["1.1.0"] {
		t.Fatalf("promote followed the retagged ring tag, not the signed pointer: %+v", res)
	}

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"rollback to retagged version", []string{"rollback", "--ring", "ring3-ga", "--to", "1.1.0"}, "registry retag refused"},
		{"promote expect-digest mismatch", []string{"release", "promote", "--from-ring", "ring3-ga", "--to-ring", "ring2-early", "--expect-digest", digests["1.0.0"]}, "expected"},
		{"rollback expect-digest mismatch", []string{"rollback", "--ring", "ring3-ga", "--to", "1.0.0", "--expect-digest", digests["1.1.0"]}, "expected"},
	} {
		if code, _, e := halo(t, append(c.args, sign...)...); code != 1 || !strings.Contains(e, c.want) {
			t.Errorf("%s: %d %s", c.name, code, e)
		}
	}

	// attacker replays the older signed ring3-ga pointer (1.0.0) before the unattended refresh
	cur := resolve(t, store, bundle.PointerTag("ring3-ga"))
	if err := store.Tag(ctx, oldPtr, bundle.PointerTag("ring3-ga")); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(t.TempDir(), "ci.json") // stateless CI run: empty state file
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"refresh with default state", nil, "replayed/rolled-back pointer refused"},
		{"refresh stateless with expect-digest", []string{"--state-file", fresh, "--expect-digest", digests["1.1.0"]}, "has no record of it"},
		{"refresh stateless adopting a replayed pointer still checks expect-digest", []string{"--state-file", fresh, "--adopt-existing", "--expect-digest", digests["1.1.0"]}, "expected " + digests["1.1.0"]},
		{"promote from replayed ring", nil, "replayed"},
	} {
		args := append([]string{"release", "refresh", "--ring", "ring3-ga"}, c.args...)
		if strings.HasPrefix(c.name, "promote") {
			args = []string{"release", "promote", "--from-ring", "ring3-ga", "--to-ring", "ring2-early"}
		}
		if code, _, e := halo(t, append(args, sign...)...); code != 1 || !strings.Contains(e, c.want) {
			t.Errorf("%s: %d %s", c.name, code, e)
		}
	}
	if err := store.Tag(ctx, cur, bundle.PointerTag("ring3-ga")); err != nil {
		t.Fatal(err)
	}
	if code, out, e := halo(t, append([]string{"release", "refresh", "--ring", "ring3-ga", "--expect-digest", digests["1.1.0"]}, sign...)...); code != 0 || !strings.Contains(out, "version 1.1.0") {
		t.Fatalf("refresh of the genuine pointer: %d %s %s", code, out, e)
	}
	// an evicted cache / new state file must not silently drop replay protection
	newState := filepath.Join(t.TempDir(), "new", "pointers.json")
	if code, _, e := halo(t, append([]string{"release", "refresh", "--ring", "ring3-ga", "--state-file", newState}, sign...)...); code != 1 || !strings.Contains(e, "--adopt-existing") {
		t.Fatalf("refresh with a new state file must refuse: %d %s", code, e)
	}
	if code, _, e := halo(t, append([]string{"release", "refresh", "--ring", "ring3-ga", "--state-file", newState, "--adopt-existing"}, sign...)...); code != 0 {
		t.Fatalf("refresh adopting with a new state file: %d %s", code, e)
	}
	bad := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := halo(t, append([]string{"release", "refresh", "--ring", "ring3-ga", "--state-file", bad}, sign...)...); code != 1 || !strings.Contains(e, "parse pointer state") {
		t.Fatalf("corrupt state file: %d %s", code, e)
	}
}

func resolve(t *testing.T, store *memory.Store, tag string) ocispec.Descriptor {
	t.Helper()
	d, err := store.Resolve(context.Background(), tag)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
