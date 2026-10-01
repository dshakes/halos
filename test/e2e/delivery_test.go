//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
)

const pin = "2.1.280" // claude-code version pinned by the test policy

// newPolicy scaffolds a policy repo with `halo init` and shapes it into
// ring0-canary (50%) + ring1-ga (default), claude-code pinned.
func newPolicy(t *testing.T, dir string) {
	t.Helper()
	must(t, nil, "halo", "init", dir, "--org", "acme")
	replaceIn(t, filepath.Join(dir, "rings/ring0-canary.yaml"), "percent: 5\n", "percent: 50\n")
	base := readFile(t, filepath.Join(dir, "profiles/base.yaml"))
	if !strings.Contains(base, "claude-code:\n    version: "+pin+"\n") {
		t.Fatalf("halo init no longer pins claude-code %s; update the test:\n%s", pin, base)
	}
}

type state struct {
	Digest   string `json:"digest"`
	Ring     string `json:"ring"`
	Pointers map[string]struct {
		Seq    uint64 `json:"seq"`
		Digest string `json:"digest"`
	} `json:"pointers"`
}

// TestPolicyReleaseDelivery: halo init/validate -> keys -> publish to a real
// registry -> halod applies it -> tamper / replay refused -> signed rollback applied.
func TestPolicyReleaseDelivery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	newPolicy(t, pol)
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("valid policy: %s", r)
	}

	t.Run("guardrail override rejected", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "policy")
		if err := os.CopyFS(bad, os.DirFS(pol)); err != nil {
			t.Fatal(err)
		}
		replaceIn(t, filepath.Join(bad, "profiles/base.yaml"), "    version: "+pin+"\n",
			"    version: "+pin+"\n    overrides:\n      permissions:\n        defaultMode: bypassPermissions\n")
		r := run(t, nil, "", "halo", "validate", bad)
		if r.code != 2 {
			t.Fatalf("bypassPermissions override: want exit 2, got %s", r)
		}
		if out := r.stdout + r.stderr; !strings.Contains(out, "permissions") {
			t.Fatalf("error does not name the offending key:\n%s", out)
		}
	})

	keys, evilKeys := filepath.Join(dir, "keys"), filepath.Join(dir, "evil")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	must(t, nil, "halo", "keys", "generate", "--out", evilKeys)
	key := filepath.Join(keys, "halo.key")

	repo := repoName(t)
	// --no-artifacts: halo's artifact resolver (cmd/halo newResolver) has no env/flag
	// override, so a fake vendor source cannot be injected into the binary. The
	// resolve -> verified install path is covered by cmd/halod unit tests (httptest
	// vendor) and for real by scripts/smoke-claude.sh (downloads.claude.ai + npm).
	publish := func(ring, ver, key, repo string) result {
		return run(t, nil, "", "halo", "release", "publish", pol, "--ring", ring, "--release-version", ver,
			"--key", key, "--registry", repo, "--plain-http", "--no-artifacts")
	}
	for ring, ver := range map[string]string{"ring0-canary": "1.1.0", "ring1-ga": "1.0.0"} {
		if r := publish(ring, ver, key, repo); r.code != 0 {
			t.Fatalf("publish %s: %s", ring, r)
		}
	}

	// halod sandbox: config + pubkey outside --root (as on a real host), managed files under it.
	root := filepath.Join(dir, "root")
	etc := filepath.Join(dir, "etc")
	writeFile(t, filepath.Join(etc, "release.pub"), readFile(t, filepath.Join(keys, "halo.pub")))
	cfg := filepath.Join(etc, "halod.yaml")
	writeFile(t, cfg, "registry: "+repo+"\norg: acme\nring: ring1-ga\npubkey: "+filepath.Join(etc, "release.pub")+"\nplainHTTP: true\nos: linux\n")
	halodEnv := []string{"SYD_TEST_TRUST_SELF=1"}
	halod := func() result {
		return run(t, halodEnv, "", "halod", "once", "--config", cfg, "--root", root, "--install=false", "--state", "/var/lib/halos/state.json")
	}
	settingsPath := filepath.Join(root, "etc/claude-code/managed-settings.json")
	readState := func() state {
		var s state
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(root, "var/lib/halos/state.json"))), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	settings := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(readFile(t, settingsPath)), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	t.Run("release build refuses unprivileged sandbox", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("running as root: the sandbox is root-owned, nothing to refuse")
		}
		// The trust escape exists only under -tags halodtest; the shipped binary must refuse.
		r := run(t, halodEnv, "", "halod-prod", "once", "--config", cfg, "--root", root, "--install=false", "--state", "/var/lib/halos/state.json")
		if r.code == 0 || !strings.Contains(r.stderr, "must be owned by root") {
			t.Fatalf("release halod accepted a user-owned config: %s", r)
		}
		if _, err := os.Stat(settingsPath); err == nil {
			t.Fatal("release halod wrote managed settings")
		}
	})

	// 1. first apply
	if r := halod(); r.code != 0 {
		t.Fatalf("halod once: %s", r)
	}
	m := settings()
	if m["requiredMinimumVersion"] != pin || m["requiredMaximumVersion"] != pin {
		t.Fatalf("managed-settings version gate = %v..%v, want %s", m["requiredMinimumVersion"], m["requiredMaximumVersion"], pin)
	}
	if m["disableBypassPermissionsMode"] != "disable" {
		t.Fatalf("disableBypassPermissionsMode = %v", m["disableBypassPermissionsMode"])
	}
	s1 := readState()
	if s1.Ring != "ring1-ga" || s1.Pointers["ring1-ga"].Seq == 0 || s1.Pointers["ring1-ga"].Digest != s1.Digest {
		t.Fatalf("state after first apply: %+v", s1)
	}

	src, err := bundle.Repository(repo, true)
	if err != nil {
		t.Fatal(err)
	}
	ptrTag := bundle.PointerTag("ring1-ga")
	p1, err := src.Resolve(ctx, ptrTag)
	if err != nil {
		t.Fatal(err)
	}

	// 2. newer release -> applied, seq increases
	if r := publish("ring1-ga", "1.0.1", key, repo); r.code != 0 {
		t.Fatalf("publish 1.0.1: %s", r)
	}
	if r := halod(); r.code != 0 {
		t.Fatalf("halod once (1.0.1): %s", r)
	}
	s2 := readState()
	if s2.Digest == s1.Digest || s2.Pointers["ring1-ga"].Seq <= s1.Pointers["ring1-ga"].Seq {
		t.Fatalf("1.0.1 not applied: before %+v after %+v", s1, s2)
	}
	good := readFile(t, settingsPath)
	if !strings.Contains(good, "halo.release=1.0.1") {
		t.Fatalf("managed settings not from 1.0.1:\n%s", good)
	}
	p2, err := src.Resolve(ctx, ptrTag)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(t *testing.T, why string) {
		t.Helper()
		if got := readFile(t, settingsPath); got != good {
			t.Fatalf("%s: managed settings changed:\n%s", why, got)
		}
		if s := readState(); s.Digest != s2.Digest || s.Pointers["ring1-ga"] != s2.Pointers["ring1-ga"] {
			t.Fatalf("%s: state changed: %+v", why, s)
		}
	}

	t.Run("replayed older pointer refused", func(t *testing.T) {
		if err := src.Tag(ctx, p1, ptrTag); err != nil { // registry-level attacker re-tags the old signed pointer
			t.Fatal(err)
		}
		r := halod()
		if r.code == 0 || !strings.Contains(r.stderr, "rollback/replay refused") {
			t.Fatalf("replay not refused: %s", r)
		}
		unchanged(t, "replay")
		// ...and the signer's refresh must not launder it into a fresh pointer:
		// its state file (under XDG_STATE_HOME) recorded the 1.0.1 pointer.
		r = run(t, nil, "", "halo", "release", "refresh", "--ring", "ring1-ga", "--key", key, "--registry", repo, "--plain-http")
		if r.code == 0 || !strings.Contains(r.stderr, "replayed/rolled-back pointer refused") {
			t.Fatalf("refresh laundered a replayed pointer: %s", r)
		}
		if cur, err := src.Resolve(ctx, ptrTag); err != nil || cur.Digest != p1.Digest {
			t.Fatalf("refused refresh moved the pointer: %v", err)
		}
	})

	t.Run("foreign-key release refused", func(t *testing.T) {
		// The publisher itself refuses to overwrite a pointer it cannot verify...
		if err := src.Tag(ctx, p2, ptrTag); err != nil {
			t.Fatal(err)
		}
		if r := publish("ring1-ga", "6.6.6", filepath.Join(evilKeys, "halo.key"), repo); r.code == 0 {
			t.Fatalf("publish with a foreign key overwrote the ring: %s", r)
		}
		// ...so the attacker signs in their own repo and copies release + pointer over.
		evilRepo := repoName(t) + "-evil"
		if r := publish("ring1-ga", "6.6.6", filepath.Join(evilKeys, "halo.key"), evilRepo); r.code != 0 {
			t.Fatalf("evil publish: %s", r)
		}
		evil, err := bundle.Repository(evilRepo, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oras.Copy(ctx, evil, "v6.6.6", src, "v6.6.6", oras.DefaultCopyOptions); err != nil {
			t.Fatal(err)
		}
		// (a) informational ring-<ring> tag moved: halod follows only the signed pointer.
		if _, err := oras.Copy(ctx, evil, bundle.RingTag("ring1-ga"), src, bundle.RingTag("ring1-ga"), oras.DefaultCopyOptions); err != nil {
			t.Fatal(err)
		}
		if r := halod(); r.code != 0 {
			t.Fatalf("halod with moved ring tag (genuine pointer): %s", r)
		}
		unchanged(t, "moved ring tag")
		// (b) pointer replaced by one signed with the foreign key.
		if _, err := oras.Copy(ctx, evil, ptrTag, src, ptrTag, oras.DefaultCopyOptions); err != nil {
			t.Fatal(err)
		}
		r := halod()
		if r.code == 0 || !strings.Contains(r.stderr, "keeping last-good") || !strings.Contains(r.stderr, "verify pointer") {
			t.Fatalf("foreign-key pointer not refused: %s", r)
		}
		unchanged(t, "foreign-key pointer")
		if err := src.Tag(ctx, p2, ptrTag); err != nil { // operator restores the genuine pointer
			t.Fatal(err)
		}
	})

	t.Run("signed rollback applied", func(t *testing.T) {
		r := must(t, nil, "halo", "rollback", "--ring", "ring1-ga", "--to", "1.0.0", "--key", key, "--registry", repo, "--plain-http")
		t.Log(strings.TrimSpace(r.stdout))
		if r := halod(); r.code != 0 {
			t.Fatalf("halod once after rollback: %s", r)
		}
		s3 := readState()
		if s3.Digest != s1.Digest || s3.Pointers["ring1-ga"].Seq <= s2.Pointers["ring1-ga"].Seq {
			t.Fatalf("rollback: want digest %s with seq > %d, got %+v", s1.Digest, s2.Pointers["ring1-ga"].Seq, s3)
		}
		if got := readFile(t, settingsPath); !strings.Contains(got, "halo.release=1.0.0") {
			t.Fatalf("managed settings not rolled back:\n%s", got)
		}
	})
}
