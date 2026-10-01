//go:build uat

package k8suat

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/telemetry/gwmetrics"
	"github.com/dshakes/halos/internal/telemetry/synth"
)

var rings = []string{"ring0-harness-team", "ring1-canary", "ring2-early", "ring3-ga"}

const (
	laptopNS, laptop = "uat-device", "laptop"
	halodBin         = "/usr/local/lib/halos/halod"
	halodOnce        = halodBin + " once --config /etc/halos/halod.yaml --state /var/lib/halos/state.json --install=false"
	settingsPath     = "/etc/claude-code/managed-settings.json"
	admin            = "admin@acme.com"
)

// managed config files halod writes on linux (what `halo render --os linux` produces for the ring).
var managed = []string{"/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-mcp.json", "/etc/claude-code/CLAUDE.md",
	"/etc/codex/requirements.toml", "/etc/codex/managed_config.toml", "/etc/gemini-cli/settings.json"}

// u is the shared UAT state threaded through the scenarios (they run in order).
type u struct {
	*env
	r       *report
	org     *policy.Org
	repo    oras.Target
	ver     bundle.Verifier
	version map[string]string // ring -> published version
	mainSHA string            // policy repo main before anything ran: must never move
	byRing  map[string]string // ring -> a user in it (no groups)
	dev     string            // the laptop's developer (group acme-platform-eng)
	devRing string
}

func TestK8sUAT(t *testing.T) {
	e := setup(t)
	s := &u{env: e, r: &report{}, version: map[string]string{}}
	t0 := time.Now()
	versions := strings.TrimSpace(runCmd(t, "", nil, "kind", "version").out) + "; helm " + strings.TrimSpace(runCmd(t, "", nil, "helm", "version", "--short").out) +
		"; kubernetes " + e.kubectl(t, "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kubeletVersion}").out
	defer func() { s.r.write(t, e, versions, time.Since(t0)) }()

	var err error
	if s.org, err = policy.Load(e.policy); err != nil {
		t.Fatal(err)
	}
	s.byRing = map[string]string{}
	for i := 0; i < 2000 && len(s.byRing) < len(rings)-1; i++ { // ring0 is group-only
		u := fmt.Sprintf("dev%d@acme.com", i)
		if r := s.org.ResolveRing(policy.Subject{ID: u}); r != nil && s.byRing[r.Name] == "" {
			s.byRing[r.Name] = u
		}
	}
	s.byRing["ring0-harness-team"] = admin
	s.dev = "dana@acme.com"
	s.devRing = s.org.ResolveRing(policy.Subject{ID: s.dev, Groups: []string{"acme-platform-eng"}}).Name
	s.mainSHA = strings.Fields(runCmd(t, "", nil, "git", "ls-remote", gitRemote, "refs/heads/main").out + " ?")[0]
	pub, _ := os.ReadFile(filepath.Join(e.work, "keys/halo.pub"))
	v, err := bundle.ParseEd25519Verifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	s.ver = v
	repo, err := bundle.Repository(hostReg, true)
	if err != nil {
		t.Fatal(err)
	}
	s.repo = repo

	for _, sc := range []struct {
		name string
		fn   func(*testing.T, *u)
	}{
		{"a platform engineer", platform}, {"b developer device", device}, {"c traffic", traffic},
		{"d toggles", toggles}, {"f shadow", shadowScenario}, {"e rollout + g evidence", rollout}, {"h ops", ops},
	} {
		if !t.Run(sc.name, func(t *testing.T) { sc.fn(t, s) }) && sc.name[0] <= 'b' {
			t.Fatalf("%s failed: later scenarios depend on it", sc.name) // releases + enrolled device
		}
	}
}

// ---------------- a. platform engineer ----------------

func platform(t *testing.T, s *u) {
	const sc = "a platform"
	ctx := context.Background()
	key := filepath.Join(s.work, "keys/halo.key")
	run := time.Now().Unix() % 1000000
	r := s.haloCLI(t, "validate", "--policy-dir", s.policy)
	s.r.check(t, sc, "halo validate (examples/acme-corp + UAT upstream overlay)", r.code == 0, "%s", firstLine(r.out+r.err))
	// A second running traffic experiment routing the same alias on a shared ring would silently get
	// no traffic at the gateway (only the first by name routes): validate must refuse it.
	bad := filepath.Join(s.work, fmt.Sprint("overlap-", run))
	if err := os.CopyFS(bad, os.DirFS(s.policy)); err != nil {
		t.Fatal(err)
	}
	rival, _ := os.ReadFile(filepath.Join(bad, "experiments/uat-ok.yaml"))
	if err := os.WriteFile(filepath.Join(bad, "experiments/uat-ok-rival.yaml"), []byte(strings.Replace(string(rival), "name: uat-ok\n", "name: uat-ok-rival\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r = s.haloCLI(t, "validate", "--policy-dir", bad)
	s.r.check(t, sc, "halo validate refuses two running traffic experiments routing one alias on a ring", r.code == 2 &&
		strings.Contains(r.out+r.err, `"uat-ok" and "uat-ok-rival" both route alias "fast" on ring "ring3-ga"`), "exit %d: %s", r.code, grepLine(r.out+r.err, "both route"))

	for i, ring := range rings {
		s.version[ring] = fmt.Sprintf("1.%d.%d", run, i) // unique per run: version tags are immutable
		r := s.haloCLI(t, "release", "publish", "--policy-dir", s.policy, "--ring", ring, "--release-version", s.version[ring],
			"--key", key, "--registry", hostReg, "--plain-http", "--no-artifacts")
		s.r.check(t, sc, "halo release publish "+ring+" v"+s.version[ring]+" to the in-cluster registry", r.code == 0, "%s", lastLine(r.out+r.err))
	}
	r = s.haloCLI(t, "plan", "--policy-dir", s.policy, "--ring", "ring1-canary", "--against", hostReg+":"+bundle.RingTag("ring1-canary"),
		"--pubkey", filepath.Join(s.work, "keys/halo.pub"), "--plain-http", "--release-version", "1.0.9")
	s.r.check(t, sc, "halo plan ring1-canary against the published release (verified)", r.code == 0, "%s", firstLine(r.out+r.err))

	ptr := map[string]bundle.Pointer{}
	for _, ring := range rings {
		p, found, err := bundle.ReadPointer(ctx, s.repo, ring, s.ver)
		ptr[ring] = p
		s.r.check(t, sc, "signed pointer "+ring+" verifies", found && err == nil && p.Org == "acme-corp" && p.Ring == ring && p.Seq > 0,
			"org=%s ring=%s seq=%d digest=%.19s err=%v", p.Org, p.Ring, p.Seq, p.Digest, err)
	}
	evilPub := genKey(t, s.env, "evil")
	ev, _ := bundle.ParseEd25519Verifier(evilPub)
	_, _, err := bundle.ReadPointer(ctx, s.repo, "ring1-canary", ev)
	s.r.check(t, sc, "pointer does not verify under a foreign key", err != nil, "err=%v", err)

	r = s.haloCLI(t, "release", "promote", "--from-ring", "ring0-harness-team", "--to-ring", "ring1-canary", "--key", key, "--registry", hostReg, "--plain-http")
	p1, _, err := bundle.ReadPointer(ctx, s.repo, "ring1-canary", s.ver)
	s.r.check(t, sc, "promote ring0 -> ring1 (signed pointer re-pointed)", r.code == 0 && err == nil && p1.Digest == ptr["ring0-harness-team"].Digest && p1.Seq > ptr["ring1-canary"].Seq,
		"ring1 now %.19s (ring0 %.19s) seq %d->%d; %s", p1.Digest, ptr["ring0-harness-team"].Digest, ptr["ring1-canary"].Seq, p1.Seq, lastLine(r.out+r.err))

	r = s.haloCLI(t, "rollback", "--ring", "ring1-canary", "--to", s.version["ring1-canary"], "--key", key, "--registry", hostReg, "--plain-http")
	p2, _, err := bundle.ReadPointer(ctx, s.repo, "ring1-canary", s.ver)
	s.r.check(t, sc, "rollback ring1 to v"+s.version["ring1-canary"]+" (re-point, new seq)", r.code == 0 && err == nil && p2.Digest == ptr["ring1-canary"].Digest && p2.Seq > p1.Seq,
		"ring1 back at %.19s seq %d; %s", p2.Digest, p2.Seq, lastLine(r.out+r.err))
}

func genKey(t *testing.T, e *env, name string) []byte {
	t.Helper()
	dir := filepath.Join(e.work, "keys-"+name)
	if _, err := os.Stat(filepath.Join(dir, "halo.pub")); err == nil {
		// generated by an earlier run against this work dir (UAT_KEEP)
	} else if r := e.haloCLI(t, "keys", "generate", "--out", dir); r.code != 0 {
		t.Fatal(r)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "halo.pub"))
	return b
}

// ---------------- b. developer device ----------------

func device(t *testing.T, s *u) {
	const sc = "b device"
	ctx := context.Background()
	c := s.login(t, s.dev, "acme-platform-eng")
	resp, body := do(t, c, "POST", portalURL+"/api/v1/launch/laptop", "", nil)
	var launch struct{ Token, Bash string }
	_ = json.Unmarshal([]byte(body), &launch)
	if !s.r.check(t, sc, "portal OIDC login + laptop launch (device flow token)", resp.StatusCode == 200 && launch.Token != "" && strings.Contains(launch.Bash, portalURL+"/enroll.sh"),
		"%s: %s", resp.Status, redact(launch.Bash, launch.Token)+redact(errBody(resp.StatusCode, body), launch.Token)) {
		t.FailNow()
	}
	r := s.sh(t, laptopNS, laptop, "", launch.Bash)
	s.r.check(t, sc, "laptop runs the portal's enroll.sh (halod download checksum-pinned, device token issued)", r.code == 0 && strings.Contains(r.out, "enrolled"), "%s", lastLine(r.out+r.err))
	cfg := s.sh(t, laptopNS, laptop, "", "stat -c '%a %U' /etc/halos/halod.yaml && cat /etc/halos/halod.yaml")
	s.r.check(t, sc, "enrolled halod.yaml is root-owned 0600 with ring endpoint + plainHTTP registry", strings.HasPrefix(cfg.out, "600 root") &&
		strings.Contains(cfg.out, "ringEndpoint: "+portalURL+"/api/v1/fleet/ring") && strings.Contains(cfg.out, "plainHTTP: true") && strings.Contains(cfg.out, "registry: "+podReg),
		"%s", strings.ReplaceAll(firstLine(cfg.out), "\n", " "))

	r = s.sh(t, laptopNS, laptop, "", halodOnce)
	s.r.check(t, sc, "halod once: pull + verify + apply the ring release", r.code == 0, "exit %d %s", r.code, grepLine(r.err, "rror"))
	st := s.state(t)
	p, _, _ := bundle.ReadPointer(ctx, s.repo, s.devRing, s.ver)
	s.r.check(t, sc, "device on its ring's signed release", st.Ring == s.devRing && st.Digest == p.Digest, "user %s ring %s digest %.19s (pointer %.19s)", s.dev, st.Ring, st.Digest, p.Digest)
	missing := []string{}
	for _, f := range managed {
		if s.sh(t, laptopNS, laptop, "", "test -s "+f).code != 0 {
			missing = append(missing, f)
		}
	}
	s.r.check(t, sc, "Claude/Codex/Gemini managed config at the linux managed paths", len(missing) == 0, "files %v; missing %v", managed, missing)
	set := s.settings(t)
	s.r.check(t, sc, "claude managed-settings from this release, bypass mode disabled", strings.Contains(set, "halo.release="+s.version[s.devRing]) &&
		strings.Contains(set, `"disableBypassPermissionsMode": "disable"`) && !strings.Contains(set, "bypassPermissions\""), "halo.release=%s present", s.version[s.devRing])

	adminC := s.login(t, admin, "ai-platform")
	_, fleet := do(t, adminC, "GET", portalURL+"/api/v1/fleet", "", nil)
	s.r.check(t, sc, "device reported to halo-server (admin fleet view)", strings.Contains(fleet, `"user":"`+s.dev+`"`) && strings.Contains(fleet, st.Digest), "fleet has %s @ %.19s", s.dev, st.Digest)

	// Tamper: an attacker with registry write access swaps the ring pointer for one signed with their key.
	ptrTag := bundle.PointerTag(s.devRing)
	good, err := s.repo.Resolve(ctx, ptrTag)
	if err != nil {
		t.Fatal(err)
	}
	genKey(t, s.env, "attacker")
	evilRepoRef := strings.Replace(hostReg, "/halos", "/evil", 1)
	if r := s.haloCLI(t, "release", "publish", "--policy-dir", s.policy, "--ring", s.devRing, "--release-version", "6.6.6",
		"--key", filepath.Join(s.work, "keys-attacker/halo.key"), "--registry", evilRepoRef, "--plain-http", "--no-artifacts"); r.code != 0 {
		t.Fatal(r)
	}
	evil, _ := bundle.Repository(evilRepoRef, true)
	before := s.settings(t)
	if _, err := oras.Copy(ctx, evil, ptrTag, s.repo, ptrTag, oras.DefaultCopyOptions); err != nil {
		t.Fatal(err)
	}
	r = s.sh(t, laptopNS, laptop, "", halodOnce)
	s.r.check(t, sc, "tampered (foreign-key) release refused, last-good kept", r.code != 0 && strings.Contains(r.err, "verify pointer") && s.settings(t) == before && s.state(t).Digest == st.Digest,
		"exit %d: %s", r.code, grepLine(r.err, "verify pointer"))
	if err := s.repo.Tag(ctx, good, ptrTag); err != nil { // operator restores the genuine pointer
		t.Fatal(err)
	}
	r = s.sh(t, laptopNS, laptop, "", halodOnce)
	s.r.check(t, sc, "genuine pointer restored: halod applies again", r.code == 0, "%s", lastLine(r.out+r.err))
	// halod as a service from here on (toggle kill polling).
	if r := s.sh(t, laptopNS, laptop, "", "setsid nohup "+strings.Replace(halodOnce, " once ", " run ", 1)+" >/var/log/halod.log 2>&1 &"); r.code != 0 {
		t.Fatal(r)
	}
}

type devState struct {
	Ring, Digest string
	Status       struct{ Toggles, KilledToggles []string }
}

func (s *u) state(t *testing.T) devState {
	t.Helper()
	var st devState
	r := s.sh(t, laptopNS, laptop, "", "cat /var/lib/halos/state.json")
	_ = json.Unmarshal([]byte(r.out), &st)
	return st
}

func (s *u) settings(t *testing.T) string {
	t.Helper()
	return s.sh(t, laptopNS, laptop, "", "cat "+settingsPath).out
}

// ---------------- c. traffic ----------------

type reply struct {
	code                                      int
	servedBy, model, ring, variant, exp, body string
}

func (s *u) send(t *testing.T, tok, model string, hdr map[string]string) reply {
	t.Helper()
	h := map[string]string{"anthropic-version": "2023-06-01"}
	if tok != "" {
		h["Authorization"] = "Bearer " + tok
	}
	for k, v := range hdr {
		h[k] = v
	}
	resp, body := do(t, s.client(), "POST", proxyURL+"/v1/messages", fmt.Sprintf(`{"model":%q,"max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`, model), h)
	return reply{resp.StatusCode, resp.Header.Get("X-Mock-Served-By"), resp.Header.Get("X-Mock-Model"), resp.Header.Get("X-Seen-X-Halo-Ring"),
		resp.Header.Get("X-Seen-X-Halo-Variant"), resp.Header.Get("X-Seen-X-Halo-Experiment"), body}
}

func traffic(t *testing.T, s *u) {
	const sc = "c traffic"
	for _, ring := range rings {
		user := s.byRing[ring]
		var groups []string
		if user == admin {
			groups = []string{"ai-platform"}
		}
		rp := s.send(t, s.mint(t, user, groups...), "haiku", map[string]string{"x-halo-ring": "ring0-harness-team", "x-halo-variant": "spoofed", "x-halo-user": "ceo@acme.com"})
		if ring == "ring0-harness-team" {
			rp = s.send(t, s.mint(t, user, groups...), "haiku", map[string]string{"x-halo-ring": "ring3-ga", "x-halo-variant": "spoofed"})
		}
		s.r.check(t, sc, "valid JWT ("+ring+") reaches the upstream with ring stamped; spoofed x-halo-* stripped",
			rp.code == 200 && rp.servedBy == "mock-a" && rp.model == "claude-haiku-4-5" && rp.ring == ring && rp.variant != "spoofed" && !strings.Contains(rp.body, "ceo@acme.com"),
			"%d served-by=%s model=%s upstream saw x-halo-ring=%s (client sent a spoofed ring/variant/user)", rp.code, rp.servedBy, rp.model, rp.ring)
	}
	ga := s.mint(t, s.byRing["ring3-ga"])
	rp := s.send(t, ga, "gpt-4o", nil)
	s.r.check(t, sc, "unknown model denied (fail closed), upstream never hit", rp.code == 400 && rp.servedBy == "" && strings.Contains(rp.body, "invalid_request_error"), "%d %s", rp.code, rp.body)
	rp = s.send(t, "", "haiku", map[string]string{"x-halo-user": "dev1@acme.com", "x-halo-ring": "ring0-harness-team"})
	s.r.check(t, sc, "no token (header-only identity) is 401", rp.code == 401 && rp.servedBy == "", "%d", rp.code)
	forger, _ := identitytest.NewIssuer("uat-1") // same kid and issuer URL, different key
	forger.URL = idpURL
	ftok, _ := forger.Mint(map[string]any{"aud": audience, "email": s.byRing["ring3-ga"]})
	rp = s.send(t, ftok, "haiku", nil)
	s.r.check(t, sc, "forged JWT (right iss/kid, wrong key) is 401", rp.code == 401, "%d", rp.code)
	_, wrongAud := do(t, s.client(), "GET", idpURL+"/mint?user=dev1@acme.com&aud=someone-else", "", nil)
	rp = s.send(t, wrongAud, "haiku", nil)
	s.r.check(t, sc, "JWT for another audience is 401", rp.code == 401, "%d", rp.code)

	served := map[string]int{}
	for i := 0; i < 40; i++ {
		rp := s.send(t, ga, "default", map[string]string{"x-claude-code-session-id": fmt.Sprintf("split-%d", i)})
		served[rp.servedBy+"/"+rp.model]++
	}
	a, b := served["mock-a/claude-split-a"], served["mock-b/claude-split-b"]
	s.r.check(t, sc, "weighted 50/50 route split across two upstreams", a+b == 40 && a >= 8 && b >= 8, "40 sessions: %v", served)
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		rp := s.send(t, ga, "default", map[string]string{"x-claude-code-session-id": "sticky-1"})
		seen[rp.servedBy] = true
	}
	s.r.check(t, sc, "split is sticky per user+session", len(seen) == 1, "10 requests, one session: %v", keys(seen))
	rp = s.send(t, ga, "opus", nil)
	s.r.check(t, sc, "failover: primary upstream refuses, secondary serves", rp.code == 200 && rp.servedBy == "mock-a" && rp.model == "claude-opus-fallback",
		"%d served-by=%s model=%s (primary mock-down has no endpoints)", rp.code, rp.servedBy, rp.model)

	// Canary uat-ok (75/25 on alias "fast", ring3): assignment is per user, sticky across requests and replicas.
	byVariant := map[string][]string{}
	for i := 0; len(byVariant["treatment"]) < 2 || len(byVariant["control"]) < 2; i++ {
		if i > 400 {
			t.Fatalf("no users in both arms: %v", byVariant)
		}
		user := fmt.Sprintf("canary%d@acme.com", i)
		if s.org.ResolveRing(policy.Subject{ID: user}).Name != "ring3-ga" {
			continue
		}
		rp := s.send(t, s.mint(t, user), "fast", nil)
		want := map[string]string{"control": "mock-a/fast-base", "treatment": "mock-b/fast-next"}[rp.variant]
		if rp.servedBy+"/"+rp.model != want {
			s.r.check(t, sc, "canary variant routes", false, "%s variant=%q served %s/%s", user, rp.variant, rp.servedBy, rp.model)
			return
		}
		byVariant[rp.variant] = append(byVariant[rp.variant], user)
	}
	sticky := true
	for v, users := range byVariant {
		for _, user := range users[:2] {
			tok := s.mint(t, user)
			for i := 0; i < 10; i++ {
				if rp := s.send(t, tok, "fast", nil); rp.variant != v {
					sticky = false
				}
			}
		}
	}
	s.r.check(t, sc, "canary experiment assignment is sticky (both proxy replicas)", sticky, "2 control + 2 treatment users x 10 requests, fresh connection each; treatment -> mock-b/fast-next")

	// uat-ok (fast) and uat-bad (slow) run on the same ring: each claims only its own alias.
	per := map[string]map[string]int{}
	for i := 0; i < 400 && len(per["fast"])+len(per["slow"]) < 4; i++ {
		user := fmt.Sprintf("canary%d@acme.com", i)
		if s.org.ResolveRing(policy.Subject{ID: user}).Name != "ring3-ga" {
			continue
		}
		tok := s.mint(t, user)
		for _, alias := range []string{"fast", "slow", "haiku"} {
			rp := s.send(t, tok, alias, nil)
			want := map[string]string{"fast": "uat-ok", "slow": "uat-bad", "haiku": ""}[alias]
			next := map[string]string{"fast": "fast-next", "slow": "slow-next"}[alias]
			if rp.exp != want || (rp.variant == "treatment") != (rp.model == next && next != "") {
				s.r.check(t, sc, "concurrent canaries on different aliases of one ring", false, "%s %s: experiment %q variant %q model %s, want experiment %q", user, alias, rp.exp, rp.variant, rp.model, want)
				return
			}
			if per[alias] == nil {
				per[alias] = map[string]int{}
			}
			if want != "" {
				per[alias][rp.variant]++
			}
		}
	}
	s.r.check(t, sc, "concurrent canaries on different aliases of one ring: each request carries only the experiment that routed it",
		len(per["fast"]) == 2 && len(per["slow"]) == 2, "ring3: fast -> uat-ok %v, slow -> uat-bad %v, haiku -> no experiment", per["fast"], per["slow"])
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------- d. toggles ----------------

func toggles(t *testing.T, s *u) {
	const sc = "d toggles"
	ctx := context.Background()
	adminTok := s.mint(t, admin, "ai-platform")
	rp := s.send(t, adminTok, "sonnet", nil)
	s.r.check(t, sc, "traffic toggle sonnet-next-route ON for its cohort (ring0) at the gateway", rp.servedBy == "mock-b" && rp.model == "claude-sonnet-5-5", "admin -> %s/%s", rp.servedBy, rp.model)
	rp = s.send(t, s.mint(t, s.byRing["ring3-ga"]), "sonnet", nil)
	s.r.check(t, sc, "... and OFF outside it", rp.servedBy == "mock-a" && rp.model == "claude-sonnet-4-5", "ring3 user -> %s/%s", rp.servedBy, rp.model)
	s.r.check(t, sc, "client toggle format-hook ON on the device (group acme-platform-eng)", strings.Contains(s.settings(t), "acme-format-hook"), "managed-settings.json carries the hook")

	ptrs := map[string]string{}
	for _, ring := range rings {
		p, _, _ := bundle.ReadPointer(ctx, s.repo, ring, s.ver)
		ptrs[ring] = p.Digest
	}
	st0 := s.state(t)
	sess := session(s.login(t, admin, "ai-platform"))
	t0 := time.Now()
	for _, tg := range []string{"sonnet-next-route", "format-hook"} {
		r := s.sh(t, laptopNS, laptop, "", "HALO_SERVER="+portalURL+" HALO_SESSION="+sess+" halo toggle kill "+tg+" --reason 'uat: kill drill'")
		s.r.check(t, sc, "halo toggle kill "+tg+" via the halo-server API (admin session)", r.code == 0, "%s", lastLine(r.out+r.err))
	}
	gw := waitFor(t, 60*time.Second, "gateway toggle off", func() bool { rp := s.send(t, adminTok, "sonnet", nil); return rp.model == "claude-sonnet-4-5" })
	s.r.check(t, sc, "killed traffic toggle OFF at the gateway within its poll interval (2s)", gw <= 10*time.Second, "off after %s", gw.Round(100*time.Millisecond))
	waitFor(t, 3*time.Minute, "device toggle off", func() bool { return !strings.Contains(s.settings(t), "acme-format-hook") })
	dv := time.Since(t0) // measured from the kill
	s.r.check(t, sc, "killed client toggle OFF on the device within halod's kill-poll interval (60s)", dv <= 75*time.Second, "hook gone %s after the kill", dv.Round(time.Second))
	same := true
	for _, ring := range rings {
		p, _, _ := bundle.ReadPointer(ctx, s.repo, ring, s.ver)
		same = same && p.Digest == ptrs[ring]
	}
	st := s.state(t)
	s.r.check(t, sc, "no release needed: ring pointers and the device's release digest unchanged", same && st.Digest == st0.Digest && contains(st.Status.KilledToggles, "format-hook"),
		"device digest %.19s, killedToggles %v", st.Digest, st.Status.KilledToggles)
	for _, tg := range []string{"sonnet-next-route", "format-hook"} {
		s.sh(t, laptopNS, laptop, "", "HALO_SERVER="+portalURL+" HALO_SESSION="+sess+" halo toggle kill "+tg+" --unkill --reason 'uat: drill over'")
	}
	back := waitFor(t, 60*time.Second, "gateway toggle back", func() bool { return s.send(t, adminTok, "sonnet", nil).model == "claude-sonnet-5-5" })
	s.r.check(t, sc, "unkill restores the toggle at the gateway", true, "back on after %s", back.Round(100*time.Millisecond))
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------- f. shadow ----------------

func shadowScenario(t *testing.T, s *u) {
	const sc = "f shadow"
	shadowed, plain := s.mint(t, s.byRing["ring2-early"]), s.mint(t, s.byRing["ring3-ga"])
	lat := func(tok string) (time.Duration, reply) {
		var ds []time.Duration
		var last reply
		for i := 0; i < 7; i++ {
			t0 := time.Now()
			last = s.send(t, tok, "sonnet", map[string]string{"x-claude-code-session-id": fmt.Sprintf("shadow-%d", i)})
			ds = append(ds, time.Since(t0))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2], last
	}
	dS, rS := lat(shadowed)
	dP, _ := lat(plain)
	s.r.check(t, sc, "mirrored request answered by the primary only", rS.code == 200 && rS.servedBy == "mock-a" && rS.model == "claude-sonnet-4-5" && !strings.Contains(rS.body, "mock-b"),
		"ring2 (100%% shadow) -> %s/%s", rS.servedBy, rS.model)
	s.r.check(t, sc, "shadow does not add primary latency", dS <= dP+250*time.Millisecond, "median %s shadowed vs %s unshadowed", dS.Round(time.Millisecond), dP.Round(time.Millisecond))

	// Read the pairs file off the halo-shadow PVC (distroless pod: no shell) from a pod running as the same uid.
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pairs-reader","namespace":"` + s.ns + `"},"spec":{"securityContext":{"runAsUser":65532,"runAsNonRoot":true},` +
		`"containers":[{"name":"r","image":"halos-uat/infra:uat","imagePullPolicy":"Never","command":["sleep","3600"],"volumeMounts":[{"name":"d","mountPath":"/data","readOnly":true}]}],` +
		`"volumes":[{"name":"d","persistentVolumeClaim":{"claimName":"halos-halo-shadow-pairs","readOnly":true}}]}}`
	runCmd(t, pod, nil, "kubectl", "--context", s.ctx, "apply", "-f", "-")
	defer s.kubectl(t, "-n", s.ns, "delete", "pod", "pairs-reader", "--wait=false")
	s.kubectl(t, "-n", s.ns, "wait", "--for=condition=Ready", "pod/pairs-reader", "--timeout=120s")
	var pair string
	waitFor(t, 60*time.Second, "a stored shadow pair", func() bool {
		for _, l := range strings.Split(s.sh(t, s.ns, "pairs-reader", "", "cat /data/pairs.jsonl 2>/dev/null").out, "\n") {
			if strings.Contains(l, `"sonnet-next-shadow"`) && strings.Contains(l, "served-by=mock-a model=claude-sonnet-4-5") && strings.Contains(l, "served-by=mock-b model=claude-sonnet-next") {
				pair = l
				return true
			}
		}
		return false
	})
	s.r.check(t, sc, "first-turn request stored as a control/candidate pair on the PVC", pair != "", "pair: control mock-a/claude-sonnet-4-5, candidate mock-b/claude-sonnet-next (%d bytes)", len(pair))
}

// ---------------- e. rollout + g. evidence ----------------

func rollout(t *testing.T, s *u) {
	const sce, scg = "e rollout", "g evidence"
	ctx := context.Background()
	// A uat-bad treatment user, routed to the candidate before anything happens.
	var badUser string
	for i := 0; badUser == "" && i < 400; i++ {
		user := fmt.Sprintf("slow%d@acme.com", i)
		if s.org.ResolveRing(policy.Subject{ID: user}).Name == "ring3-ga" {
			if rp := s.send(t, s.mint(t, user), "slow", nil); rp.variant == "treatment" && rp.exp == "uat-bad" {
				badUser = user
				s.r.check(t, sce, "uat-bad treatment routed to the candidate before the rollback", rp.servedBy == "mock-b" && rp.model == "slow-next", "%s -> %s/%s", user, rp.servedBy, rp.model)
			}
		}
	}
	if badUser == "" {
		t.Fatal("no uat-bad treatment user")
	}

	// Gateway evidence through the collector's authenticated gateway receiver (ingress :4319),
	// using halo-proxy's own emitter: uat-ok arms equal (enough units for the guardrail's
	// confidence bound to clear 15%), uat-bad treatment latency x1.6.
	em, err := gwmetrics.New(gwmetrics.Config{OTLPEndpoint: "http://127.0.0.1:30319", Protocol: gwmetrics.ProtoProtobuf, UnitSalt: "uat", TokenFile: filepath.Join(s.work, "otel-gateway.token")})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(11))
	for _, x := range []struct {
		exp, alias, ring string
		mult, sigma      float64
		users            int
	}{{"uat-ok", "fast", "ring3-ga", 1, 0.1, 250}, {"uat-bad", "slow", "ring3-ga", 1.6, 0.3, 40}} {
		for _, arm := range []string{"control", "treatment"} {
			m := 1.0
			if arm == "treatment" {
				m = x.mult
			}
			for u := 0; u < x.users; u++ {
				for i := 0; i < 20; i++ {
					em.Record(gwmetrics.Request{Ring: x.ring, Release: "uat", Experiment: x.exp, Variant: arm, Harness: "claude-code", Model: x.alias,
						Subject: fmt.Sprintf("%s-%s-%d@acme.com", x.exp, arm, u), Status: 200,
						Latency: time.Duration(1000 * m * math.Exp(x.sigma*rng.NormFloat64()) * float64(time.Millisecond))})
				}
			}
		}
	}
	if err := em.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// CLI evidence through the open CLI receiver (ingress :4318).
	m, l := synth.Generate(synth.Config{Seed: 5, Now: time.Now().UTC(), UsersPerArm: 5, SessionsPerUser: 2, BaseCostUSD: 0.5},
		[]synth.Cohort{{Experiment: "uat-cli", Variant: "control", Ring: "ring3-ga", Release: "uat", CostMult: 1, AcceptRate: 0.7, LatencyMult: 1, APIErrorRate: 0.03, ToolErrorRate: 0.05}})
	if err := synth.Send(ctx, "http://127.0.0.1:30318", m, l); err != nil {
		t.Fatal(err)
	}
	ch := func(sql string) float64 { return s.chNum(t, sql) }
	waitFor(t, 90*time.Second, "evidence rows in ClickHouse", func() bool {
		return ch("SELECT count() FROM halo_metrics WHERE experiment='uat-bad' AND metric='halo.gateway.requests'") >= 2 &&
			ch("SELECT count() FROM halo_metrics WHERE experiment='uat-cli'") > 0
	})
	units := ch("SELECT uniqExact(unit_id) FROM halo_metrics WHERE experiment='uat-bad' AND release='uat' AND metric='halo.gateway.requests' AND attrs['halo.source']='gateway'")
	s.r.check(t, scg, "gateway telemetry (authenticated OTLP) lands in ClickHouse as halo.source=gateway", units == 80, "%v units for uat-bad", units)
	cli := ch("SELECT countIf(attrs['halo.source']='cli') FROM halo_metrics WHERE experiment='uat-cli'")
	s.r.check(t, scg, "CLI telemetry (open OTLP receiver) lands in ClickHouse as halo.source=cli", cli > 0, "%v rows", cli)
	// Real requests from scenarios c/d/f (the synthetic evidence above is release "uat").
	live := ch("SELECT sum(value) FROM halo_metrics WHERE metric='halo.gateway.requests' AND attrs['halo.source']='gateway' AND release!='uat'")
	s.r.check(t, scg, "live halo-proxy traffic from these scenarios exported to ClickHouse", live > 0, "%v proxied requests recorded by the in-cluster proxies", live)
	const real = " FROM halo_metrics WHERE metric='halo.gateway.requests' AND attrs['halo.source']='gateway' AND release!='uat'"
	okN, badN := ch("SELECT sum(value)"+real+" AND experiment='uat-ok'"), ch("SELECT sum(value)"+real+" AND experiment='uat-bad'")
	wrong := ch("SELECT count()" + real + " AND ((experiment='uat-ok' AND model NOT IN ('fast-base','fast-next')) OR (experiment='uat-bad' AND model NOT IN ('slow-base','slow-next')))")
	s.r.check(t, scg, "gateway evidence attributes each real request to the experiment that routed it", okN > 0 && badN > 0 && wrong == 0,
		"uat-ok %v requests (fast-* only), uat-bad %v (slow-* only), %v misattributed rows", okN, badN, wrong)

	verdict := func(exp string) (v, src string) {
		r := s.haloCLI(t, "exp", "analyze", exp, "--policy-dir", s.policy, "--clickhouse", chURL, "--database", "halo", "--user", "halo", "--output", "json")
		var rep struct{ Verdict, Reason, Source string }
		_ = json.Unmarshal([]byte(r.out), &rep)
		return rep.Verdict, rep.Source + " " + rep.Reason + firstLine(r.err)
	}
	v, why := verdict("uat-bad")
	s.r.check(t, scg, "halo exp analyze uat-bad: rollback on gateway evidence", v == "rollback" && strings.HasPrefix(why, "gateway"), "%s: %s", v, why)
	v, why = verdict("uat-ok")
	s.r.check(t, scg, "halo exp analyze uat-ok: no rollback for equal arms", v != "rollback" && v != "", "%s: %s", v, why)
	r := s.haloCLI(t, "rollout", "status", "uat-ok", "--policy-dir", s.policy, "--clickhouse", chURL, "--database", "halo", "--user", "halo")
	s.r.check(t, sce, "halo rollout status uat-ok reads the live gates", r.code == 0 && strings.Contains(r.out, "canary-25"), "%s", firstLine(r.out+r.err))

	// The in-cluster controller (halo-server --controller, 1m tick) acts on the same evidence.
	var branches string
	took := waitFor(t, 6*time.Minute, "controller PR branches on the git remote", func() bool {
		branches = runCmd(t, "", nil, "git", "ls-remote", "--heads", gitRemote).out
		return strings.Contains(branches, "refs/heads/halos/rollout-uat-bad-rollback") && strings.Contains(branches, "refs/heads/halos/rollout-uat-ok-canary-50")
	})
	clone := filepath.Join(s.work, "remote-"+fmt.Sprint(time.Now().Unix()))
	runCmd(t, "", nil, "git", "clone", "-q", gitRemote, clone)
	show := func(prefix, file string) string {
		for _, l := range strings.Split(branches, "\n") {
			if f := strings.Fields(l); len(f) == 2 && strings.HasPrefix(f[1], "refs/heads/"+prefix) {
				return runCmd(t, "", nil, "git", "-C", clone, "show", "origin/"+strings.TrimPrefix(f[1], "refs/heads/")+":"+file).out
			}
		}
		return ""
	}
	adv, advExp := show("halos/rollout-uat-ok-canary-50", "rollouts/uat-ok.yaml"), show("halos/rollout-uat-ok-canary-50", "experiments/uat-ok.yaml")
	s.r.check(t, sce, "healthy step: controller pushes an advance PR branch (canary-25 -> canary-50)", strings.Contains(adv, "step: canary-50") && strings.Contains(advExp, "weight: 50"),
		"branch halos/rollout-uat-ok-canary-50* after %s", took.Round(time.Second))
	rb, rbExp := show("halos/rollout-uat-bad-rollback", "rollouts/uat-bad.yaml"), show("halos/rollout-uat-bad-rollback", "experiments/uat-bad.yaml")
	s.r.check(t, sce, "regression: controller pushes a rollback PR branch (rollout aborted, experiment paused)", strings.Contains(rb, "status: aborted") && strings.Contains(rbExp, "status: paused"), "branch halos/rollout-uat-bad-rollback*")
	main := strings.Fields(runCmd(t, "", nil, "git", "ls-remote", gitRemote, "refs/heads/main").out + " ?")[0]
	s.r.check(t, sce, "never merges: main untouched", main == s.mainSHA, "main %s", main)

	// The rollback tripped the signed kill switch; gateways verify and honour it.
	gwTok := s.file("gateway.token")
	_, body := do(t, s.client(), "GET", portalURL+"/api/v1/gateway/killswitch", "", map[string]string{"Authorization": "Bearer " + gwTok})
	var envl gateway.KillEnvelope
	_ = json.Unmarshal([]byte(body), &envl)
	kpub, _ := os.ReadFile(filepath.Join(s.work, "keys/killswitch.pub"))
	kv, _ := bundle.ParseEd25519Verifier(kpub)
	list, err := gateway.VerifyKillList(kv.Key, envl, time.Now(), 5*time.Minute)
	s.r.check(t, sce, "auto-rollback trips the signed kill switch (verified with the kill-switch key)", err == nil && contains(list.Experiments, "uat-bad"), "experiments=%v err=%v", list.Experiments, err)
	tok := s.mint(t, badUser)
	after := waitFor(t, 30*time.Second, "gateway honouring the kill", func() bool {
		rp := s.send(t, tok, "slow", nil)
		return rp.servedBy == "mock-a" && rp.model == "slow-base"
	})
	s.r.check(t, sce, "gateways honour the kill: treatment user back on the control route", true, "%s -> mock-a/slow-base within %s", badUser, after.Round(100*time.Millisecond))
}

func (s *u) chNum(t *testing.T, sql string) float64 {
	t.Helper()
	req, _ := http.NewRequest("POST", chURL+"/?database=halo", strings.NewReader(sql+" FORMAT TabSeparated"))
	req.Header.Set("X-ClickHouse-User", "halo")
	req.Header.Set("X-ClickHouse-Key", s.file("clickhouse.password"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var f float64
	b := make([]byte, 4096)
	n, _ := resp.Body.Read(b)
	if resp.StatusCode != 200 {
		t.Fatalf("clickhouse %d: %s", resp.StatusCode, b[:n])
	}
	_, _ = fmt.Sscan(strings.TrimSpace(string(b[:n])), &f)
	return f
}

// ---------------- h. ops ----------------

func ops(t *testing.T, s *u) {
	const sc = "h ops"
	// Pod security: every chart container non-root, read-only rootfs, no privilege escalation.
	var pods struct {
		Items []struct {
			Metadata struct{ Name string }
			Spec     struct {
				SecurityContext struct {
					RunAsNonRoot *bool
					RunAsUser    *int64
				}
				Containers, InitContainers []struct {
					Name            string
					SecurityContext struct {
						ReadOnlyRootFilesystem, AllowPrivilegeEscalation, RunAsNonRoot *bool
						Capabilities                                                   struct{ Drop []string }
					}
				}
			}
		}
	}
	_ = json.Unmarshal([]byte(s.kubectl(t, "-n", s.ns, "get", "pods", "-l", "app.kubernetes.io/instance=halos", "-o", "json").out), &pods)
	bad, n := []string{}, 0
	for _, p := range pods.Items {
		for _, c := range append(p.Spec.Containers, p.Spec.InitContainers...) {
			n++
			sc := c.SecurityContext
			if !isTrue(p.Spec.SecurityContext.RunAsNonRoot) || !isTrue(sc.ReadOnlyRootFilesystem) || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || !contains(sc.Capabilities.Drop, "ALL") {
				bad = append(bad, p.Metadata.Name+"/"+c.Name)
			}
		}
	}
	s.r.check(t, sc, "all chart pods non-root, read-only rootfs, no privilege escalation, caps dropped", n > 0 && len(bad) == 0, "%d containers in %d pods; violations %v", n, len(pods.Items), bad)
	r := s.sh(t, s.ns, "deploy/halos-server", "halo-server", "id -u; touch /uat-probe 2>&1; true")
	s.r.check(t, sc, "runtime: halo-server runs as uid 65532 and cannot write its rootfs", strings.HasPrefix(r.out, "65532") && strings.Contains(r.out, "Read-only file system"), "%s", strings.ReplaceAll(strings.TrimSpace(r.out), "\n", "; "))

	// /healthz + metrics, from the monitoring-allowed namespace (uat-infra).
	probe := func(ns, pod, url string) string {
		return strings.TrimSpace(s.sh(t, ns, pod, "", "curl -s -o /dev/null -m 4 -w '%{http_code}' "+url+"; echo \" $?\"").out)
	}
	for _, x := range []struct{ what, url string }{
		{"halo-server /healthz", "http://halos-server.halos-uat/healthz"},
		{"halo-server controller /metrics", "http://halos-server.halos-uat:9092/metrics"},
		{"halo-proxy admin /healthz", "http://halos-proxy.halos-uat:9090/healthz"},
		{"halo-proxy admin /metrics", "http://halos-proxy.halos-uat:9090/metrics"},
		{"halo-shadow /metrics", "http://halos-halo-shadow.halos-uat:9091/metrics"},
		{"otel collector /metrics", "http://halos-otel.halos-uat:8889/metrics"},
	} {
		got := probe("uat-infra", "deploy/dl", x.url)
		s.r.check(t, sc, x.what+" exposed", strings.HasPrefix(got, "200"), "%s -> %s", x.url, got)
	}
	// NetworkPolicy: an unrelated namespace is blocked from everything; uat-infra only where allowed.
	for _, url := range []string{"http://halos-proxy.halos-uat/v1/models", "http://halos-server.halos-uat/healthz", "http://halos-halo-shadow.halos-uat:8090/healthz",
		"http://halos-otel.halos-uat:4318/v1/metrics", "http://halos-proxy.halos-uat:9090/metrics"} {
		got := probe("uat-outsider", "outsider", url)
		s.r.check(t, sc, "NetworkPolicy blocks uat-outsider -> "+strings.TrimPrefix(url, "http://"), strings.HasPrefix(got, "000"), "curl: %s (000 = no connection)", got)
	}
	got := probe("uat-infra", "deploy/dl", "http://halos-halo-shadow.halos-uat:8090/healthz")
	s.r.check(t, sc, "NetworkPolicy: halo-shadow only accepts halo-proxy (ingress namespace blocked)", strings.HasPrefix(got, "000"), "curl: %s", got)
	allowed := s.sh(t, s.ns, "deploy/halos-server", "halo-server", "wget -q -T 4 -O /dev/null http://registry.uat-infra:5000/v2/ && echo ok").out
	denied := s.sh(t, s.ns, "deploy/halos-server", "halo-server", "wget -q -T 4 -O /dev/null http://mock-a.uat-infra:9000/v1/models && echo LEAK || echo blocked").out
	s.r.check(t, sc, "NetworkPolicy egress: halo-server reaches only its allowed targets", strings.Contains(allowed, "ok") && strings.Contains(denied, "blocked"),
		"registry:5000 %s, mock upstream:9000 %s", strings.TrimSpace(allowed), strings.TrimSpace(denied))

	// Zero-downtime helm upgrade: proxy rolls (2 replicas, maxUnavailable 0, preStop) under constant load.
	tok := s.mint(t, s.byRing["ring3-ga"])
	var ok, failed atomic.Int64
	var fails sync.Map
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := s.client()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest("POST", proxyURL+"/v1/messages", strings.NewReader(`{"model":"haiku","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`))
				req.Header.Set("Authorization", "Bearer "+tok)
				req.Header.Set("Content-Type", "application/json")
				resp, err := c.Do(req)
				if err == nil && resp.StatusCode == 200 {
					ok.Add(1)
				} else {
					failed.Add(1)
					k := fmt.Sprint(err)
					if resp != nil {
						k = resp.Status
					}
					fails.Store(k, true)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	time.Sleep(2 * time.Second)
	before := s.kubectl(t, "-n", s.ns, "get", "pods", "-l", "app.kubernetes.io/component=proxy", "-o", "name").out
	r = s.helm(t, "upgrade", "halos", "../../../deploy/helm/halos", "--reuse-values", "--set-string", "proxy.podAnnotations.uat-upgrade="+fmt.Sprint(time.Now().Unix()), "--wait", "--timeout", "5m")
	time.Sleep(3 * time.Second)
	close(stop)
	wg.Wait()
	after := s.kubectl(t, "-n", s.ns, "get", "pods", "-l", "app.kubernetes.io/component=proxy", "-o", "name").out
	var fk []string
	fails.Range(func(k, _ any) bool { fk = append(fk, k.(string)); return true })
	s.r.check(t, sc, "helm upgrade rolls both proxy replicas with zero failed requests", r.code == 0 && failed.Load() == 0 && ok.Load() > 50 && before != after,
		"%d ok / %d failed %v during the rollout; pods %s -> %s", ok.Load(), failed.Load(), fk, oneLine(before), oneLine(after))

	r = s.helm(t, "uninstall", "halos", "--wait", "--timeout", "3m")
	var left string
	gone := func() bool { // pods are garbage-collected after their ReplicaSets, within their grace period
		left = s.kubectl(t, "-n", s.ns, "get", "deploy,sts,ds,svc,pod,cm,secret,sa,networkpolicy,pdb,hpa,job", "-l", "app.kubernetes.io/instance=halos", "-o", "name").out
		return strings.TrimSpace(left) == ""
	}
	for end := time.Now().Add(2 * time.Minute); !gone() && time.Now().Before(end); time.Sleep(2 * time.Second) {
	}
	pvcs := s.kubectl(t, "-n", s.ns, "get", "pvc", "-l", "app.kubernetes.io/instance=halos", "-o", "name").out
	rel := s.helm(t, "list", "-q").out
	s.r.check(t, sc, "helm uninstall is clean (only PVCs kept, by their helm.sh/resource-policy: keep)", r.code == 0 && strings.TrimSpace(left) == "" && !strings.Contains(rel, "halos"),
		"left: [%s]; kept PVCs: [%s]", oneLine(left), oneLine(pvcs))
}

func isTrue(b *bool) bool { return b != nil && *b }

// ---------------- small helpers ----------------

func firstLine(s string) string { return strings.SplitN(strings.TrimSpace(s), "\n", 2)[0] }

func lastLine(s string) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	return l[len(l)-1]
}

func grepLine(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			if len(l) > 220 {
				l = l[:220]
			}
			return l
		}
	}
	return lastLine(s)
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// redact keeps one-time credentials out of the committed report.
func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<token>")
}

func errBody(code int, body string) string {
	if code == 200 {
		return ""
	}
	return " " + body
}
