package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// Runner runs a command line; injectable for tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?`)

// HarnessStatus is per-harness state in a report.
type HarnessStatus struct {
	Want      string `json:"want"`
	Installed string `json:"installed"`
}

// Status is what gets printed and POSTed after every run.
type Status struct {
	Time      time.Time                `json:"time"`
	Hostname  string                   `json:"hostname"`
	User      string                   `json:"user"`
	Ring      string                   `json:"ring"`
	Digest    string                   `json:"digest"`
	Harnesses map[string]HarnessStatus `json:"harnesses"`
	Drift     []string                 `json:"drift"`
	LastError string                   `json:"lastError,omitempty"`
	// ErrorCode classifies LastError for fleet dashboards: "untrusted_owner"
	// (a managed or halod directory is owned by a non-admin: likely squatted) or
	// "sandbox_unavailable" (profile requires the sandbox; bwrap/socat missing)
	// or "no_subject_for_experiment" (the ring runs a client-axis experiment but
	// halod does not know its user id, so it stays on the ring release).
	ErrorCode string `json:"errorCode,omitempty"`
	// Experiment/Variant: the client-axis experiment variant applied (if any).
	Experiment string `json:"experiment,omitempty"`
	Variant    string `json:"variant,omitempty"`
	// Killed: Experiment is on halo-server's signed kill list, so this device
	// runs the ring release (control) and Variant is empty.
	Killed bool `json:"killed,omitempty"`
	// Toggles are the feature toggles applied on this device (on after rule
	// evaluation and the kill list); KilledToggles is the signed kill list's
	// toggle names as of the last apply, so a change triggers a re-apply.
	Toggles       []string `json:"toggles,omitempty"`
	KilledToggles []string `json:"killedToggles,omitempty"`
}

// State is persisted to state.json between runs.
type State struct {
	Digest string `json:"digest"`
	Ring   string `json:"ring"`
	// Subject is the last user id the ring endpoint returned (used when it is unreachable).
	Subject string   `json:"subject,omitempty"`
	Groups  []string `json:"groups,omitempty"` // IdP groups the ring endpoint last returned (toggle targeting)
	Files   []string `json:"files"`            // absolute target paths owned by Digest
	Status  Status   `json:"status"`
	// Pointers is the last applied signed pointer per ring and per experiment
	// channel (anti-rollback; a channel keeps its mark after the device leaves it).
	Pointers map[string]PointerMark `json:"pointers,omitempty"`
	// Installed maps harness -> artifact id halod installed (re-install loop guard).
	Installed map[string]string `json:"installed,omitempty"`
	// Kill is the last accepted signed kill list: it stays in force across
	// restarts, and envelopes issued before it are refused as replays.
	Kill gateway.KillList `json:"kill,omitzero"`
}

// PointerMark is what freshness checks compare the next pointer against.
type PointerMark struct {
	Seq    uint64 `json:"seq"`
	Digest string `json:"digest"`
}

// pointerWarnWindow: halod warns when the ring pointer expires within this.
const pointerWarnWindow = 24 * time.Hour

// Agent applies signed releases. All host access goes through Root, Run and Open.
type Agent struct {
	Cfg       Config
	Root      string // prefix for every path written/read ("" = real filesystem)
	StatePath string // absolute target path of state.json (under Root)
	Run       Runner
	Verifier  bundle.Verifier
	Install   bool
	Host      string
	User      string
	Arch      string // runtime.GOARCH unless testing
	Now       func() time.Time
	HTTP      *http.Client // ring endpoint + report
	Download  *http.Client // install artifacts (long timeout)
	// ConsoleUser, if set, refreshes User each cycle (halod runs as root).
	ConsoleUser func(ctx context.Context) string
	// Open returns the registry source for Cfg.Registry.
	Open func(ctx context.Context) (oras.ReadOnlyTarget, error)
	// Log receives diagnostics (stderr JSON in production); nil = slog.Default().
	// Status JSON is printed to Stdout, not logged.
	Log    *slog.Logger
	Stdout io.Writer // nil = os.Stdout
	// Kill polls the signed kill list (nil = disabled); KillEvery is the
	// kill-poll interval between release pulls (0 = DefaultKillInterval).
	Kill      *gateway.KillSwitch
	KillEvery time.Duration

	// ringRel is the last verified ring release, applied on a kill without a
	// registry round trip. Only the loop goroutine touches it.
	ringRel *cachedRing
	// groups are the device's IdP groups from the ring endpoint (loop goroutine only).
	groups []string
}

type cachedRing struct {
	ring, subject string
	rel           *release.Release
	mark          PointerMark
}

func (a *Agent) log() *slog.Logger {
	if a.Log == nil {
		return slog.Default()
	}
	return a.Log
}

func (a *Agent) path(p string) string {
	if a.Root == "" {
		return p
	}
	if v := filepath.VolumeName(p); v != "" {
		p = p[len(v):]
	}
	return filepath.Join(a.Root, filepath.FromSlash(p))
}

func (a *Agent) loadState() State {
	var s State
	if b, err := os.ReadFile(a.path(a.StatePath)); err == nil {
		_ = json.Unmarshal(b, &s) // corrupt state == first run; files are re-verified by sha anyway
	}
	return s
}

func (a *Agent) saveState(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(a.path(a.StatePath), b, stateMode)
}

// Once performs one pull -> verify -> apply -> report cycle. On any failure
// before verification succeeds nothing on disk is touched (last-good stays).
func (a *Agent) Once(ctx context.Context) (Status, error) {
	return a.runCycle(ctx, func(ctx context.Context, st *Status, prev State) error {
		a.refreshKill(ctx)
		return a.cycle(ctx, st, prev)
	})
}

// runCycle runs f with a fresh Status, classifies its error and reports.
func (a *Agent) runCycle(ctx context.Context, f func(context.Context, *Status, State) error) (Status, error) {
	if a.ConsoleUser != nil {
		a.User = a.ConsoleUser(ctx)
	}
	st := Status{Time: a.Now().UTC(), Hostname: a.Host, User: a.User, Harnesses: map[string]HarnessStatus{}, Drift: []string{}}
	prev := a.loadState()
	st.Ring, st.Digest = prev.Ring, prev.Digest // report last-good until a new release is applied
	st.Experiment, st.Variant, st.Killed = prev.Status.Experiment, prev.Status.Variant, prev.Status.Killed
	err := f(ctx, &st, prev)
	if err != nil {
		st.LastError = err.Error()
		if errors.Is(err, errUntrustedOwner) {
			st.ErrorCode = "untrusted_owner"
		} else if errors.Is(err, errSandboxUnavailable) {
			st.ErrorCode = "sandbox_unavailable"
		} else if errors.Is(err, errNoSubject) {
			st.ErrorCode = "no_subject_for_experiment"
		}
	}
	a.report(ctx, st)
	return st, err
}

// errNoSubject: the ring release lists client-axis experiments but halod has
// no subject id to assign a variant with; it applies the ring release.
var errNoSubject = errors.New("ring runs a client-axis experiment but this device has no subject id (set subject in halod.yaml or enroll via halo-server); staying on the ring release")

func (a *Agent) cycle(ctx context.Context, st *Status, prev State) error {
	ring, subject, err := a.resolveRing(ctx)
	if err != nil {
		if prev.Ring == "" {
			return err // never fall back to "no ring"; first run has nothing to fall back to
		}
		a.log().Warn("ring lookup failed; using last-known ring", "err", err, "ring", prev.Ring)
		ring, subject, a.groups = prev.Ring, prev.Subject, prev.Groups
	}
	if subject == "" {
		subject = a.Cfg.Subject
	}
	src, err := a.Open(ctx)
	if err != nil {
		return fmt.Errorf("open registry: %w", err)
	}
	// PullRing verifies the signed ring pointer (org, ring, seq, expiry) and
	// the release signature before returning anything; every code path below
	// (installs, file writes) only sees a verified, fresh release.
	mark := prev.Pointers[ring]
	now := a.Now()
	rel, p, err := bundle.PullRing(ctx, src, a.Verifier, bundle.RingOptions{
		Org: a.Cfg.Org, Ring: ring, MinSeq: mark.Seq, LastDigest: mark.Digest, Now: now, MaxLayerSize: a.Cfg.MaxBundleBytes,
	})
	if err != nil {
		return fmt.Errorf("pull ring %s (keeping last-good %s): %w", ring, prev.Digest, err)
	}
	a.warnExpiry(ring, p, now)
	marks := map[string]PointerMark{ring: {Seq: p.Seq, Digest: p.Digest}}
	a.ringRel = &cachedRing{ring: ring, subject: subject, rel: rel, mark: marks[ring]}
	rel, err = a.selectVariant(ctx, src, st, prev, ring, subject, rel, marks, now)
	if err != nil && !errors.Is(err, errNoSubject) {
		return fmt.Errorf("keeping last-good %s: %w", prev.Digest, err)
	}
	return errors.Join(a.apply(ctx, st, prev, ring, subject, rel, marks), err)
}

func (a *Agent) warnExpiry(channel string, p bundle.Pointer, now time.Time) {
	if left := p.ExpiresAt.Sub(now); left < pointerWarnWindow {
		a.log().Warn("ring pointer expires soon; publisher must run a refresh or halod will stop updating",
			"ring", channel, "expires_in", left.Round(time.Minute).String(), "expires_at", p.ExpiresAt.Format(time.RFC3339))
	}
}

// selectVariant returns the release this device must apply: the verified
// ring release, or, when that release (built for ring) lists a client-axis
// experiment, the verified release of the subject's variant channel. The
// variant is computed with policy.Experiment.ResolveVariant, the gateway's
// function, from the signed manifest's salt and weights. A channel that fails
// verification fails the cycle (last-good stays): falling back to the ring
// release would silently move treatment devices to control. Without a subject
// it returns the ring release and errNoSubject; it never guesses. An
// experiment on the signed kill list is treated as not running (as gateways
// do): the device is reported in it with Killed and gets the next assigned
// experiment's variant, else the ring release.
func (a *Agent) selectVariant(ctx context.Context, src oras.ReadOnlyTarget, st *Status, prev State, ring, subject string,
	rel *release.Release, marks map[string]PointerMark, now time.Time,
) (*release.Release, error) {
	st.Experiment, st.Variant, st.Killed = "", "", false
	if rel.Manifest.Ring != ring || len(rel.Manifest.Experiments) == 0 {
		return rel, nil
	}
	if subject == "" {
		return rel, errNoSubject
	}
	killed := a.killed()
	for _, e := range rel.Manifest.Experiments {
		v := e.Policy(ring).ResolveVariant(policy.Subject{ID: subject}, ring)
		if v == nil {
			continue
		}
		if killed[e.Name] {
			if st.Experiment == "" {
				st.Experiment, st.Killed = e.Name, true
			}
			continue
		}
		want := policy.ChannelName(ring, e.Name, v.Name)
		var ch string
		for _, mv := range e.Variants {
			if mv.Name == v.Name {
				ch = mv.Channel
			}
		}
		if ch != want {
			return nil, fmt.Errorf("ring %s manifest names channel %q for %s/%s, want %q", ring, ch, e.Name, v.Name, want)
		}
		m := prev.Pointers[ch]
		vrel, p, err := bundle.PullRing(ctx, src, a.Verifier, bundle.RingOptions{
			Org: a.Cfg.Org, Ring: ch, MinSeq: m.Seq, LastDigest: m.Digest, Now: now, MaxLayerSize: a.Cfg.MaxBundleBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("pull experiment channel %s: %w", ch, err)
		}
		if vm := vrel.Manifest; vm.Ring != ring || vm.Experiment != e.Name || vm.Variant != v.Name {
			return nil, fmt.Errorf("channel %s serves %s/%s of ring %s, want %s/%s", ch, vm.Experiment, vm.Variant, vm.Ring, e.Name, v.Name)
		}
		a.warnExpiry(ch, p, now)
		marks[ch] = PointerMark{Seq: p.Seq, Digest: p.Digest}
		st.Experiment, st.Variant, st.Killed = e.Name, v.Name, false
		return vrel, nil
	}
	return rel, nil
}

// refreshKill restores the persisted kill list, fetches and verifies the
// current one (failures keep the last-known list; logged by KillSwitch) and
// persists it once accepted, so a restart cannot be fed an older envelope.
func (a *Agent) refreshKill(ctx context.Context) {
	if a.Kill == nil {
		return
	}
	s := a.loadState()
	a.Kill.Restore(s.Kill)
	if a.Kill.Refresh(ctx) != nil {
		return
	}
	if l := a.Kill.Killed(); l.IssuedAt.After(s.Kill.IssuedAt) {
		s.Kill = l
		if err := a.saveState(s); err != nil {
			a.log().Warn("persist kill list", "err", err)
		}
	}
}

// killed is the set of experiments on the current kill list.
func (a *Agent) killed() map[string]bool {
	m := map[string]bool{}
	for _, e := range a.Kill.Killed().Experiments {
		m[e] = true
	}
	return m
}

// PollKill refreshes the kill list between release pulls. If the device's
// experiment was just killed it applies the cached verified ring release
// (control) at once, pulling only when nothing is cached; if it was unkilled
// it runs a full cycle, which returns it to its variant channel.
// ponytail: only the reported experiment is watched; an unkill of an
// experiment the device fell through from waits for the next full cycle.
func (a *Agent) PollKill(ctx context.Context) error {
	a.refreshKill(ctx)
	prev := a.loadState()
	exp := prev.Status.Experiment
	if exp == "" || a.killed()[exp] == prev.Status.Killed {
		return a.pollToggles(ctx, prev)
	}
	if c := a.ringRel; !prev.Status.Killed && c != nil && c.ring == prev.Ring && c.mark.Seq >= prev.Pointers[c.ring].Seq {
		a.log().Warn("experiment killed; applying the ring release", "experiment", exp, "ring", c.ring)
		_, err := a.runCycle(ctx, func(ctx context.Context, st *Status, prev State) error {
			st.Experiment, st.Variant, st.Killed = exp, "", true
			return a.apply(ctx, st, prev, c.ring, c.subject, c.rel, map[string]PointerMark{c.ring: c.mark})
		})
		return err
	}
	a.log().Warn("kill switch changed for this device's experiment; running a full cycle", "experiment", exp, "killed", !prev.Status.Killed)
	_, err := a.runCycle(ctx, a.cycle)
	return err
}

// pollToggles re-applies when the signed kill list's toggle names differ from
// those the last apply saw, so a killed (or unkilled) toggle takes effect
// within a kill-poll interval, not at the next release pull. A device on the
// ring release re-evaluates the cached verified release with no registry round
// trip; one on a variant channel runs a full cycle, so it never drops to the
// ring release by accident.
func (a *Agent) pollToggles(ctx context.Context, prev State) error {
	cur := slices.Clone(a.Kill.Killed().Toggles)
	sort.Strings(cur)
	if slices.Equal(cur, prev.Status.KilledToggles) {
		return nil
	}
	if c := a.ringRel; prev.Status.Variant == "" && c != nil && c.ring == prev.Ring && c.mark.Seq >= prev.Pointers[c.ring].Seq {
		a.log().Warn("toggle kill list changed; re-applying the ring release", "killed", cur)
		_, err := a.runCycle(ctx, func(ctx context.Context, st *Status, prev State) error {
			return a.apply(ctx, st, prev, c.ring, c.subject, c.rel, map[string]PointerMark{c.ring: c.mark})
		})
		return err
	}
	a.log().Warn("toggle kill list changed; running a full cycle", "killed", cur)
	_, err := a.runCycle(ctx, a.cycle)
	return err
}

// resolveRing returns the device's ring and, from the ring endpoint, its
// subject id (the enrolled user; "" if the endpoint does not say).
func (a *Agent) resolveRing(ctx context.Context) (ring, subject string, err error) {
	a.groups = nil
	if a.Cfg.Ring != "" {
		return a.Cfg.Ring, "", nil
	}
	u := a.Cfg.RingEndpoint + "?" + url.Values{"user": {a.User}, "host": {a.Host}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", fmt.Errorf("ring endpoint: %w", err)
	}
	a.auth(req)
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ring endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ring endpoint: status %d", resp.StatusCode)
	}
	var r struct {
		Ring    string   `json:"ring"`
		Subject string   `json:"subject"`
		Groups  []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return "", "", fmt.Errorf("ring endpoint: decode: %w", err)
	}
	if !ringRe.MatchString(r.Ring) {
		return "", "", fmt.Errorf("ring endpoint returned invalid ring %q", r.Ring)
	}
	if r.Subject != "" && !validSubject(r.Subject) {
		return "", "", fmt.Errorf("ring endpoint returned invalid subject %q", r.Subject)
	}
	if len(r.Groups) > 256 {
		r.Groups = r.Groups[:256] // a bound, not a policy: targeting only matches names it lists
	}
	a.groups = r.Groups
	return r.Ring, r.Subject, nil
}

// apply MUST only be called with a signature-verified release.
// marks are the verified pointers (ring, and the variant channel if any) to record.
func (a *Agent) apply(ctx context.Context, st *Status, prev State, ring, subject string, rel *release.Release, marks map[string]PointerMark) error {
	var errs []error
	next := State{Digest: rel.Digest, Ring: ring, Subject: subject, Groups: a.groups, Pointers: map[string]PointerMark{}, Installed: map[string]string{}, Kill: prev.Kill}
	if l := a.Kill.Killed(); l.IssuedAt.After(next.Kill.IssuedAt) {
		next.Kill = l
	}
	for r, m := range prev.Pointers {
		next.Pointers[r] = m
	}
	for r, m := range marks {
		next.Pointers[r] = m
	}
	on, killedToggles := a.activeToggles(rel, ring, subject)
	st.Toggles, st.KilledToggles = nil, killedToggles
	for _, t := range on {
		st.Toggles = append(st.Toggles, t.Name)
	}
	// A toggle flip rewrites files without a new release: not drift.
	sameRelease := prev.Digest == rel.Digest && slices.Equal(prev.Status.Toggles, st.Toggles)
	owned := map[string]bool{}
	sandboxChecked := false
	names := make([]string, 0, len(rel.Manifest.Harnesses))
	for n := range rel.Manifest.Harnesses {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		he := rel.Manifest.Harnesses[name]
		hs, err := a.ensureHarness(ctx, name, he, prev, &next)
		if err != nil {
			errs = append(errs, fmt.Errorf("install %s@%s: %w", name, he.Version, err))
		}
		st.Harnesses[name] = hs
		files, terrs := a.withToggles(rel, name, he, on)
		errs = append(errs, terrs...)
		for _, af := range files {
			f := af.f
			if err := a.checkTarget(name, f); err != nil {
				errs = append(errs, fmt.Errorf("refusing %s: %w", f.Path, err))
				continue
			}
			owned[f.Path] = true
			data := af.data
			if !af.ok {
				errs = append(errs, fmt.Errorf("blob for %s missing", f.Path))
				continue
			}
			drift, err := a.ensureFile(f, data, sameRelease)
			if err != nil {
				errs = append(errs, fmt.Errorf("write %s: %w", f.Path, err))
				continue
			}
			if drift {
				st.Drift = append(st.Drift, f.Path)
			}
			if a.Cfg.OS == "linux" && !sandboxChecked && requiresSandbox(data) {
				sandboxChecked = true
				if err := a.checkSandboxDeps(); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	// Remove files owned by the previous release that this one no longer ships.
	for _, p := range prev.Files {
		if !owned[p] {
			if !allowedAny(a.Cfg.OS, p) {
				errs = append(errs, fmt.Errorf("state lists %s outside managed locations; not removing", p))
				continue
			}
			if err := checkChain(filepath.Dir(a.path(p))); err != nil {
				errs = append(errs, fmt.Errorf("remove stale %s: %w", p, err))
				continue
			}
			if err := os.Remove(a.path(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove stale %s: %w", p, err))
				owned[p] = true // still ours; retry next cycle
			}
		}
	}
	files := make([]string, 0, len(owned))
	for p := range owned {
		files = append(files, p)
	}
	sort.Strings(files)
	sort.Strings(st.Drift)
	st.Ring, st.Digest = ring, rel.Digest
	next.Files, next.Status = files, *st
	if err := a.saveState(next); err != nil {
		errs = append(errs, fmt.Errorf("save state: %w", err))
	}
	return errors.Join(errs...)
}

// checkTarget enforces the per-harness path allowlist, a mode ceiling of
// 0644, and root-owned, symlink-safe parent directories.
func (a *Agent) checkTarget(harnessName string, f release.FileEntry) error {
	if err := allowedPath(harnessName, a.Cfg.OS, f.Path); err != nil {
		return err
	}
	if f.Mode&^0o644 != 0 {
		return fmt.Errorf("mode %04o exceeds 0644", f.Mode)
	}
	return checkChain(filepath.Dir(a.path(f.Path)))
}

// ensureFile writes f if missing or different. drift is true when the file
// was already managed at this same release yet no longer matches.
func (a *Agent) ensureFile(f release.FileEntry, data []byte, sameRelease bool) (drift bool, err error) {
	p := a.path(f.Path)
	if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() {
		// symlink or special file where a managed file belongs: replace it
		// (rename swaps the link itself; nothing is followed)
		return sameRelease, writeAtomic(p, data, fs.FileMode(f.Mode&0o777))
	}
	cur, rerr := os.ReadFile(p)
	if rerr == nil {
		sum := sha256.Sum256(cur)
		if hex.EncodeToString(sum[:]) == f.SHA256 {
			if runtime.GOOS != "windows" {
				if fi, err := os.Stat(p); err == nil && uint32(fi.Mode().Perm()) != f.Mode&0o777 {
					return sameRelease, os.Chmod(p, fs.FileMode(f.Mode&0o777))
				}
			}
			return false, nil
		}
		drift = sameRelease
	} else if errors.Is(rerr, fs.ErrNotExist) {
		drift = sameRelease
	} else {
		return false, rerr
	}
	return drift, writeAtomic(p, data, fs.FileMode(f.Mode&0o777))
}

// writeAtomic creates path's directory (managedDir secures a new managed
// dir on windows) and writes via fsutil.WriteAtomic (temp, fsync, rename).
func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := mkdirManaged(filepath.Dir(path)); err != nil {
		return err
	}
	return fsutil.WriteAtomic(path, data, mode)
}

// runInstall executes a legacy installCommand (allowShellInstall only).
func (a *Agent) runInstall(ctx context.Context, cmd string) error {
	name, args := "sh", []string{"-c", cmd}
	if a.Cfg.OS == "windows" {
		name, args = "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", cmd}
	}
	if out, err := a.Run(ctx, name, args...); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// report prints st as one JSON line on stdout and POSTs it to ReportURL.
func (a *Agent) report(ctx context.Context, st Status) {
	b, err := json.Marshal(st)
	if err != nil { // plain strings/maps: cannot happen
		a.log().Error("marshal status", "err", err)
		return
	}
	out := a.Stdout
	if out == nil {
		out = os.Stdout
	}
	if _, err := fmt.Fprintln(out, string(b)); err != nil {
		a.log().Warn("print status", "err", err)
	}
	if a.Cfg.ReportURL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Cfg.ReportURL, bytes.NewReader(b))
	if err != nil {
		a.log().Error("report", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	a.auth(req)
	resp, err := a.HTTP.Do(req)
	if err != nil {
		a.log().Warn("report", "err", err)
		return
	}
	_ = resp.Body.Close() // status is all we read
	if resp.StatusCode/100 != 2 {
		a.log().Warn("report rejected", "status", resp.StatusCode)
	}
}

// auth attaches the device token, if configured.
func (a *Agent) auth(req *http.Request) {
	if a.Cfg.DeviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.Cfg.DeviceToken)
	}
}
