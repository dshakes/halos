package onboard

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Check statuses.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// Check is one doctor finding. Fix is the exact command or step that resolves
// a warn or fail; it never contains a secret value.
type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

// Report is the doctor result. OK is false when any check failed.
type Report struct {
	OK          bool         `json:"ok"`
	PolicyDir   string       `json:"policyDir"`
	Checks      []Check      `json:"checks"`
	Harnesses   []Harness    `json:"harnesses"`
	Credentials []Credential `json:"credentials"`
}

// tools are the non-harness programs the onboarding paths use.
var tools = []struct{ bin, why, fix string }{
	{"git", "policy repo and PRs", "install git: https://git-scm.com/downloads"},
	{"gh", "opening the policy PR (company path)", "install the GitHub CLI: https://cli.github.com, then gh auth login"},
	{"docker", "halo quickstart and halo eval run", "install Docker Desktop or Docker Engine with Compose v2: https://docs.docker.com/get-docker/"},
	{"npm", "installing codex, gemini-cli and copilot-cli", "install Node.js 22+: https://nodejs.org"},
	{"halo-proxy", "a local gateway (halo onboard proxy)", "go install github.com/dshakes/halos/cmd/halo-proxy@latest, or the halo-proxy archive from https://github.com/dshakes/halos/releases"},
}

// Doctor checks the machine and the policy repo in dir ("" = skip policy).
func Doctor(ctx context.Context, e Env, dir string) Report {
	r := Report{PolicyDir: dir, Harnesses: Detect(ctx, e), Credentials: Credentials(e)}
	add := func(c Check) { r.Checks = append(r.Checks, c) }

	var org *policy.Org
	pins := map[string]string{}
	if dir != "" {
		org = checkPolicy(dir, add)
		if org != nil {
			for _, p := range org.Profiles {
				for h, s := range p.Harnesses {
					if s.Version != "" {
						pins[h] = s.Version
					}
				}
			}
		}
	}

	installed := 0
	for _, h := range r.Harnesses {
		id := "harness/" + h.Name
		switch {
		case !h.Installed && pins[h.Name] != "":
			add(Check{id, StatusWarn, fmt.Sprintf("%s is pinned to %s by the policy but `%s` is not on PATH", h.Name, pins[h.Name], h.Binary), installFix(h.Name, pins[h.Name], e.GOOS)})
		case !h.Installed:
			add(Check{id, StatusOK, fmt.Sprintf("%s not installed (optional; `%s` not on PATH)", h.Name, h.Binary), ""})
		case h.Version == "":
			installed++
			add(Check{id, StatusWarn, fmt.Sprintf("%s at %s: %s", h.Name, h.Path, h.Error), installFix(h.Name, pins[h.Name], e.GOOS)})
		case pins[h.Name] != "" && pins[h.Name] != h.Version:
			installed++
			add(Check{id, StatusWarn, fmt.Sprintf("%s %s installed, policy pins %s", h.Name, h.Version, pins[h.Name]), installFix(h.Name, pins[h.Name], e.GOOS)})
		default:
			installed++
			add(Check{id, StatusOK, fmt.Sprintf("%s %s at %s", h.Name, h.Version, h.Path), ""})
		}
	}
	if installed == 0 {
		add(Check{"harnesses", StatusWarn, "no AI coding CLI found on PATH (claude, codex, gemini, copilot)",
			installFix("claude-code", "", e.GOOS) + "   # or: " + installFix("codex", "", e.GOOS)})
	}

	for _, t := range tools {
		if p, err := e.LookPath(t.bin); err == nil {
			add(Check{"tool/" + t.bin, StatusOK, t.bin + " at " + p, ""})
		} else {
			add(Check{"tool/" + t.bin, StatusWarn, t.bin + " not on PATH (needed for " + t.why + ")", t.fix})
		}
	}

	if org != nil {
		checkCredentials(e, org, add)
		checkGateway(ctx, e, dir, org, add)
	}

	r.OK = true
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			r.OK = false
		}
	}
	return r
}

func checkPolicy(dir string, add func(Check)) *policy.Org {
	if _, err := os.Stat(filepath.Join(dir, policy.RootFile)); err != nil {
		add(Check{"policy", StatusWarn, fmt.Sprintf("no %s in %s", policy.RootFile, dir),
			"halo onboard local --policy-dir " + dir + " --apply   (or: halo init --policy-dir " + dir + ")"})
		return nil
	}
	org, err := policy.Load(dir)
	if err != nil {
		add(Check{"policy", StatusFail, firstLine(err.Error()), "fix the YAML, then: halo validate --policy-dir " + dir})
		return nil
	}
	var errs []string
	for _, i := range org.Validate() {
		if i.Severity == policy.SeverityError {
			errs = append(errs, i.String())
		}
	}
	if len(errs) > 0 {
		add(Check{"policy", StatusFail, plural(len(errs), "validation error") + ": " + errs[0], "halo validate --policy-dir " + dir})
		return nil
	}
	add(Check{"policy", StatusOK, fmt.Sprintf("org %s: valid, %s", org.Name, plural(len(org.Rings), "ring")), ""})
	return org
}

// checkCredentials reports, per upstream the gateway routes to, whether the
// variable a local halo-proxy would read is set.
func checkCredentials(e Env, org *policy.Org, add func(Check)) {
	if org.Gateway == nil {
		return
	}
	kinds := map[string]bool{}
	for _, u := range org.Gateway.Upstreams {
		kinds[u.Kind] = true
	}
	var ks []string
	for k := range kinds {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		envs := providerEnvs[k]
		if len(envs) == 0 {
			continue
		}
		if anySet(e, envs) {
			add(Check{"credentials/" + k, StatusOK, "one of " + strings.Join(envs, ", ") + " is set (value not shown)", ""})
			continue
		}
		add(Check{"credentials/" + k, StatusWarn, "none of " + strings.Join(envs, ", ") + " is set; a local halo-proxy cannot reach " + k + " and verify will be skipped",
			"export " + envs[0] + "=<your key>   # in your shell; halo never stores or prints it"})
	}
}

func checkGateway(ctx context.Context, e Env, dir string, org *policy.Org, add func(Check)) {
	if org.Gateway == nil || org.Gateway.BaseURL == "" || e.HTTP == nil {
		return
	}
	base := org.Gateway.BaseURL
	code, err := Reachable(ctx, e.HTTP, base)
	if err == nil {
		add(Check{"gateway", StatusOK, fmt.Sprintf("%s answers (HTTP %d)", base, code), ""})
		return
	}
	fix := "point gateway: in halos.yaml at a reachable halo-proxy or Kong, or run one locally: halo onboard proxy --policy-dir " + dir + " --apply"
	if IsLoopback(base) {
		fix = "start the local proxy: halo onboard proxy --policy-dir " + dir + " --apply, then the halo-proxy command it prints"
	}
	add(Check{"gateway", StatusWarn, fmt.Sprintf("%s is not reachable (%s); installing managed config now would point the CLIs at it", base, firstLine(err.Error())), fix})
}

// Reachable reports the HTTP status base answers with; any status counts
// (a gateway answers 401/404 without a token).
func Reachable(ctx context.Context, c *http.Client, base string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// IsLoopback reports whether u's host is localhost or a loopback IP.
func IsLoopback(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := p.Hostname()
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}
