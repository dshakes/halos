// Package onboard is the deterministic core of `halo doctor` and `halo
// onboard`: detect the AI CLIs on this machine, check the environment and
// print exact fixes, plan and apply a local install of a ring's managed
// config, generate a local halo-proxy config, run a headless round trip, and
// generate a company rollout bundle. Agents (the halos-onboard skill, the MCP
// tools) call these; nothing here asks questions or decides policy.
//
// Secrets: credential checks only report whether an environment variable is
// set, never its value, and verify output is redacted before it is returned.
package onboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters
)

// Runner runs a program and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Env is everything onboarding reads from the machine, injectable for tests.
type Env struct {
	Run      Runner
	LookPath func(string) (string, error)
	Getenv   func(string) string
	GOOS     string
	HTTP     *http.Client // nil: skip network checks
}

// System is the real machine.
func System() Env {
	return Env{
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed harness binaries and flags
		},
		LookPath: exec.LookPath,
		Getenv:   os.Getenv,
		GOOS:     runtime.GOOS,
		HTTP:     &http.Client{Timeout: 3 * time.Second},
	}
}

// Harness is one AI CLI as found on PATH.
type Harness struct {
	Name      string `json:"name"`
	Binary    string `json:"binary"`
	Installed bool   `json:"installed"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

var semver = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?`)

// Detect probes every registered harness's binary with --version.
func Detect(ctx context.Context, e Env) []Harness {
	var out []Harness
	for _, n := range harness.Names() {
		m, _ := harness.MetaOf(n)
		h := Harness{Name: n, Binary: m.Binary}
		if m.Binary == "" {
			out = append(out, h)
			continue
		}
		p, err := e.LookPath(m.Binary)
		if err != nil {
			out = append(out, h)
			continue
		}
		h.Installed, h.Path = true, p
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		b, err := e.Run(cctx, p, "--version")
		cancel()
		if v := semver.FindString(string(b)); v != "" {
			h.Version = v
		} else if err != nil {
			h.Error = "--version failed: " + firstLine(err.Error())
		} else {
			h.Error = "no version in --version output"
		}
		out = append(out, h)
	}
	return out
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// Credential reports whether a credential variable is set. Never its value.
type Credential struct {
	Env     string `json:"env"`
	For     string `json:"for"`
	Present bool   `json:"present"`
}

// providerEnvs are the variables each provider's upstream (or CLI) reads.
var providerEnvs = map[string][]string{
	"anthropic": {"ANTHROPIC_API_KEY"},
	"openai":    {"OPENAI_API_KEY"},
	"gemini":    {"GEMINI_API_KEY", "GOOGLE_API_KEY"},
	"bedrock":   {"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_BEARER_TOKEN_BEDROCK"},
	"vertex":    {"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"},
}

// harnessEnvs are the variables a CLI authenticates with in headless mode.
// A CLI can also be logged in (OAuth, keychain); halo cannot see that without
// reading credential stores, so verify takes --assume-auth for it.
var harnessEnvs = map[string][]string{
	"claude-code": {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"},
	"codex":       {"OPENAI_API_KEY", "CODEX_API_KEY"},
	"gemini-cli":  {"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"},
	"copilot-cli": {"COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"},
}

// Credentials lists every known credential variable and whether it is set.
func Credentials(e Env) []Credential {
	var out []Credential
	seen := map[string]bool{}
	add := func(env, what string) {
		if seen[env] {
			return
		}
		seen[env] = true
		out = append(out, Credential{Env: env, For: what, Present: e.Getenv(env) != ""})
	}
	for _, p := range []string{"anthropic", "openai", "gemini", "bedrock", "vertex"} {
		for _, v := range providerEnvs[p] {
			add(v, "provider "+p)
		}
	}
	for _, h := range harness.Names() {
		for _, v := range harnessEnvs[h] {
			add(v, h)
		}
	}
	return out
}

func anySet(e Env, envs []string) bool {
	for _, v := range envs {
		if e.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// redact removes the value of every known credential variable from s.
func redact(e Env, s string) string {
	for _, c := range Credentials(e) {
		if v := e.Getenv(c.Env); len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[redacted "+c.Env+"]")
		}
	}
	return s
}

// installFix is the command that installs harness h at version (pin or "latest").
func installFix(h, version, goos string) string {
	a, ok := harness.Get(h)
	if !ok {
		return ""
	}
	if version == "" {
		version = "latest"
	}
	return a.InstallCommand(version, harness.OS(goos))
}

// ErrNotFound marks a missing policy repo.
var ErrNotFound = errors.New("no halos.yaml")

func plural(n int, s string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, s)
	}
	return fmt.Sprintf("%d %ss", n, s)
}
