package promote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Forge kinds. ForgeAuto (the zero value) picks from the git remote host.
const (
	ForgeAuto   = ""       // GitLab if the remote host names it, else the gh CLI
	ForgeGH     = "gh"     // git push + the gh CLI (the default; behaviour unchanged)
	ForgeGitHub = "github" // GitHub REST API (github.com or GitHub Enterprise Server)
	ForgeGitLab = "gitlab" // GitLab REST API v4 (gitlab.com or self-managed)
)

// ForgeKinds lists the values --forge accepts, for flag help.
const ForgeKinds = "gh|github|gitlab (default: autodetect from the origin remote; gh unless the host names gitlab)"

// Forge is what callers need from a code host: open a change request for a
// branch Halos pushes with git, and find one it already opened by marker. A
// Forge must never merge, enable auto-merge or approve (invariant 5: a human
// merges). *ForgeOpener implements it for GitHub (gh CLI or REST) and GitLab.
type Forge interface {
	PROpener
	PRFinder
}

// ForgeConfig selects and configures a Forge.
type ForgeConfig struct {
	// Kind is gh, github, gitlab or empty (autodetect).
	Kind string
	// BaseURL overrides the API root: https://ghe.example.com/api/v3 for GitHub
	// Enterprise Server, https://gitlab.example.com/api/v4 for self-managed
	// GitLab. Empty derives it from the origin remote host. https only, or
	// http to a loopback host.
	BaseURL string
}

// ParseForgeKind validates a --forge value.
func ParseForgeKind(s string) (string, error) {
	switch k := strings.ToLower(strings.TrimSpace(s)); k {
	case ForgeAuto, ForgeGH, ForgeGitHub, ForgeGitLab:
		return k, nil
	case "auto":
		return ForgeAuto, nil
	default:
		return "", fmt.Errorf("unknown forge %q: want %s", s, ForgeKinds)
	}
}

// NewForge validates cfg and returns the Forge. The kind is resolved per call
// from the repo's origin remote when cfg.Kind is empty, so one value serves a
// long-lived server whose clone it does not yet know.
func NewForge(cfg ForgeConfig) (*ForgeOpener, error) {
	k, err := ParseForgeKind(cfg.Kind)
	if err != nil {
		return nil, err
	}
	if cfg.BaseURL != "" {
		if k == ForgeGH {
			return nil, errors.New("forge base URL does not apply to the gh CLI; use --forge github or gitlab")
		}
		if _, err := checkBaseURL(cfg.BaseURL); err != nil {
			return nil, err
		}
	}
	return &ForgeOpener{Kind: k, BaseURL: cfg.BaseURL}, nil
}

// ForgeOpener is the Forge. Zero value = autodetect. Fields other than Kind
// and BaseURL are test seams.
type ForgeOpener struct {
	Kind    string
	BaseURL string
	// Exec runs git (and gh); default Run.
	Exec RunFunc
	// HTTP is the API client; default has a 30s timeout.
	HTTP *http.Client
	// Getenv reads token variables; default os.Getenv.
	Getenv func(string) string
}

var _ Forge = (*ForgeOpener)(nil)

func (f *ForgeOpener) run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if f.Exec != nil {
		return f.Exec(ctx, dir, name, args...)
	}
	return Run(ctx, dir, name, args...)
}

func (f *ForgeOpener) env(k string) string {
	if f.Getenv != nil {
		return f.Getenv(k)
	}
	return os.Getenv(k)
}

func (f *ForgeOpener) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Remote is a parsed git remote URL. Userinfo is dropped so it can never reach
// an error message.
type Remote struct {
	Scheme   string // http, https or ssh
	Host     string // host[:port] for http(s); bare host for ssh
	Hostname string
	Path     string // group/sub/repo, no .git
}

// ParseRemote parses an https://, ssh:// or scp-style (git@host:group/repo.git)
// remote URL.
func ParseRemote(raw string) (Remote, error) {
	raw = strings.TrimSpace(raw)
	var r Remote
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return r, errors.New("unparseable git remote URL")
		}
		r.Scheme, r.Hostname, r.Path = strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Path
		r.Host = r.Hostname
		if r.Scheme == "http" || r.Scheme == "https" {
			r.Host = strings.ToLower(u.Host) // an ssh port is not the web port
		}
	} else {
		at := strings.LastIndex(raw, "@")
		colon := strings.Index(raw[at+1:], ":")
		if colon < 0 {
			return r, errors.New("unrecognised git remote URL (want https://host/path or git@host:path)")
		}
		host := raw[at+1 : at+1+colon]
		r.Scheme, r.Host, r.Hostname, r.Path = "ssh", strings.ToLower(host), strings.ToLower(host), raw[at+1+colon+1:]
	}
	r.Path = strings.TrimSuffix(strings.Trim(r.Path, "/"), ".git")
	if r.Hostname == "" || r.Path == "" {
		return r, errors.New("git remote URL has no host or project path")
	}
	return r, nil
}

// DetectForge maps a remote host to a kind. Only a host naming gitlab selects
// GitLab; everything else keeps the gh CLI, so GitHub users see no change.
func DetectForge(hostname string) string {
	if strings.Contains(strings.ToLower(hostname), "gitlab") {
		return ForgeGitLab
	}
	return ForgeGH
}

func (f *ForgeOpener) remote(ctx context.Context, dir string) (Remote, error) {
	out, err := f.run(ctx, dir, "git", "remote", "get-url", "origin")
	if err != nil {
		return Remote{}, fmt.Errorf("promote: forge: read origin remote: %w", err)
	}
	r, err := ParseRemote(string(out))
	if err != nil {
		return r, fmt.Errorf("promote: forge: origin remote: %w", err)
	}
	return r, nil
}

// resolve picks the implementation for the repo in dir.
func (f *ForgeOpener) resolve(ctx context.Context, dir string) (kind string, rem Remote, err error) {
	kind = f.Kind
	if kind == ForgeGH {
		return kind, rem, nil
	}
	if rem, err = f.remote(ctx, dir); err != nil {
		if kind == ForgeAuto {
			return ForgeGH, rem, nil // no readable remote: the gh path reports it as before
		}
		return "", rem, err
	}
	if kind == ForgeAuto {
		kind = DetectForge(rem.Hostname)
	}
	return kind, rem, nil
}

// OpenPR implements PROpener.
func (f *ForgeOpener) OpenPR(ctx context.Context, r PRRequest) (string, error) {
	kind, rem, err := f.resolve(ctx, r.RepoDir)
	if err != nil {
		return "", err
	}
	if kind == ForgeGH {
		return GHOpener{Exec: f.Exec}.OpenPR(ctx, r)
	}
	api, err := f.api(kind, rem)
	if err != nil {
		return "", err
	}
	branch, err := PushBranch(ctx, f.run, r.RepoDir, BranchCommit{
		Branch: r.Branch, Subject: r.Title, Body: r.CommitBody, Edit: prEdit(r),
	})
	if err != nil {
		return "", err
	}
	return api.open(ctx, branch, r)
}

// FindPR implements PRFinder.
func (f *ForgeOpener) FindPR(ctx context.Context, dir, marker string) (string, bool, error) {
	kind, rem, err := f.resolve(ctx, dir)
	if err != nil {
		return "", false, err
	}
	if kind == ForgeGH {
		return GHOpener{Exec: f.Exec}.FindPR(ctx, dir, marker)
	}
	api, err := f.api(kind, rem)
	if err != nil {
		return "", false, err
	}
	return api.find(ctx, marker)
}

// forgeAPI is one REST forge bound to one project.
type forgeAPI interface {
	open(ctx context.Context, branch string, r PRRequest) (string, error)
	find(ctx context.Context, marker string) (string, bool, error)
}

func (f *ForgeOpener) api(kind string, rem Remote) (forgeAPI, error) {
	base := f.BaseURL
	if base == "" {
		scheme := "https"
		if rem.Scheme == "http" {
			scheme = "http"
		}
		switch {
		case kind == ForgeGitLab:
			base = scheme + "://" + rem.Host + "/api/v4"
		case rem.Hostname == "github.com":
			base = "https://api.github.com"
		default:
			base = scheme + "://" + rem.Host + "/api/v3" // GitHub Enterprise Server
		}
	}
	base, err := checkBaseURL(base)
	if err != nil {
		return nil, err
	}
	hc := &httpAPI{base: base, hc: f.client()}
	vars := map[string][]string{ForgeGitLab: {"GITLAB_TOKEN"}, ForgeGitHub: {"GITHUB_TOKEN", "GH_TOKEN"}}[kind]
	hc.vars, hc.getenv = vars, f.env
	// Fail before pushing a branch that no request could then open.
	if _, err := hc.token(); err != nil {
		return nil, err
	}
	switch kind {
	case ForgeGitLab:
		hc.auth = func(req *http.Request, tok string) { req.Header.Set("PRIVATE-TOKEN", tok) }
		hc.hint = gitlabHints
		return &gitlabAPI{c: hc, project: rem.Path}, nil
	case ForgeGitHub:
		hc.auth = func(req *http.Request, tok string) {
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		}
		hc.hint = githubHints
		parts := strings.Split(rem.Path, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("promote: forge github: origin path %q is not owner/repo", rem.Path)
		}
		return &githubAPI{c: hc, owner: parts[0], repo: parts[1]}, nil
	}
	return nil, fmt.Errorf("promote: forge: unsupported kind %q", kind)
}

// checkBaseURL accepts https, or http to a loopback host (tests, local mocks),
// and returns it without a trailing slash. A token is sent to this URL, so
// plaintext to anything else is refused.
func checkBaseURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User != nil {
		return "", errors.New("forge base URL must be an absolute URL without credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("forge base URL: http is allowed to a loopback host only; use https")
		}
	default:
		return "", errors.New("forge base URL must be https (or http to loopback)")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
