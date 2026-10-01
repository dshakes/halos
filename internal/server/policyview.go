package server

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// policyHolder loads the policy dir and reloads it when any file's mtime/size
// changes (checked per request) or after Invalidate (SIGHUP).
type policyHolder struct {
	dir string
	log *slog.Logger

	mu    sync.Mutex
	org   *policy.Org
	view  PolicyView
	sig   string
	force bool
	err   error
}

// Invalidate forces a reload on the next read.
func (p *policyHolder) Invalidate() { p.mu.Lock(); p.force = true; p.mu.Unlock() }

func dirSig(dir string) string {
	var latest time.Time
	var n, size int64
	if r, err := filepath.EvalSymlinks(dir); err == nil { // git-sync: dir is a symlink to the current worktree
		dir = r
	}
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			n++
			size += fi.Size()
			if fi.ModTime().After(latest) {
				latest = fi.ModTime()
			}
		}
		return nil
	})
	return fmt.Sprint(latest.UnixNano(), "/", n, "/", size)
}

// Get returns the current org (nil + error if the dir has never loaded).
// A failed reload keeps serving the last good policy and returns its error.
func (p *policyHolder) Get() (*policy.Org, PolicyView, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if sig := dirSig(p.dir); p.force || sig != p.sig || p.org == nil && p.err == nil {
		p.force, p.sig = false, sig
		org, err := policy.Load(p.dir)
		if err != nil {
			p.err = err
			p.log.Error("policy reload failed", "dir", p.dir, "err", err)
		} else {
			p.err, p.org, p.view = nil, org, buildPolicyView(org)
			p.log.Info("policy loaded", "org", org.Name, "rings", len(org.Rings), "experiments", len(org.Experiments))
		}
	}
	return p.org, p.view, p.err
}

// PolicyView is the JSON shape of GET /api/v1/policy.
type PolicyView struct {
	Org         string           `json:"org"`
	Gateway     *policy.Gateway  `json:"gateway,omitempty"`
	Rings       []RingView       `json:"rings"`
	Profiles    []string         `json:"profiles"`
	Experiments []ExperimentView `json:"experiments"`
	Issues      []IssueView      `json:"issues"`
}

type RingView struct {
	Name       string            `json:"name"`
	Order      int               `json:"order"`
	Profile    string            `json:"profile"`
	Release    string            `json:"release,omitempty"`
	Membership policy.Membership `json:"membership"`
	Resolved   *policy.Profile   `json:"resolved,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type ExperimentView struct {
	Name     string                `json:"name"`
	Type     policy.ExperimentType `json:"type"`
	Axis     policy.Axis           `json:"axis"`
	Status   string                `json:"status"`
	Rings    []string              `json:"rings"`
	Variants []policy.Variant      `json:"variants"`
	Sample   float64               `json:"sampleRate,omitempty"`
	Metrics  policy.Metrics        `json:"metrics"`
	Stopping policy.Stopping       `json:"stopping"`
}

type IssueView struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

func buildPolicyView(o *policy.Org) PolicyView {
	v := PolicyView{Org: o.Name, Gateway: o.Gateway, Rings: []RingView{}, Profiles: []string{}, Experiments: []ExperimentView{}, Issues: []IssueView{}}
	for n := range o.Profiles {
		v.Profiles = append(v.Profiles, n)
	}
	sort.Strings(v.Profiles)
	for _, r := range o.Rings {
		rv := RingView{Name: r.Name, Order: r.Order, Profile: r.Profile, Release: r.Release, Membership: r.Membership}
		if p, err := o.ResolveProfile(r.Profile); err != nil {
			rv.Error = err.Error()
		} else {
			rv.Resolved = redact(p)
		}
		v.Rings = append(v.Rings, rv)
	}
	for _, e := range o.Experiments {
		st := e.Status
		if st == "" {
			st = "draft"
		}
		v.Experiments = append(v.Experiments, ExperimentView{e.Name, e.Type, e.Axis, st, e.Rings, e.Variants, e.SampleRate, e.Metrics, e.Stopping})
	}
	for _, i := range o.Validate() {
		v.Issues = append(v.Issues, IssueView{string(i.Severity), i.Path, i.Message})
	}
	return v
}

// redact masks values that may be credentials on a copy of p: every MCP
// header and Env value, and harness override string leaves that look secret.
func redact(p *policy.Profile) *policy.Profile {
	c := *p
	c.MCP.Servers = append([]policy.MCPServer(nil), p.MCP.Servers...)
	for i, s := range c.MCP.Servers {
		c.MCP.Servers[i].Headers = maskAll(s.Headers)
	}
	c.Env = maskAll(p.Env)
	if p.Harnesses != nil {
		c.Harnesses = make(map[string]policy.HarnessSpec, len(p.Harnesses))
		for k, h := range p.Harnesses {
			if h.Overrides != nil {
				h.Overrides = redactAny(h.Overrides).(map[string]any)
			}
			c.Harnesses[k] = h
		}
	}
	return &c
}

func maskAll(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k := range m {
		out[k] = "***"
	}
	return out
}

// redactAny deep-copies v, masking string leaves that look like credentials.
func redactAny(v any) any {
	switch x := v.(type) {
	case string:
		if policy.LooksSecret(x) {
			return "***"
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = redactAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactAny(e)
		}
		return out
	}
	return v
}
