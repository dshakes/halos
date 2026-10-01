// Package mcpserver exposes a Halos policy repo to agents over MCP.
//
// Design rule: the server can inspect everything and propose changes, but it
// can never take an irreversible step. It does not publish releases, retag
// registry rings, merge, or push to a default branch; those stay with a human.
// Write tools exist only when Options.AllowWrites is set, default to
// dry_run, and require a reason that lands in the commit message.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/upgrade"
)

// Options configures New.
type Options struct {
	PolicyDir   string
	AllowWrites bool
	// ClickHouse, when non-nil, enables analyze_experiment and lets
	// propose_promotion check the verdict before opening a PR.
	ClickHouse *promote.ClickHouse
	// SchemaDir holds *.schema.json; auto-detected near PolicyDir when empty.
	SchemaDir string
	Version   string
	// Upgrade, when set, supplies upgrade_candidates' Registry, Models and
	// Verifier (tests); nil = npm and the vendors' release metadata.
	Upgrade *upgrade.Watcher
}

type srv struct {
	Options
	dir string // absolute policy dir
}

// New builds the MCP server. It registers tools, resources and prompts.
func New(o Options) (*mcp.Server, error) {
	abs, err := filepath.Abs(o.PolicyDir)
	if err != nil {
		return nil, fmt.Errorf("mcpserver: resolve policy dir %q: %w", o.PolicyDir, err)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("mcpserver: policy dir %q is not a directory", o.PolicyDir)
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	s := &srv{Options: o, dir: abs}
	m := mcp.NewServer(&mcp.Implementation{Name: "halos", Version: o.Version}, &mcp.ServerOptions{
		Instructions: "Halos policy control plane. Read tools are always safe. Write tools (if present) default to dry_run " +
			"and only edit a local branch or open a PR; a human publishes releases, retags rings and merges.",
	})
	s.addReadTools(m)
	if o.AllowWrites {
		s.addWriteTools(m)
	}
	s.addResources(m)
	addPrompts(m)
	return m, nil
}

func (s *srv) load() (*policy.Org, error) {
	org, err := policy.Load(s.dir)
	if err != nil {
		return nil, fmt.Errorf("load policy %s: %w", s.dir, err)
	}
	return org, nil
}

// loadValid refuses to proceed when the policy has validation errors.
func (s *srv) loadValid() (*policy.Org, error) {
	org, err := s.load()
	if err != nil {
		return nil, err
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		var b strings.Builder
		for _, i := range issues {
			if i.Severity == policy.SeverityError {
				b.WriteString("\n  " + i.String())
			}
		}
		return nil, fmt.Errorf("policy has validation errors (run the validate tool):%s", b.String())
	}
	return org, nil
}

func findRing(org *policy.Org, name string) (*policy.Ring, error) {
	var names []string
	for _, r := range org.Rings {
		if r.Name == name {
			return r, nil
		}
		names = append(names, r.Name)
	}
	return nil, fmt.Errorf("unknown ring %q (have: %s)", name, strings.Join(names, ", "))
}

func findExp(org *policy.Org, name string) (*policy.Experiment, error) {
	for _, e := range org.Experiments {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("unknown experiment %q", name)
}

// toMap converts v to a generic JSON object so tool output schemas stay simple.
func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// within reports whether p (absolute) is inside root.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

const (
	policyPrefix = "halos://policy/"
	schemaPrefix = "halos://schema/"
)

func (s *srv) schemaDir() string {
	for _, c := range []string{s.SchemaDir, filepath.Join(s.dir, "schemas"), filepath.Join(s.dir, "..", "..", "schemas")} {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

func (s *srv) addResources(m *mcp.Server) {
	_ = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != s.dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); !d.Type().IsRegular() || ext != ".yaml" && ext != ".yml" {
			return nil // symlinks could expose files outside the policy dir
		}
		rel, _ := filepath.Rel(s.dir, p)
		rel = filepath.ToSlash(rel)
		m.AddResource(&mcp.Resource{URI: policyPrefix + rel, Name: rel, MIMEType: "application/yaml",
			Description: "Policy file " + rel}, s.readPolicy)
		return nil
	})
	if sd := s.schemaDir(); sd != "" {
		files, _ := filepath.Glob(filepath.Join(sd, "*.schema.json"))
		sort.Strings(files)
		for _, f := range files {
			kind := strings.TrimSuffix(filepath.Base(f), ".schema.json")
			m.AddResource(&mcp.Resource{URI: schemaPrefix + kind, Name: kind + " schema", MIMEType: "application/schema+json",
				Description: "JSON Schema for " + kind + " documents"}, readFile(f))
		}
	}
}

func (s *srv) readPolicy(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	rel, ok := strings.CutPrefix(uri, policyPrefix)
	if !ok {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	p := filepath.Join(s.dir, filepath.FromSlash(rel))
	if ext := filepath.Ext(p); !within(s.dir, p) || ext != ".yaml" && ext != ".yml" {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	// Only regular files whose resolved path stays inside the policy dir:
	// a symlink (or symlinked parent dir) must not reach e.g. /etc/hosts.
	root, err1 := filepath.EvalSymlinks(s.dir)
	real, err2 := filepath.EvalSymlinks(p)
	st, err3 := os.Lstat(p)
	if err1 != nil || err2 != nil || err3 != nil || !st.Mode().IsRegular() || !within(root, real) {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	return readContents(uri, "application/yaml", real)
}

func readFile(p string) mcp.ResourceHandler {
	return func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return readContents(req.Params.URI, "application/schema+json", p)
	}
}

func readContents(uri, mime, p string) (*mcp.ReadResourceResult, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		return nil, fmt.Errorf("read %s: %w", uri, err)
	}
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mime, Text: string(b)}}}, nil
}
