package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// MCP drift (ADR-0029): halod reads the console user's own MCP configs and
// reports every server the release's registry does not give this device
// (unapproved), or gives with another URL or command line (version-drift).
// It only reports: user files are the user's, and the managed config already
// blocks what the harness can block.

// userMCPConfig is one per-user MCP config file: harness, path under the home
// directory, and the JSON/TOML keys holding the server map. Sources in
// internal/harness/FACTS.md (ADR-0029 section).
type userMCPConfig struct {
	harness, rel string
	toml         bool
	keys         []string // the server map's key; "projects.*" entries hold more maps (Claude Code)
}

var userMCPConfigs = []userMCPConfig{
	{harness: "claude-code", rel: ".claude.json", keys: []string{"mcpServers"}},
	{harness: "codex", rel: ".codex/config.toml", toml: true, keys: []string{"mcp_servers"}},
	{harness: "gemini-cli", rel: ".gemini/settings.json", keys: []string{"mcpServers"}},
	{harness: "copilot-cli", rel: ".copilot/mcp-config.json", keys: []string{"mcpServers"}},
	{harness: "cursor", rel: ".cursor/mcp.json", keys: []string{"mcpServers"}},
	{harness: "opencode", rel: ".config/opencode/opencode.json", keys: []string{"mcp"}},
}

// maxUserConfig bounds what halod reads from a user-owned file.
const maxUserConfig = 4 << 20

// foundServer is one server definition in a user config.
type foundServer struct {
	name, url string
	command   []string
}

// userHome is the console user's home directory ("" when unknown).
func (a *Agent) userHome() string {
	if a.Home != nil {
		return a.Home(a.User)
	}
	if a.User == "" {
		return ""
	}
	return homeDir(a.User)
}

// mcpDrift reports the user's MCP servers rel's registry does not approve
// for this device (in unit, or none). nil when rel carries no registry.
func (a *Agent) mcpDrift(rel *release.Release, unit *release.UnitEntry) []policy.MCPFinding {
	m := rel.Manifest
	home := a.userHome()
	if m.MCPMode == "" || home == "" {
		return nil
	}
	approved := approvedPins(m, unit)
	var out []policy.MCPFinding
	for _, c := range userMCPConfigs {
		if _, ok := m.Harnesses[c.harness]; !ok {
			continue
		}
		p := filepath.Join(home, filepath.FromSlash(c.rel))
		servers, err := a.readUserMCP(p, c)
		if err != nil {
			a.log().Warn("mcp drift: cannot read user config", "harness", c.harness, "file", p, "err", err)
			continue
		}
		for _, s := range servers {
			if f, ok := checkServer(s, approved, m.Ring); !ok {
				f.Harness, f.File = c.harness, p
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Harness+out[i].File+out[i].Server < out[j].Harness+out[j].File+out[j].Server
	})
	return out
}

// approvedPins are the manifest's pinned servers this device gets: every
// ring-wide pin, and unit-limited ones for unit or a unit above it.
func approvedPins(m release.Manifest, unit *release.UnitEntry) []policy.MCPPin {
	var chain []string
	for u := unit; u != nil && !slices.Contains(chain, u.Name); {
		chain = append(chain, u.Name)
		i := slices.IndexFunc(m.Units, func(e release.UnitEntry) bool { return e.Name == u.Parent })
		if i < 0 {
			break
		}
		u = &m.Units[i]
	}
	var out []policy.MCPPin
	for _, p := range m.MCPServers {
		if len(p.Units) == 0 || slices.ContainsFunc(p.Units, func(n string) bool { return slices.Contains(chain, n) }) {
			out = append(out, p)
		}
	}
	return out
}

// checkServer judges one user server: ok when an approved pin has its name
// and definition, or (renamed) its definition.
func checkServer(s foundServer, approved []policy.MCPPin, ring string) (policy.MCPFinding, bool) {
	same := func(p policy.MCPPin) bool {
		if p.URL != "" {
			a, ok1 := policy.CanonicalResource(p.URL)
			b, ok2 := policy.CanonicalResource(s.url)
			return ok1 && ok2 && a == b
		}
		return len(p.Command) > 0 && slices.Equal(p.Command, s.command)
	}
	i := slices.IndexFunc(approved, func(p policy.MCPPin) bool { return p.ID == s.name })
	switch {
	case i >= 0 && same(approved[i]):
		return policy.MCPFinding{}, true
	case i >= 0:
		want := approved[i].URL
		if want == "" {
			want = strings.Join(approved[i].Command, " ")
		}
		return policy.MCPFinding{Server: s.name, Kind: "version-drift",
			Detail: fmt.Sprintf("defined as %s; the registry pins %s", s.def(), want),
			Fix:    fmt.Sprintf("change %q to %s, or remove it (the managed config already provides it)", s.name, want)}, false
	case slices.ContainsFunc(approved, same):
		return policy.MCPFinding{}, true
	}
	return policy.MCPFinding{Server: s.name, Kind: "unapproved",
		Detail: fmt.Sprintf("defined as %s; not in the halos.yaml mcp registry for ring %s or this device's unit", s.def(), ring),
		Fix:    fmt.Sprintf("remove %q, or propose it for halos.yaml mcp (halo mcp registry import) with this ring or unit enabled", s.name)}, false
}

func (s foundServer) def() string {
	if s.url != "" {
		return s.url
	}
	if len(s.command) > 0 {
		return strings.Join(s.command, " ")
	}
	return "no url or command"
}

// readUserMCP parses one user config (readUserFile: a regular file, never
// through a symlink or a FIFO); a missing file is no servers.
func (a *Agent) readUserMCP(p string, c userMCPConfig) ([]foundServer, error) {
	b, err := a.readUserFile(p, maxUserConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if c.toml {
		err = toml.Unmarshal(b, &doc)
	} else {
		err = json.Unmarshal(b, &doc)
	}
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err) // the decoders report positions, not content
	}
	maps := []any{doc[c.keys[0]]}
	if c.harness == "claude-code" { // local-scope servers live under projects.<path>.mcpServers
		if projects, ok := doc["projects"].(map[string]any); ok {
			for _, pr := range projects {
				if pm, ok := pr.(map[string]any); ok {
					maps = append(maps, pm["mcpServers"])
				}
			}
		}
	}
	var out []foundServer
	for _, mv := range maps {
		servers, _ := mv.(map[string]any)
		for name, v := range servers {
			e, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if en, ok := e["enabled"].(bool); ok && !en {
				continue // disabled (OpenCode, Codex): not running
			}
			out = append(out, foundServer{name: name, url: firstString(e, "url", "httpUrl", "serverUrl"), command: commandLine(e)})
		}
	}
	return out, nil
}

func firstString(e map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := e[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// commandLine is command (a string, or OpenCode's array) followed by args.
func commandLine(e map[string]any) []string {
	var out []string
	switch c := e["command"].(type) {
	case string:
		out = []string{c}
	case []any:
		out = strs(c)
	}
	if a, ok := e["args"].([]any); ok && len(out) > 0 {
		out = append(out, strs(a)...)
	}
	return out
}

func strs(v []any) []string {
	var out []string
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
