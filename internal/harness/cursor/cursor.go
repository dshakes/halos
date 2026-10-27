// Package cursor renders Cursor CLI (cursor-agent) enterprise hooks: the
// system-wide hooks.json is the one root-owned, admin-controlled file the CLI
// reads. Everything else Cursor can govern (models, MCP allowlist, rules,
// telemetry, permissions) is either a server-side team setting or a per-user
// file, so it is warned about, never rendered. Facts and sources:
// internal/harness/FACTS.md.
package cursor

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

const name = "cursor-agent"

func init() { harness.Register(Adapter{}) }

// Adapter implements harness.Adapter for Cursor CLI.
type Adapter struct{}

func (Adapter) Name() string { return name }

// Meta implements harness.Describer. Cursor's installer cannot pin a version
// and the CLI sends no documented User-Agent, so neither is declared.
func (Adapter) Meta() harness.Meta {
	return harness.Meta{Binary: "cursor-agent",
		ManagedDirs: map[harness.OS][]string{harness.Darwin: {"/Library/Application Support/Cursor"}, harness.Linux: {"/etc/cursor"}, harness.Windows: {`C:\ProgramData\Cursor`}}}
}

// Capabilities is empty: the rendered hooks run alongside user and project
// hooks (the CLI loads all of them), so there is no hooks lock, and every other
// capability is server-side or per-user in Cursor.
func (Adapter) Capabilities() []harness.Capability { return nil }

// InstallCommand is empty: https://cursor.com/install installs whatever
// version is current and takes no version argument, so no exact-version
// install can be stated. halod then reports "no verified install artifact".
func (Adapter) InstallCommand(string, harness.OS) string { return "" }

func hooksPath(os harness.OS) string {
	switch os {
	case harness.Darwin:
		return "/Library/Application Support/Cursor/hooks.json"
	case harness.Windows:
		return `C:\ProgramData\Cursor\hooks.json`
	default:
		return "/etc/cursor/hooks.json"
	}
}

// events maps the profile's hook events to Cursor's.
var events = map[string]string{
	"PreToolUse": "preToolUse", "PostToolUse": "postToolUse", "SessionStart": "sessionStart",
	"Stop": "stop", "UserPromptSubmit": "beforeSubmitPrompt",
}

// toolEvents are the events whose matcher is a tool type.
var toolEvents = map[string]bool{"preToolUse": true, "postToolUse": true}

// tools maps Claude Code tool names (what a profile's hook matcher uses) to
// Cursor's tool types.
var tools = map[string]string{
	"Bash": "Shell", "Read": "Read", "Write": "Write", "Edit": "Write", "MultiEdit": "Write", "NotebookEdit": "Write",
	"Grep": "Grep", "Task": "Task",
}

// matcher translates a Claude-style tool matcher ("Bash|Edit") to Cursor's
// ("Shell|Write"). ok is false if any alternative has no Cursor tool type.
func matcher(m string) (string, bool) {
	var out []string
	for _, alt := range strings.Split(m, "|") {
		t, known := tools[strings.TrimSpace(alt)]
		if !known {
			return "", false
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return strings.Join(out, "|"), true
}

func (Adapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	warns := hutil.WarnUnsupported(name, p, "hooks.items")
	if p.Permissions.Sandbox != "" || p.Egress.Restricted() || len(p.Sandbox.ProtectedPaths)+len(p.Sandbox.WritableRoots) > 0 {
		// The native keys exist (sandbox.json type and networkPolicy
		// {default, allow, deny}; cli-config.json permissions.deny
		// WebFetch(domain)/Read(glob)) but only per user, per repo or in the
		// team admin dashboard; halo doctor reports the per-user sandbox type.
		// https://cursor.com/docs/reference/sandbox.md,
		// https://cursor.com/docs/cli/reference/configuration.md
		warns = append(warns, "cursor-agent: sandbox and egress are not rendered: Cursor reads sandbox.json (type, networkPolicy) and cli-config.json permission rules per user (~/.cursor) or per repo only, and team policy from its admin dashboard (no system-wide file); set the team sandbox policy there and check devices with halo doctor")
	}
	warns = append(warns,
		"cursor-agent: cannot self-enforce version; halod enforces, but Cursor's installer cannot pin one, so halod cannot install it",
		"cursor-agent: gateway not rendered; Cursor CLI talks to Cursor's backend and documents no base-URL override (-H/--header is a per-invocation flag); traffic is not routed through Halos",
		"cursor-agent: models, MCP allowlist, rules, telemetry and permissions are Cursor team settings (dashboard) or per-user files (~/.cursor/cli-config.json, ~/.cursor/mcp.json); no root-owned location is documented, so none is rendered")

	if len(p.Hooks.Hooks) == 0 {
		return nil, warns, nil
	}
	byEvent := map[string][]map[string]any{}
	for _, h := range p.Hooks.Hooks {
		ev, ok := events[h.Event]
		if !ok {
			return nil, nil, fmt.Errorf("cursor-agent: hook event %q has no Cursor equivalent (want %s)", h.Event, strings.Join(hutil.SortedKeys(events), ", "))
		}
		if h.Command == "" {
			return nil, nil, fmt.Errorf("cursor-agent: hook for %s has no command", h.Event)
		}
		e := map[string]any{"command": h.Command}
		switch {
		case h.Matcher == "":
		case toolEvents[ev]:
			m, ok := matcher(h.Matcher)
			if !ok {
				warns = append(warns, fmt.Sprintf("cursor-agent: hook %s matcher %q names a tool with no Cursor tool type; hook not rendered", h.Event, h.Matcher))
				continue
			}
			e["matcher"] = m
		default:
			warns = append(warns, fmt.Sprintf("cursor-agent: hook %s matcher %q is not rendered (Cursor matches %s against a fixed value); the hook runs unfiltered", h.Event, h.Matcher, ev))
		}
		byEvent[ev] = append(byEvent[ev], e)
	}
	if len(byEvent) == 0 {
		return nil, warns, nil
	}
	warns = append(warns, "cursor-agent: system hooks run alongside user and project hooks, so hooks.managedOnly cannot be enforced; hook scripts receive Cursor's JSON (hook_event_name, tool_name, tool_input), not Claude Code's")
	doc := hutil.DeepMerge(map[string]any{"version": 1, "hooks": byEvent}, p.Harnesses[name].Overrides)
	data, err := hutil.JSON(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("cursor-agent: encode hooks.json: %w", err)
	}
	return []harness.File{{Path: hooksPath(c.OS), Mode: 0o644, Data: data}}, warns, nil
}
