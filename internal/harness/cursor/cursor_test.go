package cursor

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func TestRenderGolden(t *testing.T) {
	for _, tc := range []struct {
		os     harness.OS
		path   string
		golden string
	}{
		{harness.Linux, "/etc/cursor/hooks.json", "linux_hooks.json"},
		{harness.Darwin, "/Library/Application Support/Cursor/hooks.json", "darwin_hooks.json"},
		{harness.Windows, `C:\ProgramData\Cursor\hooks.json`, "windows_hooks.json"},
	} {
		t.Run(string(tc.os), func(t *testing.T) {
			p, g := hutiltest.Fixture()
			files, warns, err := Adapter{}.Render(p, harness.Context{Gateway: g, OS: tc.os})
			if err != nil || len(files) != 1 || files[0].Path != tc.path {
				t.Fatalf("files=%v err=%v", files, err)
			}
			hutiltest.Golden(t, tc.golden, files[0].Data)
			all := strings.Join(warns, "\n")
			for _, want := range []string{
				"gateway not rendered", "cannot self-enforce version", "no root-owned location is documented",
				`"models.default" is not supported`, `"permissions.allow" is not supported`, `"mcp.servers" is not supported`,
				`"telemetry.enabled" is not supported`, `"instructions" is not supported`, `"hooks.managedOnly" is not supported`,
				"hooks.managedOnly cannot be enforced", "Cursor's JSON",
			} {
				if !strings.Contains(all, want) {
					t.Errorf("missing warning %q in\n%s", want, all)
				}
			}
			if strings.Contains(all, `"hooks.items"`) {
				t.Errorf("hooks are rendered, so must not be reported unsupported:\n%s", all)
			}
		})
	}
}

func TestHookMapping(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hooks []policy.Hook
		want  map[string][]map[string]any // nil = no file
		warn  string
	}{
		{"every event", []policy.Hook{
			{Event: "PreToolUse", Command: "/a"}, {Event: "PostToolUse", Command: "/b"}, {Event: "SessionStart", Command: "/c"},
			{Event: "Stop", Command: "/d"}, {Event: "UserPromptSubmit", Command: "/e"},
		}, map[string][]map[string]any{
			"preToolUse": {{"command": "/a"}}, "postToolUse": {{"command": "/b"}}, "sessionStart": {{"command": "/c"}},
			"stop": {{"command": "/d"}}, "beforeSubmitPrompt": {{"command": "/e"}},
		}, ""},
		{"tool matcher", []policy.Hook{{Event: "PreToolUse", Matcher: "Bash|Edit|Write|MultiEdit", Command: "/a"}},
			map[string][]map[string]any{"preToolUse": {{"command": "/a", "matcher": "Shell|Write"}}}, ""},
		{"two hooks one event keep order", []policy.Hook{{Event: "Stop", Command: "/1"}, {Event: "Stop", Command: "/2"}},
			map[string][]map[string]any{"stop": {{"command": "/1"}, {"command": "/2"}}}, ""},
		{"unknown tool skips the hook", []policy.Hook{{Event: "PreToolUse", Matcher: "Bash|Glob", Command: "/a"}},
			nil, `matcher "Bash|Glob" names a tool with no Cursor tool type; hook not rendered`},
		{"matcher on a non-tool event is dropped with a warning", []policy.Hook{{Event: "SessionStart", Matcher: "startup", Command: "/a"}},
			map[string][]map[string]any{"sessionStart": {{"command": "/a"}}}, `matcher "startup" is not rendered`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &policy.Profile{Hooks: policy.Hooks{Hooks: tc.hooks}}
			files, warns, err := Adapter{}.Render(p, harness.Context{OS: harness.Linux})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(warns, "\n"), tc.warn) {
				t.Errorf("want warning %q in %v", tc.warn, warns)
			}
			if tc.want == nil {
				if len(files) != 0 {
					t.Fatalf("rendered %s", files[0].Data)
				}
				return
			}
			var doc struct {
				Version int                         `json:"version"`
				Hooks   map[string][]map[string]any `json:"hooks"`
			}
			if err := json.Unmarshal(files[0].Data, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Version != 1 {
				t.Errorf("version = %d", doc.Version)
			}
			got, _ := json.Marshal(doc.Hooks)
			want, _ := json.Marshal(tc.want)
			if string(got) != string(want) {
				t.Errorf("hooks = %s, want %s", got, want)
			}
		})
	}
}

func TestNoHooksRendersNothingAndWarns(t *testing.T) {
	p, _ := hutiltest.Fixture()
	p.Hooks = policy.Hooks{}
	files, warns, err := Adapter{}.Render(p, harness.Context{OS: harness.Linux})
	if err != nil || len(files) != 0 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	if all := strings.Join(warns, "\n"); !strings.Contains(all, "gateway not rendered") {
		t.Errorf("warns = %s", all)
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		hook policy.Hook
		want string
	}{
		{"unknown event", policy.Hook{Event: "PreCompact", Command: "/a"}, `no Cursor equivalent`},
		{"no command", policy.Hook{Event: "Stop"}, "has no command"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &policy.Profile{Hooks: policy.Hooks{Hooks: []policy.Hook{tc.hook}}}
			if _, _, err := (Adapter{}).Render(p, harness.Context{OS: harness.Linux}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMeta(t *testing.T) {
	a := Adapter{}
	m := a.Meta()
	if m.Binary != "cursor-agent" || m.Installer != "" || len(m.UAPrefixes) != 0 {
		t.Errorf("meta = %+v (no verified installer, no documented User-Agent)", m)
	}
	if got := a.InstallCommand("2026.10.19", harness.Linux); got != "" {
		t.Errorf("install = %q, want none: Cursor's installer cannot pin a version", got)
	}
	if len(a.Capabilities()) != 0 {
		t.Errorf("capabilities = %v", a.Capabilities())
	}
	p, g := hutiltest.Fixture()
	for _, os := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
		files, _, err := a.Render(p, harness.Context{Gateway: g, OS: os})
		if err != nil || len(files) != 1 {
			t.Fatalf("%s: files=%v err=%v", os, files, err)
		}
		if !slices.ContainsFunc(m.ManagedDirs[os], func(d string) bool { return strings.HasPrefix(files[0].Path, d) }) {
			t.Errorf("%s: %s is outside ManagedDirs %v", os, files[0].Path, m.ManagedDirs[os])
		}
	}
}
