package harness

import (
	"encoding/json"
	"fmt"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Posture is a harness's effective sandbox and egress posture on one device
// (ADR-0032): what its managed file turns on, plus the per-user settings that
// weaken it. halod reports Findings as drift; halo doctor prints all of it.
type Posture struct {
	Harness  string    `json:"harness"`
	Sandbox  string    `json:"sandbox"` // human summary, e.g. "on (managed)", "not managed"
	Egress   string    `json:"egress"`
	Managed  bool      `json:"managed"` // the managed file turns the sandbox or egress rules on
	Findings []Finding `json:"findings,omitempty"`
}

// Finding is one local setting that weakens the managed posture, with the fix.
type Finding struct {
	Problem string `json:"problem"`
	Fix     string `json:"fix"`
}

// postureSpec says where a harness keeps its sandbox and egress settings.
type postureSpec struct {
	file    string                                            // managed file name in Meta.ManagedDirs[os][0] ("" = none)
	summary func(doc map[string]any) (sandbox, egress string) // from the managed file
	user    []userCheck                                       // per-user files that can weaken it
}

// userCheck is one per-user setting that weakens the sandbox when bad(value).
type userCheck struct {
	file, key string // file relative to home (forward slashes), dotted key
	bad       func(v any) bool
	problem   string
	fix       string
}

func is(want any) func(any) bool { return func(v any) bool { return v == want } }

// Sources: internal/harness/FACTS.md ("Sandbox and egress").
var postureSpecs = map[string]postureSpec{
	"claude-code": {file: "managed-settings.json", summary: func(d map[string]any) (string, string) {
		if get(d, "sandbox.enabled") != true {
			return "", ""
		}
		return "on (managed)", netSummary(get(d, "sandbox.network.allowManagedDomainsOnly") == true, get(d, "sandbox.network.allowedDomains"), get(d, "sandbox.network.deniedDomains"))
	}},
	"codex": {file: "requirements.toml", summary: func(d map[string]any) (string, string) {
		sb := ""
		if m, ok := get(d, "allowed_sandbox_modes").([]any); ok {
			sb = fmt.Sprintf("modes %v (managed)", m)
		}
		eg := ""
		if get(d, "experimental_network.enabled") == true {
			doms, _ := get(d, "experimental_network.domains").(map[string]any)
			var allow, deny []any
			for k, v := range doms {
				if v == "deny" {
					deny = append(deny, k)
				} else {
					allow = append(allow, k)
				}
			}
			eg = netSummary(get(d, "experimental_network.managed_allowed_domains_only") == true, allow, deny)
		}
		return sb, eg
	}, user: []userCheck{{file: ".codex/config.toml", key: "sandbox_mode", bad: is("danger-full-access"),
		problem: `~/.codex/config.toml sets sandbox_mode = "danger-full-access"`,
		fix:     "remove sandbox_mode from ~/.codex/config.toml; requirements.toml refuses it on codex >= 0.77.0, older versions run unsandboxed"}}},
	"gemini-cli": {file: "settings.json", summary: func(d map[string]any) (string, string) {
		if v := get(d, "tools.sandbox"); v != nil && v != false {
			return fmt.Sprintf("tools.sandbox=%v (system default; --sandbox and GEMINI_SANDBOX override it)", v), ""
		}
		return "", ""
	}, user: []userCheck{{file: ".gemini/settings.json", key: "tools.sandbox", bad: is(false),
		problem: "~/.gemini/settings.json sets tools.sandbox = false",
		fix:     "remove tools.sandbox from ~/.gemini/settings.json"}}},
	"copilot-cli": {file: "managed-settings.json", summary: func(d map[string]any) (string, string) {
		if get(d, "sandbox.enabled") != true {
			return "", ""
		}
		eg := ""
		switch {
		case get(d, "sandbox.userPolicy.network.allowOutbound") == false:
			eg = "default deny, nothing allowed (managed)"
		case get(d, "sandbox.userPolicy.network.allowedHosts") != nil || get(d, "sandbox.userPolicy.network.blockedHosts") != nil:
			hosts := get(d, "sandbox.userPolicy.network.allowedHosts")
			eg = netSummary(hosts != nil, hosts, get(d, "sandbox.userPolicy.network.blockedHosts"))
		}
		return "on (managed minimum)", eg
	}},
	"opencode": {file: "opencode.json", summary: func(d map[string]any) (string, string) {
		if w, ok := get(d, "permission.webfetch").(string); ok {
			return "", "webfetch " + w + " (managed; bash is not sandboxed)"
		}
		return "", ""
	}},
	"cursor-agent": {user: []userCheck{{file: ".cursor/sandbox.json", key: "type", bad: is("insecure_none"),
		problem: `~/.cursor/sandbox.json sets type = "insecure_none" (sandbox off)`,
		fix:     `remove "type" from ~/.cursor/sandbox.json, or set Cursor's team sandbox policy in the admin dashboard`}}},
}

func netSummary(exclusive bool, allow, deny any) string {
	n := func(v any) int { l, _ := v.([]any); return len(l) }
	def := "default allow"
	if exclusive {
		def = "default deny"
	}
	return fmt.Sprintf("%s, %d allowed, %d denied (managed)", def, n(allow), n(deny))
}

// ReadPosture reads name's managed file and, when home is set, the per-user
// files under it, through read (an absolute path; halod prefixes its root).
// A per-user weakening is a Finding only while the managed file turns the
// sandbox or egress rules on (Cursor, which has no managed file, always).
func ReadPosture(name string, os OS, home string, read func(string) ([]byte, error)) Posture {
	p := Posture{Harness: name, Sandbox: "not managed", Egress: "not managed"}
	spec, ok := postureSpecs[name]
	if !ok {
		return p
	}
	if m, ok := MetaOf(name); ok && spec.file != "" && len(m.ManagedDirs[os]) > 0 {
		sep := "/"
		if os == Windows {
			sep = `\`
		}
		if doc := decode(read, m.ManagedDirs[os][0]+sep+spec.file); doc != nil {
			sb, eg := spec.summary(doc)
			if sb != "" {
				p.Sandbox, p.Managed = sb, true
			}
			if eg != "" {
				p.Egress, p.Managed = eg, true
			}
		}
	}
	if home == "" || (!p.Managed && spec.file != "") {
		return p
	}
	sep := "/"
	if os == Windows {
		sep = `\`
	}
	for _, u := range spec.user {
		doc := decode(read, strings.TrimRight(home, `/\`)+sep+strings.ReplaceAll(u.file, "/", sep))
		if v := get(doc, u.key); v != nil && u.bad(v) {
			p.Findings = append(p.Findings, Finding{Problem: u.problem, Fix: u.fix})
		}
	}
	return p
}

// decode reads a JSON or TOML file; nil when missing or unparseable.
func decode(read func(string) ([]byte, error), path string) map[string]any {
	b, err := read(path)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if strings.HasSuffix(path, ".toml") {
		err = toml.Unmarshal(b, &doc)
	} else {
		err = json.Unmarshal(b, &doc)
	}
	if err != nil {
		return nil
	}
	return doc
}

// get returns the value at a dotted key, or nil.
func get(doc map[string]any, key string) any {
	var cur any = doc
	for _, k := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}
