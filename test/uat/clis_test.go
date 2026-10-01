//go:build uat

package uat

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCLIs drives the real Claude Code, Codex, Gemini and Copilot CLIs
// installed by the Halos Dev Container Feature (see clis_env_test.go).
func TestCLIs(t *testing.T) {
	e := cliSetup(t)
	versions := map[string]string{}
	for h, cmd := range map[string]string{"claude-code": "claude --version", "codex": "codex --version", "gemini-cli": "gemini --version", "copilot": "copilot --version | head -1"} {
		versions[h], _ = e.sh(cmd + " 2>&1")
	}
	defer writeReport(t, e, versions)

	t.Run("install", func(t *testing.T) { testInstall(t, e, versions) })
	t.Run("claude-code", func(t *testing.T) { testClaude(t, e) })
	t.Run("codex", func(t *testing.T) { testCodex(t, e) })
	t.Run("gemini-cli", func(t *testing.T) { testGemini(t, e) })
	t.Run("copilot", func(t *testing.T) { testCopilot(t, e) })
	t.Run("eval", func(t *testing.T) { testEval(t, e) })
}

// testInstall: the Feature installed every pinned CLI and halod applied
// exactly what `halo render` produces for the release.
func testInstall(t *testing.T, e *cliEnv, versions map[string]string) {
	for h, want := range map[string]string{"claude-code": e.pins["claude-code"] + " (Claude Code)", "codex": "codex-cli " + e.pins["codex"],
		"gemini-cli": e.pins["gemini-cli"], "copilot": "GitHub Copilot CLI " + e.pins["copilot"]} {
		got := strings.TrimSpace(versions[h])
		got = got[strings.LastIndex(got, "\n")+1:] // gemini prints an OTEL exporter notice first
		check(t, h, "Feature installs pinned version", strings.HasPrefix(got, want), fmt.Sprintf("`--version` = %q, pin %s", got, e.pins[h]), "")
	}
	byHarness := map[string][]string{}
	for p := range e.rendered {
		h := map[string]string{"/etc/profile.d/halos-gemini.sh": "gemini-cli", "/etc/profile.d/halos-codex.sh": "codex",
			"/etc/profile.d/halos-copilot-cli.sh": "copilot"}[p]
		if h == "" {
			h = map[string]string{"/etc/claude-code": "claude-code", "/etc/codex": "codex", "/etc/gemini-cli": "gemini-cli",
				"/etc/github-copilot": "copilot"}[p[:strings.LastIndex(p, "/")]]
		}
		byHarness[h] = append(byHarness[h], p)
	}
	for _, h := range []string{"claude-code", "codex", "gemini-cli", "copilot"} {
		var bad []string
		for _, p := range byHarness[h] {
			if got, _ := e.sh("cat " + p); got != e.rendered[p] {
				bad = append(bad, p)
			}
		}
		check(t, h, "halod applied == halo render", len(byHarness[h]) > 0 && len(bad) == 0,
			fmt.Sprintf("files %v, differing %v", byHarness[h], bad), "")
	}
}

func lastModelCall(rs []mockReq, path string) (mockReq, bool) {
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].Path == path || (strings.HasSuffix(path, "/") && strings.HasPrefix(rs[i].Path, path)) {
			return rs[i], true
		}
	}
	return mockReq{}, false
}

// checkTraffic asserts what halo-proxy forwarded to the mock upstream.
func checkTraffic(t *testing.T, e *cliEnv, h, path, alias string, upstream []string, out string, rc int, known string) {
	r, ok := lastModelCall(e.mockRequests(), path)
	check(t, h, "CLI prints the mock's answer via halo-proxy", rc == 0 && strings.Contains(out, "UAT-MOCK-ANSWER"),
		fmt.Sprintf("rc=%d out=%q", rc, tail(out, 3)), known)
	if !ok {
		check(t, h, "request reached upstream through halo-proxy", false, "no "+path+" request at the mock; proxy log: "+tail(proxyLog(e), 3), known)
		return
	}
	ring, variant := r.header("x-halo-ring"), r.header("x-halo-variant")
	check(t, h, "x-halo-ring / x-halo-variant stamped", ring == cliRing && (variant == "control" || variant == "uat-next"),
		fmt.Sprintf("x-halo-ring=%q x-halo-variant=%q x-halo-experiment=%q", ring, variant, r.header("x-halo-experiment")), "")
	auth := r.header("authorization") + r.header("x-api-key") + r.header("x-goog-api-key")
	check(t, h, "client auth (JWT) not forwarded", auth == "", fmt.Sprintf("upstream saw Authorization/x-api-key/x-goog-api-key = %q", auth), "")
	m := r.model()
	inSet := false
	for _, u := range upstream {
		inSet = inSet || m == u
	}
	check(t, h, "model alias rewritten", inSet && m != alias, fmt.Sprintf("alias %q -> upstream saw %q (want one of %v)", alias, m, upstream), "")
}

func proxyLog(e *cliEnv) string { out, _ := e.sh("tail -5 /var/log/halo-proxy.log"); return out }

// checkOTLP asserts the CLI's own telemetry carries halo.ring/halo.release.
func checkOTLP(t *testing.T, e *cliEnv, h, service, known string) {
	var hit *otlpRec
	recs := e.mockOTLP()
	var services []string
	for i, r := range recs {
		services = append(services, r.Attrs["service.name"])
		if strings.Contains(r.Attrs["service.name"], service) {
			hit = &recs[i]
		}
	}
	if hit == nil {
		check(t, h, "OTEL carries halo.ring/halo.release/halo.harness", false, fmt.Sprintf("no OTLP export from %s (services seen: %v)", service, services), known)
		return
	}
	ok := hit.Attrs["halo.ring"] == cliRing && hit.Attrs["halo.release"] == cliRelease && hit.Attrs["halo.harness"] != ""
	b, _ := json.Marshal(hit.Attrs)
	check(t, h, "OTEL carries halo.ring/halo.release/halo.harness", ok, hit.Signal+" resource "+string(b), known)
}

// editJSON rewrites a managed JSON file in place (python3; no jq in the image).
func editJSON(e *cliEnv, path, pyExpr string) {
	e.sh(`python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); ` + pyExpr + `; json.dump(d,open(p,"w"),indent=2)' ` + path)
}

func testClaude(t *testing.T, e *cliEnv) {
	const h, ms = "claude-code", "/etc/claude-code/managed-settings.json"
	pin := e.pins[h]
	e.sh("mkdir -p /proj && printf 'SECRET=hunter2-uat\\n' >/proj/.env")

	// Version window (managed requiredMinimum/MaximumVersion): `claude -p` refuses outside it.
	e.sh("cp " + ms + " /root/ms.bak")
	editJSON(e, ms, `d["requiredMinimumVersion"]="99.0.0"; d["requiredMaximumVersion"]="99.0.0"`)
	out, rc := e.sh("cd /proj && timeout 60 claude -p hi </dev/null 2>&1")
	check(t, h, "requiredMinimumVersion above installed: refuses to start", rc != 0 && strings.Contains(out, "older than the minimum version required"),
		fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")
	editJSON(e, ms, `d["requiredMinimumVersion"]="1.0.0"; d["requiredMaximumVersion"]="2.0.0"`)
	out, rc = e.sh("cd /proj && timeout 60 claude -p hi </dev/null 2>&1")
	check(t, h, "requiredMaximumVersion below installed: refuses to start", rc != 0 && strings.Contains(out, "newer than the maximum version allowed"),
		fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")
	vout, _ := e.sh("claude --version 2>&1")
	check(t, h, "`claude --version` not gated (informational)", strings.Contains(vout, pin), "out-of-window `claude --version` = "+strings.TrimSpace(vout), "")
	e.sh("cp /root/ms.bak " + ms)

	// What the CLI itself reports: `claude doctor` runs headless; it lists remote
	// (not file) managed settings, but shows the managed env taking effect.
	out, rc = e.sh("timeout 30 claude doctor </dev/null 2>&1")
	check(t, h, "`claude doctor`: managed env applied (DISABLE_AUTOUPDATER)", rc == 0 && strings.Contains(out, "Running:") && !strings.Contains(out, "Auto-updates: enabled"),
		firstLines(out, "Running:", "Auto-update", "Managed settings", "Organization policy"), "")

	// Traffic: claude -p through halo-proxy (apiKeyHelper -> mock-issued JWT).
	e.resetMock()
	out, rc = e.sh("cd /proj && timeout 90 claude -p 'say hi' </dev/null 2>&1")
	checkTraffic(t, e, h, "/v1/messages", "sonnet", []string{"claude-uat-sonnet-upstream", "claude-uat-sonnet-next"}, out, rc, "")
	checkOTLP(t, e, h, "claude-code", "")

	// Deny rule: Read(./.env) from the profile; the mock asks the CLI to read it.
	e.resetMock()
	_, rc = e.sh("cd /proj && timeout 90 claude -p 'UAT-READ path=/proj/.env' </dev/null 2>&1")
	tr := ""
	for _, r := range e.mockRequests() {
		if strings.Contains(r.Body, `"tool_result"`) {
			tr = r.Body
		}
	}
	m := regexp.MustCompile(`"tool_result","content":"([^"]*)"`).FindStringSubmatch(tr)
	got := ""
	if m != nil {
		got = m[1]
	}
	check(t, h, "permissions.deny Read(./.env) blocks the tool call", tr != "" && !strings.Contains(tr, "hunter2-uat") && strings.Contains(got, "denied"),
		fmt.Sprintf("rc=%d tool_result=%q", rc, got), "")

	// Model lock: a model outside availableModels never reaches the upstream.
	e.resetMock()
	// Claude drops the disallowed --model silently and falls back to its tier
	// default's built-in ID (claude-opus-5-5[1m]); the adapter's modelOverrides
	// maps that back to the `opus` alias, so the fallback is a policy model.
	out, _ = e.sh("cd /proj && mkdir -p /root/.claude/debug && find /root/.claude/debug -type f -delete; timeout 20 claude --debug -p --model my-rogue-model hi </dev/null >/tmp/rogue.out 2>&1; grep -ho 'dispatching to firstParty model=[^ ]*' /root/.claude/debug/*.txt | sort | uniq -c")
	var models []string
	for _, r := range e.mockRequests() {
		if r.Path == "/v1/messages" {
			models = append(models, r.model())
		}
	}
	rogue := strings.Contains(out, "rogue") || strings.Contains(strings.Join(models, ","), "rogue")
	check(t, h, "availableModels/enforce: `--model my-rogue-model` never sent", !rogue && strings.Contains(out, "dispatching"),
		fmt.Sprintf("CLI dispatched instead: %q; upstream saw %v", strings.TrimSpace(out), models), "")
	msg, _ := e.sh("grep -v Sandbox /tmp/rogue.out")
	check(t, h, "disallowed --model: fallback goes to a gateway alias (modelOverrides), not refused upstream",
		strings.Contains(msg, "UAT-MOCK-ANSWER") && !strings.Contains(msg, "not permitted") && strings.Contains(strings.Join(models, ","), "claude-uat-opus-upstream"),
		fmt.Sprintf("%q; upstream saw %v", strings.TrimSpace(msg), models), "")

	// MCP allowlist: a user-added server outside allowedMcpServers is not used.
	e.resetMock()
	e.sh("claude mcp add --transport http --scope user rogue http://mock:8080/mcp/rogue >/dev/null 2>&1")
	out, _ = e.sh("cd /proj && timeout 90 claude mcp list 2>&1")
	hits := map[string]int{}
	for _, r := range e.mockRequests() {
		if strings.HasPrefix(r.Path, "/mcp/") {
			hits[r.Path]++
		}
	}
	check(t, h, "allowManagedMcpServersOnly: user server `rogue` not connected", hits["/mcp/rogue"] == 0 && hits["/mcp/docs"] > 0,
		fmt.Sprintf("mock MCP hits %v; `claude mcp list`: %q", hits, tail(out, 4)), "")
	e.sh("claude mcp remove --scope user rogue >/dev/null 2>&1")

	// bypassPermissions is disabled by policy.
	out, rc = e.sh("cd /proj && timeout 60 claude -p --permission-mode bypassPermissions hi </dev/null 2>&1")
	r, _ := lastModelCall(e.mockRequests(), "/v1/messages")
	check(t, h, "disableBypassPermissionsMode: bypassPermissions refused", rc != 0 || !strings.Contains(out, "UAT-MOCK-ANSWER") || r.Body == "",
		fmt.Sprintf("rc=%d out=%q", rc, tail(out, 2)), "")
}

func testCodex(t *testing.T, e *cliEnv) {
	const h = "codex"
	tok := `HALO_GATEWAY_TOKEN=$(halo-uat-token) `
	e.sh("mkdir -p /proj")

	e.resetMock()
	// Through `bash -c` (not `timeout codex`): the release's profile.d wrapper
	// function is what labels the CLI's telemetry, as in a developer's shell.
	out, rc := e.sh("cd /proj && " + tok + `timeout 90 bash -c "codex exec --skip-git-repo-check 'say hi'" </dev/null 2>&1`)
	check(t, h, "managed_config.toml loads (model_provider = halos)", strings.Contains(out, "provider: halos") && strings.Contains(out, "model: codex-default"),
		fmt.Sprintf("rc=%d %q", rc, firstLines(out, "provider:", "model:", "Error")), "")
	checkTraffic(t, e, h, "/v1/responses", "codex-default", []string{"gpt-uat-upstream", "gpt-uat-next"}, out, rc, "")
	checkOTLP(t, e, h, "codex", "")

	// Enforced from codex 0.77.0; `codex exec` runs under it from 0.99.0 (the
	// acme pin), falling back to the allowed values. Older pins get adapter warnings.
	out, rc = e.sh("cd /proj && " + tok + "timeout 90 codex exec --skip-git-repo-check -s danger-full-access 'say hi' </dev/null 2>&1")
	check(t, h, "requirements.toml: `-s danger-full-access` refused", strings.Contains(out, "UAT-MOCK-ANSWER") && !strings.Contains(out, "sandbox: danger-full-access") &&
		(strings.Contains(out, "sandbox: read-only") || strings.Contains(out, "sandbox: workspace-write")),
		fmt.Sprintf("rc=%d %q", rc, firstLines(out, "sandbox:", "Error")), "")
	out, rc = e.sh("cd /proj && " + tok + "timeout 90 codex exec --skip-git-repo-check -c approval_policy=never 'say hi' </dev/null 2>&1")
	check(t, h, "requirements.toml: approval_policy=never refused", strings.Contains(out, "UAT-MOCK-ANSWER") && strings.Contains(out, "approval: on-request"),
		fmt.Sprintf("rc=%d %q", rc, firstLines(out, "approval:", "falling back", "Error")), "")
	out, rc = e.sh("cd /proj && " + tok + `timeout 60 bash -c "codex exec --skip-git-repo-check -m my-rogue-model hi" </dev/null 2>&1`)
	check(t, h, "model not permitted: gateway message shown, not retried", rc != 0 && strings.Contains(out, "model_not_allowed") && strings.Contains(out, "not permitted by the Halos gateway policy") && !strings.Contains(out, "Reconnecting"),
		fmt.Sprintf("rc=%d %q", rc, firstLines(out, "ERROR: {")), "")

	e.resetMock()
	e.sh(`mkdir -p /root/.codex && printf '[mcp_servers.rogue]\nurl = "http://mock:8080/mcp/rogue"\n' >/root/.codex/config.toml`)
	e.sh("cd /proj && " + tok + "timeout 90 codex exec --skip-git-repo-check 'say hi' </dev/null >/dev/null 2>&1")
	hits := mcpHits(e)
	check(t, h, "requirements.toml mcp_servers allowlist: user server `rogue` not connected", hits["/mcp/rogue"] == 0 && hits["/mcp/docs"] > 0,
		fmt.Sprintf("mock MCP hits %v", hits), "")
	e.sh("rm -f /root/.codex/config.toml")
}

func testGemini(t *testing.T, e *cliEnv) {
	const h = "gemini-cli"
	e.sh("mkdir -p /proj")

	env, _ := e.sh("echo $GOOGLE_GEMINI_BASE_URL")
	check(t, h, "gateway base URL exported (/etc/profile.d, login shell)", strings.TrimSpace(env) == "http://localhost:8088", "GOOGLE_GEMINI_BASE_URL="+strings.TrimSpace(env), "")

	out, rc := e.sh("cd /proj && GOOGLE_GENAI_USE_GCA=true timeout 60 gemini -p hi </dev/null 2>&1")
	check(t, h, "security.auth.enforcedType=gemini-api-key: Google login refused", rc != 0 && strings.Contains(out, "enforced authentication type is 'gemini-api-key'"),
		fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")

	e.resetMock()
	e.sh(`mkdir -p /root/.gemini && printf '{"mcpServers":{"rogue":{"httpUrl":"http://mock:8080/mcp/rogue"}}}' >/root/.gemini/settings.json`)
	key, _ := e.sh(`printf %s "$GEMINI_API_KEY" | cut -d. -f1 | base64 -d 2>/dev/null`)
	check(t, h, "GEMINI_API_KEY from gateway.auth.helperCommand (/etc/profile.d)", strings.Contains(key, `"RS256"`), "JWT header "+strings.TrimSpace(key), "")
	// No explicit key: the login shell's rendered GEMINI_API_KEY is the credential.
	out, rc = e.sh(`cd /proj && timeout 120 bash -c "gemini -p 'say hi'" </dev/null 2>&1`)
	hits := mcpHits(e)
	check(t, h, "mcp.allowed: user server `rogue` not connected", hits["/mcp/rogue"] == 0 && hits["/mcp/docs"] > 0, fmt.Sprintf("mock MCP hits %v", hits), "")
	e.sh("rm -f /root/.gemini/settings.json")
	pl := proxyLog(e)
	check(t, h, "model calls go to the gateway base URL", strings.Contains(pl, "generateContent") || strings.Contains(pl, "/v1beta/"),
		"halo-proxy log: "+tail(pl, 2), "")
	checkTraffic(t, e, h, "/v1beta/models/", "gemini-default", []string{"gemini-uat-upstream", "gemini-uat-next"}, out, rc, "")
	checkOTLP(t, e, h, "gemini", "")
	if r, ok := lastModelCall(e.mockRequests(), "/v1beta/models/"); ok {
		var names []string
		for n := range r.Headers {
			names = append(names, strings.ToLower(n))
		}
		sort.Strings(names)
		session := ""
		for _, n := range names {
			if strings.Contains(n, "session") {
				session = n
			}
		}
		check(t, h, "session header reported (observation for sticky routing)", true, fmt.Sprintf("session header %q; headers reaching upstream: %v", session, names), "")
	}

	// ?key= is the other Gemini credential carrier: never forwarded upstream.
	// halo-proxy takes the credential from x-goog-api-key only (?key= alone is 401).
	e.resetMock()
	q := `-XPOST -H 'content-type: application/json' -d '{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}' "http://localhost:8088/v1beta/models/gemini-default:generateContent?key=`
	alone, _ := e.sh(`curl -s -o /dev/null -w '%{http_code}' ` + q + `$(halo-uat-token)"`)
	out, _ = e.sh(`curl -s -o /dev/null -w '%{http_code}' -H "x-goog-api-key: $(halo-uat-token)" ` + q + `uat-leak-probe"`)
	r, ok := lastModelCall(e.mockRequests(), "/v1beta/models/")
	check(t, h, "x-goog-api-key and ?key= stripped upstream", ok && strings.TrimSpace(out) == "200" && !strings.Contains(r.Query, "key=") && r.header("x-goog-api-key") == "",
		fmt.Sprintf("header+?key= -> %s, upstream query %q, x-goog-api-key %q; ?key= alone -> %s (not a credential)", strings.TrimSpace(out), r.Query, r.header("x-goog-api-key"), strings.TrimSpace(alone)), "")

	// An alias not in policy: Gemini-shaped 400, nothing forwarded, the CLI reports it.
	e.resetMock()
	out, rc = e.sh("cd /proj && timeout 120 gemini -m my-rogue-model -p hi </dev/null 2>&1")
	body, _ := e.sh(`curl -s -XPOST -H "x-goog-api-key: $(halo-uat-token)" -H 'content-type: application/json' http://localhost:8088/v1beta/models/my-rogue-model:generateContent -d '{"contents":[]}'`)
	fwd := 0
	for _, r := range e.mockRequests() {
		if strings.Contains(r.Path, "rogue") {
			fwd++
		}
	}
	check(t, h, "unlisted model alias: Gemini-shaped refusal, not forwarded", fwd == 0 && rc != 0 && (strings.Contains(body, `"PERMISSION_DENIED"`) || strings.Contains(body, `"INVALID_ARGUMENT"`)),
		fmt.Sprintf("gemini rc=%d %q; proxy body %s; forwarded %d", rc, tail(out, 1), strings.TrimSpace(body), fwd), "")
	check(t, h, "model not permitted: gateway message shown", strings.Contains(out, "not permitted by the Halos gateway policy"),
		fmt.Sprintf("%q (gemini also ends with \"[object Object]\")", firstLines(out, "Error when talking to Gemini API")), "")

	out, rc = e.sh("cd /proj && timeout 60 gemini -p hi --yolo </dev/null 2>&1")
	check(t, h, "security.disableYoloMode: --yolo refused", !strings.Contains(out, "UAT-MOCK-ANSWER") && strings.Contains(out, "YOLO mode is disabled"),
		fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")
}

func testCopilot(t *testing.T, e *cliEnv) {
	const h = "copilot"
	byok := `COPILOT_PROVIDER_BASE_URL=http://mock:8080/v1 COPILOT_PROVIDER_TYPE=openai COPILOT_PROVIDER_API_KEY=x COPILOT_MODEL=gpt-uat `
	e.sh("mkdir -p /proj")
	e.resetMock()
	out, rc := e.sh("cd /proj && " + byok + `timeout 120 bash -c "copilot -p 'say hi'" </dev/null 2>&1`)
	check(t, h, "runs without GitHub login (BYOK env, direct to mock)", rc == 0 && strings.Contains(out, "UAT-MOCK-ANSWER"),
		fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")
	unverified(t, h, "traffic through halo-proxy", "by design: Copilot BYOK is env-only and the adapter renders no gateway (warned); halo-proxy also has no chat-completions route")
	checkOTLP(t, e, h, "copilot", "")

	e.resetMock()
	e.sh(`mkdir -p /root/.copilot && printf '{"mcpServers":{"docs":{"type":"http","url":"https://mock:8443/mcp/docs","tools":["*"]},"rogue":{"type":"http","url":"http://mock:8080/mcp/rogue","tools":["*"]}}}' >/root/.copilot/mcp-config.json`)
	e.sh("cd /proj && " + byok + "timeout 120 copilot -p 'say hi' </dev/null 2>&1")
	hits := mcpHits(e)
	if hits["/mcp/docs"] == 0 && hits["/mcp/rogue"] == 0 {
		unverified(t, h, "allowedMcpServers: user server `rogue` not connected", fmt.Sprintf("copilot -p connected to neither the allowed nor the rogue user MCP server (hits %v), so the allowlist could not be observed", hits))
	} else {
		check(t, h, "allowedMcpServers: user server `rogue` not connected", hits["/mcp/rogue"] == 0 && hits["/mcp/docs"] > 0, fmt.Sprintf("mock MCP hits %v", hits), "")
	}
	e.sh("rm -f /root/.copilot/mcp-config.json")

	out, rc = e.sh("cd /proj && " + byok + "timeout 120 copilot -p 'say hi' --allow-all </dev/null 2>&1")
	if rc == 0 && strings.Contains(out, "UAT-MOCK-ANSWER") {
		unverified(t, h, "permissions.disableBypassPermissionsMode", fmt.Sprintf("`copilot -p --allow-all` starts and answers (rc=%d); whether tool calls still need approval was not exercised (the mock issues no chat-completions tool calls)", rc))
	} else {
		check(t, h, "permissions.disableBypassPermissionsMode: --allow-all refused", true, fmt.Sprintf("rc=%d %q", rc, tail(out, 2)), "")
	}
}

func mcpHits(e *cliEnv) map[string]int {
	hits := map[string]int{}
	for _, r := range e.mockRequests() {
		if strings.HasPrefix(r.Path, "/mcp/") {
			hits[r.Path]++
		}
	}
	return hits
}

// firstLines returns the lines of out containing any of the markers.
func firstLines(out string, markers ...string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		for _, m := range markers {
			if strings.Contains(l, m) {
				keep = append(keep, strings.TrimSpace(l))
				break
			}
		}
	}
	return strings.Join(keep, " / ")
}
