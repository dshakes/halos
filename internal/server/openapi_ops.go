package server

import (
	"net/http"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// Wire shapes the handlers build from maps or unexported structs. Each mirrors
// one handler's output; TestOpenAPILiveConformance calls the handlers and
// fails when a body stops matching its schema here.
type (
	fleetRingDoc struct {
		Ring    string    `json:"ring"`
		Subject string    `json:"subject"` // the device's bound user id
		Groups  *[]string `json:"groups"`  // IdP groups at enrollment; null when none
	}
	usageAck struct {
		Records   int  `json:"records"`
		Duplicate bool `json:"duplicate"`
	}
	dlpAck struct {
		Events    int  `json:"events"`
		Duplicate bool `json:"duplicate"`
	}
	webhookAck struct {
		Status string `json:"status"` // recorded | duplicate | stale | ignored
		Task   string `json:"task,omitempty"`
	}
	unlockResult struct {
		WasLocked bool `json:"wasLocked"`
	}
	breakGlassSession struct {
		User    string `json:"user"`
		Expires string `json:"expires"`
	}
	prResult struct {
		PRURL string `json:"prURL"`
	}
	experimentKillResult struct {
		Experiment  string         `json:"experiment"`
		Killed      bool           `json:"killed"`
		Changed     bool           `json:"changed"`
		CloudAgents map[string]any `json:"cloudAgents,omitempty"` // active cloud tasks the kill does not cancel
	}
	toggleKillResult struct {
		Toggle  string `json:"toggle"`
		Killed  bool   `json:"killed"`
		Changed bool   `json:"changed"`
	}
	killsResponse struct {
		Version uint64                  `json:"version"`
		Killed  []controller.KillRecord `json:"killed"`
	}
	freezeResult struct {
		Frozen  bool `json:"frozen"`
		Changed bool `json:"changed"`
	}
	togglesResponse struct {
		Toggles     []ToggleView `json:"toggles"`
		KillEnabled bool         `json:"killEnabled"`
	}
	toggleDetail struct {
		Toggle  ToggleView     `json:"toggle"`
		History []AuditEntry   `json:"history"`
		Preview *TogglePreview `json:"preview,omitempty"`
	}
	statusRequest struct {
		Status string `json:"status"`
	}
	reasonRequest struct {
		Reason string `json:"reason,omitempty"`
	}
	freezeRequest struct {
		Frozen *bool  `json:"frozen"`
		Reason string `json:"reason"`
	}
	ticketRequest struct {
		Ticket string `json:"ticket,omitempty"`
	}
	enrollRequest struct {
		Token string `json:"token"`
		OS    string `json:"os,omitempty"` // darwin | windows | anything else is unix
	}
	requestCreate struct {
		Kind          string `json:"kind"` // mcp-server | model | ring-opt-in | harness
		Item          string `json:"item"`
		Justification string `json:"justification"`
		Ticket        string `json:"ticket,omitempty"`
	}
	toggleProposal struct {
		promote.ToggleChange
		Reason string `json:"reason"`
	}
	tokenExchangeForm struct {
		GrantType          string `json:"grant_type"`         // urn:ietf:params:oauth:grant-type:token-exchange
		SubjectToken       string `json:"subject_token"`      // the CI provider's OIDC token (or a Halos credential, for delegation)
		SubjectTokenType   string `json:"subject_token_type"` // urn:ietf:params:oauth:token-type:jwt or :id_token
		RequestedTokenType string `json:"requested_token_type,omitempty"`
		Audience           string `json:"audience,omitempty"`
		ActorID            string `json:"actor_id,omitempty"` // delegation: the agent acting for the subject
	}
)

func errMap(codes ...any) map[int]string {
	m := map[int]string{}
	for i := 0; i+1 < len(codes); i += 2 {
		m[codes[i].(int)] = codes[i+1].(string)
	}
	return m
}

const (
	msgPolicy = "Policy not loaded."
	msgStore  = "The state store is unavailable; retry."
	msgAudit  = "The audit append failed (the message says whether the change stands)."
)

func jsonOK(typ any, example string) []res {
	return []res{{code: http.StatusOK, body: body{typ: typ, example: example}}}
}

func noBody(code int, desc string) []res { return []res{{code: code, body: body{desc: desc}}} }

func text(code int, ct, desc, example string) []res {
	return []res{{code: code, body: body{ct: ct, desc: desc, example: example}}}
}

// apiOps documents every route the server registers except the catch-alls
// ("/api/", "/", "/scim/v2/"). TestOpenAPICoversMux keeps it in step with mux().
var apiOps = append(append(coreOps, scimOps...), sessionOps...)

var coreOps = []apiOp{
	// ---- health ----
	{route: "GET /healthz", id: "getHealthz", tag: "Health", summary: "Liveness", auth: authNone,
		ok: text(200, "text/plain", "The process is alive.", "ok\n")},
	{route: "GET /readyz", id: "getReadyz", tag: "Health", summary: "Readiness", auth: authNone,
		desc: "Ready when a policy is loaded and, with the shared Postgres backend, the database answers.",
		ok:   text(200, "text/plain", "Ready.", "ok\n"), errs: errMap(503, "Database unreachable, or no policy loaded yet.")},
	{route: "GET /api/v1/openapi.yaml", id: "getOpenAPI", tag: "Health", summary: "This description", auth: authNone,
		desc: "The OpenAPI 3.1 document for this server's API, identical to api/openapi.yaml in the release. Public and read-only: it describes routes, not data.",
		ok:   text(200, "application/yaml", "The OpenAPI document.", "openapi: 3.1.0\n")},

	// ---- auth ----
	{route: "GET /auth/login", id: "login", tag: "Auth", summary: "Start the OIDC login", auth: authNone,
		desc: "Redirects to the identity provider (authorization-code flow with PKCE).",
		ok:   noBody(302, "Redirect to the identity provider."), errs: errMap(503, "Login unavailable (policy or identity provider not usable).")},
	{route: "GET /auth/callback", id: "loginCallback", tag: "Auth", summary: "OIDC redirect target", auth: authNone,
		desc:  "Completes the login, sets the `halo_session` cookie and redirects to `/`.",
		query: []query{{name: "code", desc: "Authorization code from the identity provider."}, {name: "state", desc: "The state issued by GET /auth/login."}, {name: "error", desc: "Set by the identity provider on failure."}},
		ok:    noBody(302, "Logged in; session cookie set."),
		errs: errMap(400, "Missing, reused or mismatched login state.", 401, "The identity provider or its token was rejected.",
			403, "The user is not allowed in (unverified email, unprovisioned, authn context, reserved id).", 429, "Too many failed logins from this address.", 503, "Login unavailable.")},
	{route: "POST /auth/logout", id: "logout", tag: "Auth", summary: "End the session", auth: authNone,
		desc: "Ends every session of the user, not only this cookie. Must come from the server's origin.",
		ok:   noBody(204, "Logged out."), errs: errMap(403, "Cross-origin request rejected.", 500, "The revocation could not be stored.")},
	{route: "POST /auth/breakglass", id: "breakGlassLogin", tag: "Service tokens", summary: "Break-glass local admin login", auth: authNone,
		desc: "A 30-minute admin session for `breakglass:<user>`. 404 unless break-glass is enabled or from an address outside --breakglass-allowed-cidrs. Audited at high severity.",
		req:  &body{typ: BreakGlassLogin{}, example: `{"user":"oncall","password":"..."}`},
		ok:   jsonOK(breakGlassSession{}, `{"user":"breakglass:oncall","expires":"2026-01-02T03:34:05Z"}`),
		errs: errMap(400, "Invalid JSON.", 401, "Invalid credentials.", 403, "Cross-origin request rejected.", 404, "Break-glass is not enabled, or the address is not allowed.",
			429, "Too many failed logins, the global lockout, or two attempts already running.", 500, msgAudit, 503, "Login unavailable.")},

	// ---- fleet and devices ----
	{route: "POST /api/v1/fleet/report", id: "postFleetReport", tag: "Fleet", summary: "Report a host's state", auth: authFleet,
		desc: "A halod status report (at most 64 KB). With a device token the user and device come from the binding, not the body; unknown fields are tolerated.",
		req:  &body{typ: Report{}, example: `{"time":"2026-01-02T03:04:05Z","hostname":"dev-laptop-17","user":"dev@acme.example","ring":"ring1-ga","digest":"sha256:0f1e2d3c","harnesses":{"claude-code":{"want":"2.1.0","installed":"2.1.0"}},"drift":[]}`},
		ok:   noBody(204, "Stored."),
		errs: errMap(400, "Unreadable or invalid JSON.", 401, "Invalid fleet or device token.", 413, "Report exceeds 64 KB.", 422, "Invalid report (hostname required, field too long).", 429, "Too many failed authentications.", 500, "Store failed.")},
	{route: "GET /api/v1/fleet/ring", id: "getFleetRing", tag: "Fleet", summary: "The ring this device follows", auth: authDevice,
		ok:   jsonOK(fleetRingDoc{}, `{"ring":"ring1-ga","subject":"dev@acme.example","groups":["eng"]}`),
		errs: errMap(401, "Invalid or expired device token.", 409, "No ring assigned.", 429, "Too many failed authentications.", 503, msgPolicy)},
	{route: "GET /api/v1/fleet/killswitch", id: "getFleetKillswitch", tag: "Kill switch", summary: "Signed kill list for halod", auth: authDevice,
		desc: "The same signed list as the gateway endpoint, for client-axis devices.",
		ok:   jsonOK(gateway.KillEnvelope{}, `{"payload":"eyJ2ZXJzaW9uIjo3fQ==","signature":"c2ln"}`),
		errs: errMap(401, "Invalid device token.", 404, "No kill-list signing key is configured.", 500, "Could not read or sign the list.")},
	{route: "GET /api/v1/gateway/killswitch", id: "getGatewayKillswitch", tag: "Kill switch", summary: "Signed kill list for gateways", auth: authGateway,
		desc: "`payload` is base64 of a KillList JSON; `signature` is ed25519 over `halo-killswitch-v1\\n` followed by the raw payload. Enabled only with both --killswitch-key-file and a gateway token.",
		ok:   jsonOK(gateway.KillEnvelope{}, `{"payload":"eyJ2ZXJzaW9uIjo3fQ==","signature":"c2ln"}`),
		errs: errMap(401, "Gateway token required.", 404, "Kill switch not configured.", 500, "Could not read or sign the list.")},
	{route: "GET /api/v1/gateway/posture", id: "getGatewayPosture", tag: "Gateway", summary: "Device-posture verdict", auth: authGateway,
		query: []query{{name: "subject", desc: "The user id, at most 256 characters.", required: true}},
		ok:    jsonOK(gateway.PostureVerdict{}, `{"compliant":true}`),
		errs:  errMap(400, "subject required.", 401, "Gateway token required.", 404, "Posture not configured.")},
	{route: "GET /api/v1/gateway/directory", id: "getGatewayDirectory", tag: "Gateway", summary: "SCIM directory entry, or the revocation list", auth: authGateway,
		desc:  "With `subject`: whether the user is an active provisioned user and their groups. With `revocations=1`: the credential revocation list gateways poll every 30 seconds.",
		query: []query{{name: "subject", desc: "The user id."}, {name: "revocations", desc: "Set to 1 for the revocation list instead of a directory entry."}},
		ok:    []res{{code: 200, body: body{one: []any{gateway.DirectoryEntry{}, gateway.RevocationList{}}, example: `{"active":true,"groups":["eng"]}`}}},
		errs:  errMap(400, "subject required.", 401, "Gateway token required.", 404, "SCIM directory or gateway token not configured.", 503, msgStore)},
	{route: "POST /api/v1/gateway/budget/check", id: "postGatewayBudgetCheck", tag: "Budgets", summary: "Budget verdict for a principal", auth: authGateway,
		req:  &body{typ: gateway.BudgetCheck{}, example: `{"subject":"dev@acme.example","groups":["eng"],"ring":"ring1-ga"}`},
		ok:   jsonOK(gateway.BudgetVerdict{}, `{"budgets":[]}`),
		errs: errMap(400, "Invalid JSON.", 401, "Gateway token required.", 404, "Budgets not configured.", 422, "Invalid principal.", 503, "Budget store unavailable.")},
	{route: "POST /api/v1/gateway/budget/usage", id: "postGatewayBudgetUsage", tag: "Budgets", summary: "Report gateway usage", auth: authGateway,
		desc: "At most 5000 records and 8 MiB. A batch id seen in the last hour is acknowledged with `duplicate: true` and not counted again.",
		req:  &body{typ: gateway.BudgetUsage{}, example: `{"batch":"b-1","records":[]}`},
		ok:   jsonOK(usageAck{}, `{"records":0,"duplicate":false}`),
		errs: errMap(400, "Invalid JSON.", 401, "Gateway token required.", 404, "Budgets not configured.", 413, "Usage batch too large.", 422, "Invalid batch.", 503, "Budget store unavailable; the gateway keeps and retries the batch.")},
	{route: "POST /api/v1/gateway/dlp/events", id: "postGatewayDLPEvents", tag: "Gateway", summary: "Report DLP findings", auth: authGateway,
		desc: "At most 500 events and 1 MiB; each is appended to the audit log as dlp.secret or dlp.injection. A batch id seen in the last hour returns `duplicate: true`.",
		req:  &body{typ: gateway.DLPBatch{}, example: `{"batch":"b-1","events":[]}`},
		ok:   jsonOK(dlpAck{}, `{"events":0,"duplicate":false}`),
		errs: errMap(400, "Invalid JSON.", 401, "Gateway token required.", 404, "DLP audit not configured.", 413, "DLP batch too large.", 422, "Invalid batch or event.", 503, "The audit log cannot be written; the gateway resends.")},

	// ---- enrollment ----
	{route: "GET /enroll.sh", id: "getEnrollSh", tag: "Enrollment", summary: "Enrollment script (macOS, Linux)", auth: authNone,
		ok: text(200, "text/x-shellscript", "A shell script that pins the halod checksum from server config.", ""), errs: errMap(404, "Enrollment is not configured.")},
	{route: "GET /enroll.ps1", id: "getEnrollPs1", tag: "Enrollment", summary: "Enrollment script (Windows)", auth: authNone,
		ok: text(200, "text/plain", "A PowerShell script that pins the halod checksum from server config.", ""), errs: errMap(404, "Enrollment is not configured.")},
	{route: "GET /enroll/release.pub", id: "getReleasePub", tag: "Enrollment", summary: "Release verification public key", auth: authNone,
		ok: text(200, "application/x-pem-file", "PEM public key.", ""), errs: errMap(404, "No public key configured.")},
	{route: "GET /enroll/killswitch.pub", id: "getKillswitchPub", tag: "Enrollment", summary: "Kill-list verification public key", auth: authNone,
		ok: text(200, "application/x-pem-file", "PEM public key.", ""), errs: errMap(404, "The kill switch is not configured.")},
	{route: "POST /api/v1/enroll", id: "postEnroll", tag: "Enrollment", summary: "Exchange an enrollment token for a device token", auth: authNone,
		desc: "The single-use enrollment token in the body is the credential (issued by POST /api/v1/launch/laptop). Answers a halod.yaml containing the device token; it is shown once.",
		req:  &body{typ: enrollRequest{}, example: `{"token":"enroll-token","os":"darwin"}`},
		ok:   text(200, "text/yaml", "The halod.yaml, mode 0600.", "registry: ghcr.io/acme/rel\n"),
		errs: errMap(400, "token required.", 401, "Invalid, expired or already used token.", 409, "No ring assigned.", 429, "Too many failed attempts.", 500, "Store or render failed, or "+msgAudit)},

	// ---- identity ----
	{route: "POST /api/v1/token/exchange", id: "postTokenExchange", tag: "Identity", summary: "RFC 8693 token exchange", auth: authNone, errKind: "OAuthError",
		desc: "Exchanges a CI provider's OIDC token for a short-lived Halos workload credential (ADR-0023), a delegated agent credential (ADR-0024) or an MCP access token (ADR-0029). " +
			"The subject token is the credential; policy `workloads` rules decide. Form-encoded, at most 16 KB. Errors follow RFC 6749 section 5.2.",
		req: &body{ct: "application/x-www-form-urlencoded", typ: tokenExchangeForm{}, example: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=eyJ...&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"},
		ok:  jsonOK(TokenExchangeResponse{}, `{"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900,"subject":"workload:acme/repo","ring":"ring1-ga"}`),
		errs: errMap(400, "invalid_request, invalid_grant, unsupported_grant_type or invalid_target.", 401, "The delegated credential was rejected.", 403, "No workload rule matches.",
			404, "Workload federation is not enabled (--workload-key-file) or policy declares no workloads.", 429, "slow_down: too many failed attempts.", 503, "temporarily_unavailable.")},
	{route: "POST /api/v1/agents/egress", id: "postAgentEgress", tag: "Identity", summary: "May this credential call a remote agent?", auth: authWorkload,
		desc: "Decides, from the verified credential's cohort and policy `agents.remote`, whether the caller may call a remote A2A agent (ADR-0024). A refusal is a 200 with `allow: false`.",
		req:  &body{typ: EgressRequest{}, example: `{"agent":"billing-agent","skill":"lookup"}`},
		ok:   jsonOK(policy.RemoteDecision{}, `{"allow":true,"agent":"billing-agent","reason":"listed in agents.remote"}`),
		errs: errMap(400, "Body must name an agent or url, under 4 KB.", 401, "A Halos workload or delegated agent credential is required.", 403, "The credential is revoked or its human root is deprovisioned.",
			404, "Needs --workload-key-file.", 429, "Too many failed attempts.", 500, msgAudit, 503, "Revocations cannot be checked, or no policy; retry.")},
	{route: "POST /api/v1/cloud-agents/webhooks/github", id: "postGitHubWebhook", tag: "Cloud agents", summary: "GitHub workflow_run delivery", auth: authSignature,
		desc: "Governed runs are stored as cloudagent.task; finished ones also as session.record. Body at most 1 MiB. An older delivery than the stored task answers 202 `stale`.",
		req:  &body{typ: map[string]any{}, desc: "A GitHub webhook payload (event workflow_run).", example: `{"action":"completed"}`},
		ok: []res{{code: 200, body: body{typ: webhookAck{}, example: `{"status":"recorded","task":"gh-1"}`}},
			{code: 202, body: body{typ: webhookAck{}, desc: "Ignored, duplicate or stale delivery.", example: `{"status":"ignored"}`}}},
		errs: errMap(400, "Unreadable payload.", 401, "Invalid signature.", 404, "Webhooks are not configured.", 413, "Body too large.", 500, "Audit log unreadable, or "+msgAudit, 503, "State store unavailable.")},
}

// sessionOps are the routes in routePerms: a session cookie or service token, and a permission.
var sessionOps = []apiOp{
	// ---- identity of the caller ----
	{route: "GET /api/v1/capabilities", id: "getCapabilities", tag: "Portal", summary: "Optional features and the caller's permissions",
		ok: jsonOK(Capabilities{}, `{"killSwitch":true,"roles":["operator"],"permissions":["read","operate"]}`)},
	{route: "GET /api/v1/harnesses", id: "getHarnesses", tag: "Portal", summary: "Harness capability matrix",
		ok: jsonOK(map[string][]harness.Capability{}, "")},
	{route: "GET /api/v1/whoami", id: "getWhoAmI", tag: "Portal", summary: "Ring and variants for a user",
		note:  "Without `read`, only the caller's own id is accepted (403 otherwise, audited).",
		query: []query{{name: "user", desc: "The user id, at most 256 characters.", required: true}, {name: "groups", desc: "Comma-separated groups to evaluate (read permission only; otherwise the caller's own)."}},
		ok:    jsonOK(WhoAmI{}, `{"user":"dev@acme.example","groups":[],"ring":"ring1-ga","assignments":[]}`),
		errs:  errMap(400, "user required.", 503, msgPolicy)},
	{route: "GET /api/v1/me", id: "getMe", tag: "Portal", summary: "The caller, their ring and what they may do",
		ok: jsonOK(Me{}, `{"id":"dev@acme.example","groups":[],"roles":[],"admin":false,"permissions":[],"ring":"","variants":[],"selfService":false,"launchers":[],"requestable":[],"optInRings":[]}`), errs: errMap(503, msgPolicy)},
	{route: "GET /api/v1/me/devices", id: "getMyDevices", tag: "Portal", summary: "The caller's enrolled devices and posture",
		ok: jsonOK(MyDevices{}, `{"devices":[],"posture":{"compliant":true}}`)},
	{route: "GET /api/v1/catalog", id: "getCatalog", tag: "Portal", summary: "What the caller may request",
		ok: jsonOK(Catalog{}, `{"harnesses":[],"launchers":[],"items":[]}`), errs: errMap(403, "Self-service is disabled.", 503, msgPolicy)},
	{route: "POST /api/v1/launch/{launcher}", id: "postLaunch", tag: "Portal", summary: "Launcher output",
		desc: "devcontainer: a snippet; codespaces and coder: a URL; laptop: a single-use enrollment token with bash and PowerShell one-liners.",
		ok:   jsonOK(Launch{}, `{"launcher":"codespaces","url":"https://github.com/codespaces/new?ref=ring1-ga"}`),
		errs: errMap(403, "Self-service is disabled.", 404, "Launcher not available.", 409, "Not assigned to a ring, or the launcher is not configured.", 503, msgStore)},
	{route: "POST /api/v1/requests", id: "postRequest", tag: "Portal", summary: "Ask for access",
		note: "Needs a person: a service token or break-glass session gets 403 (audited as authz.deny with need `human`).",
		req:  &body{typ: requestCreate{}, example: `{"kind":"ring-opt-in","item":"ring1-ga","justification":"I want the new model"}`},
		ok:   []res{{code: 201, body: body{typ: Request{}, example: `{"id":"r1","user":"dev@acme.example","kind":"ring-opt-in","item":"ring1-ga","justification":"I want the new model","status":"pending","createdAt":"2026-01-02T03:04:05Z"}`}}},
		errs: errMap(400, "Invalid JSON.", 403, "Self-service is disabled, or the caller is not a person.", 409, "A pending request for this already exists.", 422, "Invalid request, or a change ticket is required.", 500, "Store failed.", 503, msgStore)},
	{route: "GET /api/v1/requests", id: "listRequests", tag: "Portal", summary: "List access requests",
		note: "Everyone's requests need `approve`; otherwise only the caller's own are returned.",
		ok:   jsonOK([]Request{}, `[]`)},
	{route: "POST /api/v1/requests/{id}/approve", id: "approveRequest", tag: "Portal", summary: "Approve an access request",
		desc: "Opens a policy-repo pull request; nothing merges. Approval rules (ADR-0030) can require several approvers: 202 while the quorum is not met. A person only.",
		ok:   []res{{code: 200, body: body{typ: decisionView{}, example: `{"id":"r1","user":"dev@acme.example","kind":"ring-opt-in","item":"ring1-ga","justification":"I want the new model","status":"approved","createdAt":"2026-01-02T03:04:05Z"}`}}, {code: 202, body: body{typ: decisionView{}, desc: "Recorded; the quorum is not met yet.", example: `{"id":"r1","user":"dev@acme.example","kind":"ring-opt-in","item":"ring1-ga","justification":"I want the new model","status":"pending","createdAt":"2026-01-02T03:04:05Z"}`}}},
		errs: errMap(403, "Not a person, not an approver for this request, or the requester's own request.", 404, "Request not found.", 409, "Already decided, being decided, or already approved by this caller.",
			500, "The decision could not be stored or audited.", 502, "Could not open the policy PR.", 503, msgStore)},
	{route: "POST /api/v1/requests/{id}/deny", id: "denyRequest", tag: "Portal", summary: "Deny an access request",
		ok:   []res{{code: 200, body: body{typ: decisionView{}, example: `{"id":"r1","user":"dev@acme.example","kind":"ring-opt-in","item":"ring1-ga","justification":"I want the new model","status":"denied","createdAt":"2026-01-02T03:04:05Z"}`}}},
		errs: errMap(403, "Not a person, or the requester's own request.", 404, "Request not found.", 409, "Already decided or being decided.", 500, "The decision could not be stored or audited.", 503, msgStore)},

	// ---- fleet, devices, releases ----
	{route: "GET /api/v1/fleet", id: "getFleet", tag: "Fleet", summary: "Hosts, per-ring stats and drift", ok: jsonOK(FleetResponse{}, `{"hosts":[],"rings":[],"total":0,"driftHosts":0}`)},
	{route: "GET /api/v1/devices", id: "listDevices", tag: "Devices", summary: "Enrolled devices", ok: jsonOK([]Device{}, `[]`)},
	{route: "GET /api/v1/devices/{id}", id: "getDevice", tag: "Devices", summary: "One device with its recent reports",
		desc: "At most 50 recent reports, newest first; history resets on server restart. Token hashes are never returned.",
		ok:   jsonOK(DeviceDetail{}, `{"device":{"id":"d1","userID":"dev@acme.example","createdAt":"2026-01-02T03:04:05Z","lastSeen":"2026-01-02T03:04:05Z","revoked":false},"history":[]}`), errs: errMap(404, "Device not found.")},
	{route: "POST /api/v1/devices/{id}/revoke", id: "revokeDevice", tag: "Devices", summary: "Revoke a device token", ok: noBody(204, "Revoked. Audited as device.revoke."),
		errs: errMap(404, "Device not found.", 500, "Store failed, or "+msgAudit+" The revocation holds.")},
	{route: "POST /api/v1/users/{id}/revoke-sessions", id: "revokeUserSessions", tag: "Devices", summary: "Sign a user out everywhere", ok: noBody(204, "Revoked. Audited as session.revoke."),
		errs: errMap(500, "Store failed, or "+msgAudit+" The revocation holds.")},
	{route: "GET /api/v1/releases", id: "getReleases", tag: "Releases", summary: "Ring pointers, convergence and drift",
		desc: "Per ring: the signature-verified pointer read from the registry, convergence of reporting devices and drift. Cached 30 seconds; if the registry is unreachable the last verified state is returned with `stale`.",
		ok:   jsonOK(ReleasesResponse{}, `{"rings":[],"stale":false,"registry":"ghcr.io/acme/rel"}`)},

	// ---- audit and session ledger ----
	{route: "GET /api/v1/audit", id: "getAudit", tag: "Audit", summary: "The hash-chained audit log",
		desc: "`next` is the cursor to pass as `since`; `verified` covers the whole chain across rotated segments. Reads stream, so memory is bounded by `limit`.",
		query: []query{{name: "limit", desc: "Entries to return (default 100).", typ: "integer", min: 1, max: auditMaxLimit}, {name: "since", desc: "A sequence number or RFC 3339 time; returns entries after it, oldest first. Without it, the newest `limit` entries."},
			{name: "actor", desc: "Exact match."}, {name: "action", desc: "Exact match."}},
		ok:   jsonOK(AuditResponse{}, `{"entries":[{"seq":1,"time":"2026-01-02T03:04:05Z","actor":"boss@acme.example","action":"login","prev":"","hash":"0f1e2d3c"}],"next":1,"total":1,"verified":true,"head":"0f1e2d3c"}`),
		errs: errMap(400, "Invalid limit or since.", 500, "Audit log unreadable.")},
	{route: "GET /api/v1/sessions", id: "listAgentSessions", tag: "Sessions", summary: "Agent session ledger (ADR-0031)",
		desc: "The newest stored version of each session, newest start first.",
		query: []query{{name: "user", desc: "Halos identity, or the vendor identity of an unresolved session."}, {name: "harness", desc: "Harness name."}, {name: "ring", desc: "Ring name."},
			{name: "tool", desc: "A tool or MCP server."}, {name: "since", desc: "RFC 3339, on the session start."}, {name: "until", desc: "RFC 3339, on the session start."},
			{name: "limit", desc: "Sessions to return (default 100).", typ: "integer", min: 1, max: ledgerMaxLimit}},
		ok:   jsonOK(SessionsResponse{}, `{"sessions":[],"total":0,"verified":true,"head":""}`),
		errs: errMap(400, "Invalid filter.", 500, "Audit log unreadable.")},
	{route: "GET /api/v1/sessions/{id}", id: "getAgentSession", tag: "Sessions", summary: "One session by ledger id or harness session id",
		ok: jsonOK(SessionsResponse{}, `{"sessions":[],"total":0,"verified":true,"head":""}`), errs: errMap(404, "No such session.", 500, "Audit log unreadable.")},
	{route: "POST /api/v1/sessions", id: "importAgentSessions", tag: "Sessions", summary: "Store normalized session records",
		desc: "Up to 1000 records. Every record is validated first; one invalid record (prose in any field, an unhashed path, a forged id, an unknown field) refuses the whole batch. `who.user` is set from the SCIM directory, never from the body.",
		req:  &body{typ: SessionsIngest{}, example: `{"records":[]}`}, ok: jsonOK(SessionsIngest{}, `{"records":[]}`),
		errs: errMap(400, "Invalid body or record; nothing stored.", 500, msgAudit+" Some records may be stored.")},

	// ---- policy, experiments, toggles, rollouts ----
	{route: "GET /api/v1/policy", id: "getPolicy", tag: "Policy", summary: "The loaded policy",
		desc: "A console view of the policy; sets `X-Policy-Stale: 1` when serving the last good policy after a failed reload.",
		ok:   jsonOK(PolicyView{}, ""), errs: errMap(503, msgPolicy)},
	{route: "GET /api/v1/experiments", id: "listExperiments", tag: "Policy", summary: "Experiments with status and latest verdict",
		ok: jsonOK([]ExperimentDetail{}, ""), errs: errMap(503, msgPolicy)},
	{route: "GET /api/v1/experiments/{name}", id: "getExperiment", tag: "Policy", summary: "One experiment",
		ok: jsonOK(ExperimentDetail{}, ""), errs: errMap(404, "Experiment not found.", 503, msgPolicy)},
	{route: "POST /api/v1/experiments/{name}/status", id: "setExperimentStatus", tag: "Policy", summary: "Propose a status change",
		desc: "Opens a policy-repo pull request; nothing changes until a human merges. Audited as experiment.status.",
		req:  &body{typ: statusRequest{}, example: `{"status":"paused"}`}, ok: jsonOK(prResult{}, `{"prURL":"https://git.example/pr/1"}`),
		errs: errMap(404, "Experiment not found.", 409, "Already in that status.", 422, "status must be one of running, paused, concluded.", 500, msgAudit+" The PR was opened.",
			501, "No policy writer is configured (portal policyRepoDir).", 503, msgPolicy)},
	{route: "GET /api/v1/toggles", id: "listToggles", tag: "Policy", summary: "Feature toggles with live kill state",
		ok: jsonOK(togglesResponse{}, `{"toggles":[],"killEnabled":false}`), errs: errMap(500, "Kill switch unreadable.", 503, msgPolicy)},
	{route: "GET /api/v1/toggles/{name}", id: "getToggle", tag: "Policy", summary: "One toggle, its history and an optional evaluation",
		query: []query{{name: "user", desc: "Evaluate the toggle for this user; adds `preview`."}, {name: "ring", desc: "The ring to evaluate in (resolved from the user when omitted)."}, {name: "groups", desc: "Comma-separated groups."}},
		ok:    jsonOK(toggleDetail{}, ""), errs: errMap(404, "Toggle not found.", 422, "Unknown ring.", 500, "Kill switch or audit log unreadable.", 503, msgPolicy)},
	{route: "POST /api/v1/toggles/{name}/propose", id: "proposeToggleChange", tag: "Policy", summary: "Propose a toggle change",
		desc: "Validated against the guardrails first; opens a policy-repo pull request, nothing merges. Audited as toggle.propose.",
		req:  &body{typ: toggleProposal{}, example: `{"reason":"widen to ring1","default":false}`}, ok: jsonOK(prResult{}, `{"prURL":"https://git.example/pr/2"}`),
		errs: errMap(400, "Invalid JSON.", 404, "Toggle not found.", 422, "Reason missing, or an invalid or no-op change.", 500, msgAudit+" The PR was opened.", 501, "No policy writer is configured.", 503, msgPolicy)},
	{route: "GET /api/v1/rollouts", id: "listRollouts", tag: "Policy", summary: "Rollouts with controller state",
		ok: jsonOK([]RolloutView{}, ""), errs: errMap(503, msgPolicy)},
	{route: "GET /api/v1/rollouts/{name}", id: "getRollout", tag: "Policy", summary: "One rollout",
		ok: jsonOK(RolloutView{}, ""), errs: errMap(404, "Rollout not found.", 503, msgPolicy)},
	{route: "GET /api/v1/rollouts/{name}/approvals", id: "getRolloutApprovals", tag: "Governance", summary: "Approvals for a rollout's live step",
		ok: jsonOK(RolloutApprovals{}, ""), errs: errMap(404, "Rollout not found.", 503, msgStore)},
	{route: "POST /api/v1/rollouts/{name}/approve", id: "approveRolloutStep", tag: "Governance", summary: "Approve advancing a rollout",
		desc: "A person only. When an approval rule covers the next step the approver must hold one of its groups. Audit-strict: no record, no approval.",
		note: "Approval rules narrow this to their groups, in the handler.",
		req:  &body{typ: ticketRequest{}, example: `{"ticket":"CHG0012345"}`}, reqOptional: true, ok: jsonOK(RolloutApprovals{}, ""),
		errs: errMap(400, "Invalid JSON.", 403, "Not a person, or not in an approver group.", 404, "Rollout not found.", 409, "The rollout is finished, or this caller already approved the step.",
			422, "Invalid change ticket.", 500, msgAudit, 503, msgStore)},

	// ---- kill switch and freeze ----
	{route: "GET /api/v1/killswitch", id: "getKills", tag: "Kill switch", summary: "Active kills", ok: jsonOK(killsResponse{}, `{"version":7,"killed":[]}`), errs: errMap(500, "Kill switch unreadable.")},
	{route: "POST /api/v1/experiments/{name}/kill", id: "killExperiment", tag: "Kill switch", summary: "Kill an experiment",
		desc: "Takes effect on gateways at their next poll (default 10 seconds), does not expire, and is not lifted by pausing or concluding the experiment. No PR, no merge. Audited as experiment.kill.",
		req:  &body{typ: reasonRequest{}, example: `{"reason":"p95 latency regression"}`}, ok: jsonOK(experimentKillResult{}, `{"experiment":"opus-5-5-canary","killed":true,"changed":true}`),
		errs: errMap(400, "Invalid JSON or name.", 404, "Experiment not found.", 422, "A reason is required (at most 500 characters).", 500, "Store failed, or "+msgAudit,
			501, "The kill switch is not configured (--killswitch-key-file).", 503, msgPolicy)},
	{route: "POST /api/v1/experiments/{name}/unkill", id: "unkillExperiment", tag: "Kill switch", summary: "Lift an experiment kill",
		desc: "Also works for names no longer in policy, so stale kills can be cleared.",
		req:  &body{typ: reasonRequest{}, example: `{"reason":"fixed"}`}, reqOptional: true, ok: jsonOK(experimentKillResult{}, `{"experiment":"opus-5-5-canary","killed":false,"changed":true}`),
		errs: errMap(400, "Invalid JSON or name.", 422, "Reason too long.", 500, "Store failed, or "+msgAudit+" The unkill is reverted.", 501, "The kill switch is not configured.", 503, msgPolicy)},
	{route: "POST /api/v1/toggles/{name}/kill", id: "killToggle", tag: "Kill switch", summary: "Kill a feature toggle (fleet-wide off)",
		req: &body{typ: reasonRequest{}, example: `{"reason":"bad payload"}`}, ok: jsonOK(toggleKillResult{}, `{"toggle":"new-hook","killed":true,"changed":true}`),
		errs: errMap(400, "Invalid JSON or name.", 404, "Toggle not found.", 422, "A reason is required.", 500, "Store failed, or "+msgAudit, 501, "The kill switch is not configured.", 503, msgPolicy)},
	{route: "POST /api/v1/toggles/{name}/unkill", id: "unkillToggle", tag: "Kill switch", summary: "Lift a toggle kill",
		req: &body{typ: reasonRequest{}, example: `{}`}, reqOptional: true, ok: jsonOK(toggleKillResult{}, `{"toggle":"new-hook","killed":false,"changed":false}`),
		errs: errMap(400, "Invalid JSON or name.", 422, "Reason too long.", 500, "Store failed, or "+msgAudit, 501, "The kill switch is not configured.", 503, msgPolicy)},
	{route: "GET /api/v1/freeze", id: "getFreeze", tag: "Governance", summary: "Incident freeze and each ring's freeze windows",
		ok: jsonOK(FreezeView{}, ""), errs: errMap(500, "Freeze state unreadable.", 503, msgPolicy)},
	{route: "POST /api/v1/freeze", id: "setFreeze", tag: "Governance", summary: "Set or lift the incident freeze",
		desc: "Rollbacks and the kill switch are never frozen. Audit-strict: a freeze whose record fails stays set; a lift whose record fails is reverted.",
		req:  &body{typ: freezeRequest{}, example: `{"frozen":true,"reason":"incident INC-42"}`}, ok: jsonOK(freezeResult{}, `{"frozen":true,"changed":true}`),
		errs: errMap(400, `Want {"frozen": true|false, "reason": "..."}.`, 422, "A reason is required (at most 500 characters).", 500, "Store failed, or "+msgAudit)},

	// ---- budgets, cloud agents ----
	{route: "GET /api/v1/budgets", id: "getBudgets", tag: "Budgets", summary: "Every budget counter with spend in its current window",
		query: []query{{name: "budget", desc: "Exact-match budget name."}, {name: "key", desc: "Exact-match counter key, for example user:alice@acme.com."}},
		ok:    jsonOK(BudgetsResponse{}, `{"budgets":[],"at":"2026-01-02T03:04:05Z"}`), errs: errMap(503, "Budget store unavailable, or no policy.")},
	{route: "GET /api/v1/cloud-agents", id: "getCloudAgents", tag: "Cloud agents", summary: "Cloud agent tasks and policy alerts",
		query: []query{{name: "active", desc: "true keeps queued and running tasks only.", typ: "boolean"}},
		ok:    jsonOK(CloudAgentsView{}, `{"tasks":[],"alerts":[],"configured":{"cursor":false,"github":false,"githubWebhook":false}}`), errs: errMap(500, "Audit log unreadable.", 503, msgPolicy)},
	{route: "POST /api/v1/cloud-agents/kill", id: "killCloudAgents", tag: "Cloud agents", summary: "Cancel the active cloud tasks of a user, ring or experiment",
		desc: "`dryRun` defaults to true (plan only). A real run is audited before any vendor call and each result after.",
		req:  &body{typ: CloudKillRequest{}, example: `{"scope":"user","name":"dev@acme.example","reason":"leaked credential"}`}, ok: jsonOK(CloudKillResponse{}, `{"dryRun":true,"actions":[],"unattributed":0,"next_steps":[]}`),
		errs: errMap(400, "Invalid JSON, or an unknown scope or name.", 422, "A reason is required (at most 500 characters).", 500, "Audit log unreadable, or "+msgAudit, 503, msgPolicy)},

	// ---- revocations, service tokens, break-glass ----
	{route: "POST /api/v1/revocations", id: "revokeCredential", tag: "Revocations", summary: "Revoke a halo-server credential (ADR-0026)",
		desc: "Exactly one of `jti` (kills the credential and every credential exchanged from it) and `subject` (`agent:<name>`, `workload:<subject>` or a human id; kills every credential issued at or before now, and a human id also revokes their sessions). Audited as credential.revoke.",
		req:  &body{typ: RevokeRequest{}, example: `{"subject":"agent:reviewer","reason":"compromised"}`},
		ok:   jsonOK(Revocation{}, `{"subject":"agent:reviewer","revokedBefore":"2026-01-02T03:04:06Z","expires":"2026-01-02T04:04:06Z","by":"boss@acme.example","reason":"compromised","at":"2026-01-02T03:04:05Z"}`),
		errs: errMap(400, "Invalid body (exactly one of jti and subject, a reason, a valid jti).", 409, "10,000 revocations are active.", 500, msgAudit+" The revocation holds.", 503, msgStore+" Nothing was revoked.")},
	{route: "GET /api/v1/revocations", id: "listRevocations", tag: "Revocations", summary: "Active revocations", ok: jsonOK(RevocationsResponse{}, `{"revocations":[]}`), errs: errMap(503, msgStore)},
	{route: "POST /api/v1/service-tokens", id: "createServiceToken", tag: "Service tokens", summary: "Create a service-account token (ADR-0036)",
		desc: "The secret is shown once. The role may not exceed the caller's; `ttl` is 1h up to --service-token-max-ttl (default and maximum 90 days). Audited as service-token.create.",
		note: "Only an interactive session may create one: a token or break-glass caller gets 403.",
		req:  &body{typ: CreateServiceTokenRequest{}, example: `{"name":"ci-reporter","role":"viewer","ttl":"720h","owner":"platform"}`},
		ok:   []res{{code: 201, body: body{typ: CreateServiceTokenResponse{}, example: `{"token":"halo_sat_0123456789abcdef.secret","serviceToken":{"id":"0123456789abcdef","principal":"svc:ci-reporter:0123456789abcdef","name":"ci-reporter","role":"viewer","owner":"platform","createdBy":"boss@acme.example","createdAt":"2026-01-02T03:04:05Z","expiresAt":"2026-02-01T03:04:05Z","expired":false,"revoked":false}}`}}},
		errs: errMap(400, "Invalid name, role, ttl, description or owner.", 403, "The caller is a token or break-glass session, or the role exceeds the caller's.", 409, "1,000 tokens are active.",
			500, "Token generation failed, or "+msgAudit+" The token is revoked and not returned.", 503, msgStore)},
	{route: "GET /api/v1/service-tokens", id: "listServiceTokens", tag: "Service tokens", summary: "Service-account tokens (never the secret)",
		ok: jsonOK(ServiceTokensResponse{}, `{"tokens":[]}`), errs: errMap(503, msgStore)},
	{route: "POST /api/v1/service-tokens/{id}/revoke", id: "revokeServiceToken", tag: "Service tokens", summary: "Revoke a service-account token",
		desc: "Holds on every replica at the token's next request. Audited as service-token.revoke.",
		req:  &body{typ: RevokeServiceTokenRequest{}, example: `{"reason":"rotated"}`},
		ok:   jsonOK(ServiceTokenInfo{}, `{"id":"0123456789abcdef","principal":"svc:ci-reporter:0123456789abcdef","name":"ci-reporter","role":"viewer","createdBy":"boss@acme.example","createdAt":"2026-01-02T03:04:05Z","expiresAt":"2026-02-01T03:04:05Z","expired":false,"revoked":true}`),
		errs: errMap(400, "Invalid id, JSON or reason.", 404, "Service token not found.", 500, msgAudit+" The revocation holds.", 503, msgStore)},
	{route: "POST /api/v1/breakglass/unlock", id: "unlockBreakGlass", tag: "Service tokens", summary: "Lift the break-glass lockout",
		desc: "Lifts the global lockout on every replica and resets its failure count. Audited as breakglass.unlock at high severity.",
		note: "A person only: a token or break-glass caller gets 403.",
		ok:   jsonOK(unlockResult{}, `{"wasLocked":false}`),
		errs: errMap(403, "The caller is a token or break-glass session.", 404, "Break-glass is not configured.", 500, msgAudit+" Nothing changed.", 503, msgStore)},
}

// scimOps are the RFC 7644 endpoints; bodies are the RFC's resources, kept loose.
var scimOps = func() []apiOp {
	var out []apiOp
	scimErrs := errMap(401, "Invalid SCIM token.", 404, "SCIM is not enabled, or unknown endpoint.", 429, "Too many failed authentications.")
	add := func(route, id, summary string, query []query, example string, code int, typ any, extra map[int]string) {
		errs := map[int]string{}
		for k, v := range scimErrs {
			errs[k] = v
		}
		for k, v := range extra {
			errs[k] = v
		}
		o := apiOp{route: route, id: id, tag: "SCIM", summary: summary, auth: authSCIM, errKind: "ScimError", query: query, errs: errs}
		if example != "" {
			o.req = &body{ct: "application/scim+json", typ: map[string]any{}, example: example}
		}
		if typ != nil {
			o.ok = []res{{code: code, body: body{ct: "application/scim+json", typ: typ}}}
		} else {
			o.ok = noBody(code, "Deleted.")
		}
		out = append(out, o)
	}
	for _, d := range []struct{ route, id, summary string }{
		{"GET /scim/v2/ServiceProviderConfig", "scimServiceProviderConfig", "SCIM service provider configuration"},
		{"GET /scim/v2/ResourceTypes", "scimResourceTypes", "SCIM resource types"},
		{"GET /scim/v2/ResourceTypes/{id}", "scimResourceType", "One SCIM resource type"},
		{"GET /scim/v2/Schemas", "scimSchemas", "SCIM schemas"},
		{"GET /scim/v2/Schemas/{id}", "scimSchema", "One SCIM schema"},
	} {
		add(d.route, d.id, d.summary, nil, "", http.StatusOK, map[string]any{}, errMap(404, "Unknown id or SCIM not enabled."))
	}
	list := []query{
		{name: "filter", desc: "`attr eq \"value\"` only: userName, externalId or id on users; displayName, externalId or id on groups."},
		{name: "startIndex", desc: "1-based index of the first result.", typ: "integer"},
		{name: "count", desc: "Page size, at most 1000.", typ: "integer", min: 0, max: 1000},
		{name: "excludedAttributes", desc: "`members` omits group members."},
	}
	const patch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Renamed"}]}`
	for _, k := range []struct{ plural, noun, res string }{
		{"Users", "user", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"new@acme.example","active":true}`},
		{"Groups", "group", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"new-group"}`},
	} {
		base := "/scim/v2/" + k.plural
		add("GET "+base, "scimList"+k.plural, "List "+k.noun+"s", list, "", 200, scimListDoc{}, nil)
		add("POST "+base, "scimCreate"+k.plural, "Create a "+k.noun, nil, k.res, 201, scimResourceDoc{}, errMap(400, "Invalid resource.", 409, "uniqueness: userName or displayName is taken."))
		add("GET "+base+"/{id}", "scimGet"+k.plural, "Read a "+k.noun, nil, "", 200, scimResourceDoc{}, nil)
		add("PUT "+base+"/{id}", "scimReplace"+k.plural, "Replace a "+k.noun, nil, k.res, 200, scimResourceDoc{}, errMap(400, "Invalid resource.", 409, "uniqueness.", 412, "If-Match does not match."))
		add("PATCH "+base+"/{id}", "scimPatch"+k.plural, "Patch a "+k.noun, nil, patch, 200, scimResourceDoc{}, errMap(400, "Invalid patch.", 412, "If-Match does not match."))
		add("DELETE "+base+"/{id}", "scimDelete"+k.plural, "Delete a "+k.noun, nil, "", 204, nil, errMap(412, "If-Match does not match."))
	}
	return out
}()

// scimResourceDoc and scimListDoc stand for the loose SCIM schemas in the spec.
type (
	scimResourceDoc map[string]any
	scimListDoc     map[string]any
)
