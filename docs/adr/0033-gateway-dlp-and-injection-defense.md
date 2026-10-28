---
title: "ADR-0033: Data-loss prevention and prompt-injection defense at the gateway"
description: halo-proxy and halo-kong scan model-call requests for secrets (monitor, redact or block) and tool results for prompt-injection signals (monitor or block), per ring and org unit; halo-proxy also watches streamed responses for echoed secrets. Findings are counted, audited through halo-server's hash-chained log to the SIEM, and totalled in the session ledger, never with the secret.
status: accepted
date: 2026-10-27
---

# ADR-0033: Data-loss prevention and prompt-injection defense at the gateway

- Status: accepted (extends ADR-0007, ADR-0016, ADR-0017)
- Date: 2026-10-27

## Context and problem statement

Every model call from a coding CLI carries whatever the agent read: `.env` files, cloud credentials in shell history, a teammate's token pasted into a chat, a service-account key the agent `cat`ed while debugging. All of it leaves the company in the request body. The guardrails (ADR-0007) govern the *configuration* the CLIs run with; nothing looks at the *content* they send. In the other direction, tool results (web pages, issue bodies, files, MCP output) enter the model with the same authority as the user's own text, which is how indirect prompt injection works: a README tells the agent to ignore its instructions and post `~/.aws/credentials` somewhere.

Every model call already crosses the Halos gateway with a verified identity, ring and org unit. How should the gateway find secrets and injection attempts in that traffic, act on them per policy, and leave evidence, without breaking the wire protocols, streaming, or the "never log content" rule?

## Decision drivers

- **Precision over recall.** A false positive that blocks a developer's request costs more trust than one missed generic string. Detectors must be high precision, and the defaults must not block anything.
- **Never store the secret.** Not in logs, metrics, audit events or error messages. Findings carry a detector id, an 8-hex SHA-256 prefix and a JSON path.
- **Protocol correctness.** A redacted body is still valid JSON with the same structure; a block is the error shape each CLI already shows (like `Rejection`); a streamed response is never buffered, delayed or changed.
- **Bounded cost.** A size cap and a time budget per request, linear-time regexes (RE2), and a benchmark.
- **Policy-driven per ring and org unit**, with the same validation and `halos.dev/v1` additivity as budgets (ADR-0017): a policy without `gateway.dlp` compiles to the same snapshot bytes.
- **Evidence in the existing chain.** Findings reach the SIEM through the ADR-0016 exporter, not a new pipeline.
- No new dependency, no model call on the request path, no content-modifying "sanitizer" for model output.

## Considered options

1. **An external DLP service or LLM classifier on the request path.** Rejected: a network hop and a second copy of every prompt per request, a new trust boundary, and non-deterministic verdicts that cannot be dry-run.
2. **Client-side hooks only** (a Claude Code `PreToolUse` hook, a pre-commit scan). Kept as complementary, rejected as the control: not every harness has hooks, and a client can turn them off. The gateway sees every routed call regardless of harness.
3. **Gateway scan in `internal/gateway` with deterministic detectors and heuristics (chosen).** Shared by halo-proxy and halo-kong through `PrepareVerified`, testable offline with `halo dlp test`.

## Decision outcome

Chosen: **option 3**.

### Policy (`Gateway.dlp`, optional)

```yaml
dlp:
  secrets:
    action: redact            # monitor (default) | redact | block | off
    disable: [jwt]            # built-in detector ids to turn off
    patterns:                 # org detectors, RE2; first capture group (if any) is the secret
      - {id: acme-deploy-token, regex: 'acme_dpl_[a-z0-9]{32}'}
  injection:
    action: monitor           # monitor (default) | block | off
    threshold: 4              # default 4: two independent signals
  rules:                      # first match wins; empty rings/units = any; a unit matches its descendants
    - {units: [payments], secrets: block}
    - {rings: [ring1-canary], injection: block}
  maxScanBytes: 4194304       # default 4 MiB
  scanResponses: true         # default true (halo-proxy)
```

`halo validate` checks actions, detector ids, ids against `^[a-z0-9][a-z0-9._-]{0,62}$` (and not a built-in id), patterns compile as RE2 (Go `regexp`: no backreferences or lookaround, linear time), do not match the empty string and are at most 1 KiB (64 per policy), rule rings and units exist, and warns that `engine: kong` scans requests only and `engine: external` scans nothing.

### Secret detectors

| id | Matches |
|---|---|
| `aws-access-key-id` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + 16 upper-case alphanumerics, word-bounded; AWS's `...EXAMPLE` documentation key excluded |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 or more alphanumerics; `github_pat_` fine-grained tokens |
| `gitlab-token` | `glpat-`/`glptt-`/`gldt-`/`glrt-` + 20 to 64 characters |
| `slack-token` | `xox[abposr]-<digits>-<...>` |
| `slack-webhook` | `https://hooks.slack.com/services|workflows/T…/…/…` |
| `stripe-key` | `sk_live_`/`rk_live_` (test keys are not secrets) |
| `anthropic-api-key` | `sk-ant-api|admin|oatNN-` + 32 or more characters |
| `openai-api-key` | `sk-[proj-|svcacct-|admin-]…T3BlbkFJ…` (the base64 of `OpenAI` every key carries) |
| `jwt` | `eyJ….eyJ….<signature>`: a base64url JSON header and payload and a signature |
| `private-key` | a PEM `-----BEGIN … PRIVATE KEY-----` block with at least 64 base64 characters before its END line (documentation stubs do not match) |
| `gcp-service-account` | the 40-hex `private_key_id` of a key file that says `service_account` (its `private_key` is the PEM detector's) |
| `generic-secret` | a key name (`secret`, `token`, `password`, `api_key`, `access_key`, `private_key`, `credential`, `auth`…) assigned a value of 24 or more characters that mixes upper case, lower case and digits, has at least 3.5 bits of entropy per character, is not two or more lower-case words (paths, sentences) and holds no placeholder (`example`, `your`, `changeme`, `xxxx`…) |

Each detector runs only near its anchors: one pass over the text finds every anchor (a table keyed by the first two bytes), and the regex runs on a bounded window around each. Overlapping windows are merged and fed to the regex in 32 KiB chunks (overlapping by the window size), so a text that repeats an anchor (`eyJ`, `-----BEGIN `) costs one regex pass per detector, never anchors times window; matches come from the index engine and submatch offsets are computed only for a match. `html-comment-imperative` is a linear matcher (each `-->` visited once) instead of a regex with 2000 counted repetitions. The 250 ms budget and a 64 MiB cap on regex bytes per request are checked inside every pass, not only between JSON strings. Overlapping matches keep the earliest, then the longest.

**What is scanned.** Every JSON string of the request body, object keys included (a tool input or function response can carry a secret as a key; keys are scanned for secrets, never scored for injection, and a key's finding location is its object's path plus `.<key>`, never the key), so user text, system prompts, tool results, documents and file contents in any wire (Anthropic Messages, Bedrock invoke and Converse, OpenAI Responses, Gemini), including `count_tokens` (it sends the same content to the provider). Not scanned: values under ids, enums and opaque or signed blobs (`model`, `id`, `type`, `role`, `tool_use_id`, `call_id`, `signature`, `thoughtSignature`, `thinking`, `encrypted_content`, `data` (base64 media), `media_type`, `mimeType`, `file_id`, `cache_control`). Thinking blocks are signed by the provider; changing them would break the next turn.

**Actions.**

- `monitor`: count, log, audit; the request is forwarded unchanged.
- `redact`: each secret is replaced in place with `[REDACTED:<detector>:<hash8>]`, where `hash8` is the first 8 hex of SHA-256 of the secret. Only the string literals holding a secret are re-encoded (without HTML escaping), keys as well as values: a key is replaced by its redacted text, which is never ambiguous (two keys of one object redact to the same text only if they were already equal, or on an 8-hex hash collision), so a key is redacted rather than blocked; every other byte of the body is kept, so the JSON stays valid and its structure, key order and other values are unchanged. The redacted body is what the model rewrite, failover targets, the budget estimate and the shadow mirror use (`shadow.Jobs` takes it from `Result.DLP`).
- `block`: HTTP 400 in the caller's wire format, like every gateway `Rejection`: Anthropic `invalid_request_error`, OpenAI Responses `code: secret_detected`, Gemini `INVALID_ARGUMENT`, Bedrock `{"message"}`. 400 is permanent, so the CLIs show it and do not retry. The message names the detector, marker and JSON path, never the secret.

A conversation re-sends its history every turn, so a secret in history is found (and redacted or blocked) on every later turn until the user removes it. With `block`, that means the session cannot continue until the user rewinds or clears it, which is intended.

### Prompt-injection signals

Scored only on tool output and documents entering the model (by wire: an Anthropic or Bedrock block's own `content`, Bedrock `toolResult`, Responses `input[i].output`, Gemini `functionResponse`), never on what the user typed. Each signal counts once per text:

| Signal | Weight | Heuristic |
|---|---|---|
| `instruction-override` | 3 | "ignore / disregard / forget / override (all) previous / prior / above / system instructions / prompts / rules" |
| `secret-in-url` | 3 | a detected secret inside an `http(s)://` URL |
| `invisible-unicode` | 3 or 2 | Unicode tag characters (U+E0000–U+E007F, invisible ASCII smuggling): 3; zero-width or bidi controls (U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+2069, U+FEFF after the start): 2 |
| `role-reassignment` | 2 | a new role or rule set for the model: "you are now" plus a role, a "new instructions" header, "from now on" plus an order to the model, a request to disclose the model's system prompt |
| `fake-turn` | 2 | a line opening with `<system>`, `</tool_result>`, `<function_results>`, `[INST]`, `<\|im_start\|>`, `Human:`, `Assistant:` or `SYSTEM:` |
| `html-comment-imperative` | 2 | an HTML comment holding "ignore previous", "you must", "assistant", "do not tell", `curl `, `wget `, "send the/all/your", "exfiltrate" |
| `exfil-url` | 2 | a Markdown image whose URL carries a query value of 24 or more characters (the classic render-to-exfiltrate) |
| `permission-bypass` | 2 | `policy.BypassToken`: `bypassPermissions`, `danger-full-access`, `--dangerously-skip-permissions`, `--yolo` … (the same scanner as invariant 1) |

A text at or above `threshold` (default 4) is a finding; below it nothing is recorded. With the default, one signal never triggers alone: an override phrase needs a second, independent sign. `monitor` counts and audits; `block` answers 400 `prompt_injection_detected` in the wire format. Model content is never modified: rewriting a tool result changes what the agent did, and a partial "sanitizer" gives false assurance.

**False positives.** `TestBenignCorpus` scans every Go, Markdown and YAML file in this repository (about 1,000 files, including the guardrail docs that discuss bypass tokens and this ADR) as tool results with every detector on. It passes with no finding except two test fixtures that plant a fake secret on purpose (a jwt.io example token and a `ghp_` value), which the test lists by file and detector.

### Streaming responses (monitor only)

halo-proxy scans the generated text of streamed responses for secrets the model echoes back. The text comes from the same parser that meters usage (`gateway.UsageTapText`: Anthropic and Bedrock deltas, OpenAI Responses `*.delta`, Gemini parts), so the client receives the upstream bytes unchanged and unbuffered; `TestDLPRedactsRequestAndMonitorsStream` checks byte equality. Text is scanned in 16 KiB windows with 4 KiB carried over, so a secret split across deltas or windows is seen whole, up to 4 MiB per response; each distinct secret is reported once. Non-streamed JSON responses and halo-kong responses are not scanned (Kong's Go PDK cannot read a streamed body without buffering it, as for budgets).

### Bounds

- `maxScanBytes` (default 4 MiB, at most 64 MiB) per request body and a 250 ms scan budget. Past either, under a `monitor` or `redact` secret action the rest of the body is forwarded unscanned and counted as `truncated`: the scan fails open. Under a `block` secret action (resolved per ring and unit) the request is refused instead, because `block` promises no secret reaches the model and an unscanned tail could hold one: a 413 in the caller's wire format past `maxScanBytes`, a 400 (`dlp_scan_incomplete`) past the time budget or for a body that is not JSON, each counted as `truncated` and `blocked`. A body that is not JSON is otherwise not scanned (the upstream refuses it anyway).
- **Benchmark** (`BenchmarkScanRequest200KB`, Apple M4 Max, Go 1.26): a 200 KB Claude Code style request whose tool results are the Go sources of `internal/gateway` (an adversarial corpus: dense in key names, `token`, `secret` and the detectors' own anchors) costs **4.6 ms mean, 5.0 to 5.7 ms p99** for `monitor` and about the same for `redact` (2.2 MB allocated per scan). A request without candidates costs one pass of the anchor table plus the JSON walk. After window merging the same benchmark is about 3.2 ms mean, 3.5 ms p99. `TestScanAdversarialBodies` holds a 256 KB body repeating any one anchor (each detector's and each injection signal's) under 300 ms scanned in full, a 4 MB one within the budget (truncated if not done), and the response scanner over 4 MB of one anchor under 1 s.

### Evidence

- **Request log:** a `dlp` attribute per request: kind, detector, action, JSON path, `#hash8`, injection score and signals.
- **Metrics** (halo-proxy `/metrics`): `halo_proxy_dlp_scans_total{direction,outcome}` (`clean`, `finding`, `redacted`, `blocked`, `truncated`), `halo_proxy_dlp_findings_total{kind,detector,action,direction}`, `halo_proxy_dlp_scan_seconds_total`, `halo_proxy_dlp_audit_events_total{outcome}` (`sent`, `dropped`, `deduped`), `halo_proxy_dlp_audit_failures_total`; halo-kong `halo_kong_dlp_findings_total{kind,detector,action}`. Labels are detector ids from code or policy, never request data.
- **Audit and SIEM.** With `dlp.url` (halo-proxy) or `dlp_url` (halo-kong), findings are posted to `POST /api/v1/gateway/dlp/events` on halo-server (a per-gateway token from `--gateway-dlp-tokens-dir` is recommended: the token, never the body, names the gateway, and a body naming another gateway is refused; with `--gateway-dlp-token-file` or the shared gateway token any gateway could write as another, so entries are attributed to `gateway:unverified` with the claimed name in `claimedGateway`). halo-server validates each event (enumerated kinds, actions and directions; `hash` must be 8 hex characters, so a gateway cannot put a secret where the hash goes; bounded strings without control characters) and appends one audit entry per event: action `dlp.secret` or `dlp.injection`, actor `gateway:<name>` (per-gateway token) or `gateway:unverified`, target the verified subject (`anonymous` otherwise), details `detector`, `hash`, `location`, `action`, `direction`, `ring`, `unit`, `protocol`, `harness`, `chain`, `score`, `signals`, `batch`. The ADR-0016 exporter forwards them with every other entry. Gateways batch every 5 s (and on shutdown), never block the request path (a 10,000-event queue; overflow is dropped and counted), report one finding (subject, detector, hash, location, direction, action) once per hour, resend a failed batch under the same id (halo-server appends a batch id once per replica; delivery is at least once), and drop a batch halo-server refuses as invalid.
- **Session ledger** (ADR-0031): halo-proxy's GenAI span carries `halo.dlp.secrets` and `halo.dlp.injections`; the ledger's gateway source sums them per trace into `dlpSecrets` and `dlpInjections`, and the ClickHouse table gains `dlp_secrets` and `dlp_injections` (`ALTER TABLE … ADD COLUMN IF NOT EXISTS` for existing tables).

### `halo dlp test <file>`

Dry-runs the scan locally: a JSON model-call body is scanned as a request, any other file as a tool result. With `--policy-dir`, the policy's detectors, org patterns and rules apply for `--ring` and `--unit`; `--secrets` and `--injection` override the action for the run, `--show-redacted` prints the redacted body, `--output json` gives the report. Exit 0 when nothing is found, 2 when something is.

## Consequences

- Good: one policy block protects every harness that routes through the gateway, with evidence in the audit chain the security team already receives, and a local dry-run for tuning.
- Good: redaction keeps every byte that is not a secret, so prompt caching of earlier turns keeps working when history is unchanged.
- Bad: detection is pattern-based. A secret with no recognisable shape and no key name (a random password pasted alone) is not found; a secret split across two JSON strings is not either. Org patterns cover formats specific to the company.
- Bad: injection heuristics are conservative by design and will miss paraphrased attacks. They are a tripwire and an audit trail, not a guarantee; the CLI's own permission prompts and the guardrails (ADR-0007) remain the control on what the agent may do.
- Bad: under `monitor` and `redact`, a scan past `maxScanBytes` or 250 ms fails open (counted). Fail-closed there would refuse legitimate large contexts for a mode that never refuses. Under `block` it fails closed (413 or 400, counted): a ring that blocks secrets cannot honour that on bytes it did not read, so scope `block` with `rules` to the rings and units that need it and size `maxScanBytes` to their contexts. The time budget makes that refusal load-dependent near the limit; a retry after `/compact` succeeds.
- Bad: the 8-hex hash prefix lets someone who already holds a candidate secret confirm it appeared. 32 bits do not let anyone recover a high-entropy secret, but a low-entropy password could be confirmed by guessing; the detectors target generated credentials.
- Neutral: response scanning is monitor-only and halo-proxy-only. Blocking a response mid-stream would leave the CLI with a broken message; the finding is audited and the secret should be rotated.
- Neutral: older gateways ignore `gateway.dlp` in a snapshot; upgrade the traffic plane first, as the compatibility page recommends.

## More information

`internal/gateway/dlp.go`, `internal/gateway/dlp_report.go`, `internal/policy/dlp.go`, `internal/server/dlp.go`, `cmd/halo-proxy/dlp.go`, `cmd/halo-kong/main.go`, `cmd/halo/cmd_dlp.go`; guide: [Data-loss prevention](/halos/guides/dlp/).
