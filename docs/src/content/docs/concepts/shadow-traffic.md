---
title: Shadow traffic
description: What halo-shadow does, how it measures every step of multi-turn agent sessions without executing anything, and what to use for whole-task comparison.
---

The shadow mirror (`halo-shadow`) sends a sampled, asynchronous copy of production requests to a candidate route and stores request/response pairs for grading. Kong OSS has no request-mirroring plugin, so Halos ships its own. `halo-proxy` and `halo-kong` both enqueue mirror jobs.

## What a shadow can and cannot measure

A coding agent's turns are linked by tool calls with side effects: edit a file, run the tests, read the output. A shadow candidate's tool calls are **never executed**. Running them would double side effects and is unsafe. So no shadow can tell you where the candidate's *own* trajectory would have gone. That is what [replay evals](/halos/guides/writing-evals/) are for: they run whole tasks in a sandbox where tools really execute.

What a shadow *can* measure is every **decision** the candidate would make on real traffic. Each request a coding agent sends after the first carries the real conversation so far: the developer's prompt, the actions production took, and the real tool results (terminal output, test failures, file contents). Replaying that request asks both arms one question: *given exactly this state, what do you do next?* The comparison is [teacher-forced](/halos/adr/0014-step-level-multi-turn-shadow/), which means both arms always answer a prefix production really produced.

| `turns` | Mirrors | Use it to catch |
|---|---|---|
| `first` (default) | The opening request of a sampled session | Format, refusal, latency and cost regressions on fresh tasks ([ADR-0004](/halos/adr/0004-shadow-single-turn-only/)) |
| `all` | Every step of a sampled session | The above, plus: misreading terminal output, hallucinated tools, invalid arguments, giving up early, and drift deep into long sessions ([ADR-0014](/halos/adr/0014-step-level-multi-turn-shadow/)) |

`halo-shadow`:

- samples **per session**, so a sampled session is mirrored on every eligible step and an unsampled one on none,
- replays each step to both the control and the candidate route (non-streaming, with halo-shadow's own credentials; client credentials are never forwarded),
- **resolves both upstreams from its own copy of the compiled policy** (`-policy`, hot-reloaded). A mirror job names only an experiment and variant, so the shadow token cannot be used to point halo-shadow, or its per-upstream credentials, at an arbitrary URL,
- stores the pair, and executes nothing either arm returns.

`halo eval online` then reads each pair at two levels: an LLM judge with a pinned rubric, and a step-level reading that needs no judge (below).

<img class="diagram dark:sl-hidden" src="/halos/diagrams/shadow-sequence-light.svg" alt="The gateway forwards the request to the primary route, which answers the user. If the session is sampled and the step eligible (the first turn, or any step with turns: all), an async copy goes to halo-shadow, which replays it non-streaming against the candidate route, stores the pair and sends it to the judge in batches." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/shadow-sequence-dark.svg" alt="The gateway forwards the request to the primary route, which answers the user. If the session is sampled and the step eligible (the first turn, or any step with turns: all), an async copy goes to halo-shadow, which replays it non-streaming against the candidate route, stores the pair and sends it to the judge in batches." width="760" />

## Config

```yaml
apiVersion: halos.dev/v1
kind: Experiment
name: opus-5-5-shadow
type: shadow
axis: traffic
rings: [ring0-harness-team]
sampleRate: 0.05
turns: all            # every step of a sampled session; default: first
variants:
  - {name: control, weight: 1, control: true}
  - name: candidate
    weight: 1
    routes:
      opus: {upstream: orchestrator, model: us.anthropic.claude-opus-5-5-v1:0}
metrics:
  primary: {metric: halo.task.success, direction: increase}
stopping: {method: fixed, minSamples: 500, maxDays: 7, maxSpendUSD: 200}
```

`sampleRate` is the fraction (0-1) of sessions mirrored. `turns` picks which of their requests are eligible. With `turns: all`, cost grows with session length, because every step replays the whole prefix to two arms. Bound it with `maxSpendUSD`, halo-shadow's `-budget-usd`, and the proxy's mirror `maxBytes`. That last one defaults to 1 MiB: longer requests are not mirrored, so raise it to cover long sessions (halo-shadow accepts up to 8 MiB).

## Reading a multi-turn shadow

`halo eval online` reads every pair whose both sides answered. For each pair it extracts the arm's **action**: the multiset of tool calls with canonical arguments, or "ended its turn". It does this for Anthropic Messages, Bedrock (invoke and Converse), OpenAI Responses and Gemini. When the session's next step was mirrored too, that request contains the action **production actually took**. It is used as a reference only when its history extends this step's: subagent and compacted conversations share the session id but not the prefix, and are skipped.

| Reading | Meaning |
|---|---|
| Tool / argument agreement | Candidate's next action vs the control replay, on the same prefix |
| Fidelity (control) | Control replay vs production's real action: the **noise floor** (the same model, re-sampled) |
| Fidelity (candidate) | Candidate vs production's real action. Read it against the control's, never alone |
| Fidelity delta | Candidate minus control, paired by step, with a 95% CI. Below zero with the CI excluding zero = regression |
| Invalid-call rate | Steps calling a tool the request did not offer, or missing a required argument |
| Premature stop | Production kept working; the arm ended its turn |
| Divergence | Share of sessions where the candidate's action differed from the control's, and the mean first step it did |
| By depth | Tool agreement at steps 0, 1-4, 5-19 and 20+: catches models that degrade deep into long sessions |

```
EXPERIMENT       STEPS   SESS  TOOL AGREE        FIDELITY ctl       FIDELITY cand      INVALID / STOP ctl/cand  FIRST DIVERGENCE
opus-5-5-shadow   4120    212  81% (77..85)      88% (85..91)       86% (82..89)       0.2/0.9% 1/4%            64% of sessions, step 7.3
```

**Statistics.** Steps of one session are correlated, so a naive per-step interval would be falsely narrow. Every interval resamples **sessions** (a cluster bootstrap), and that includes the judge-score delta. Exported analysis samples are one per session and arm (`halo.eval.agent.fidelity`, `halo.eval.agent.invalid_call_rate`, unit = hashed session id). That keeps `halo exp analyze`'s per-unit tests valid, and raw session ids never leave the eval host. Both are registered metrics, so a shadow experiment can use them as guardrails:

```yaml
metrics:
  primary: {metric: halo.eval.agent.fidelity, direction: increase}
  guardrails:
    - {metric: halo.eval.agent.invalid_call_rate, direction: decrease, maxRegression: 0.10}
    - {metric: halo.eval.judge.score, direction: increase, maxRegression: 0.05}
```

A breach opens a pause or rollback PR. Shadow evidence never promotes: it measures decisions, not outcomes.

## Running halo-shadow

```bash
halo gateway compile --policy-dir policy-repo -o policy.json
halo-shadow -policy policy.json -listen 127.0.0.1:8090 -out pairs.jsonl \
  -pair-key-file pair.key -upstream-headers upstream-headers.yaml \
  -budget-usd 50 -retention 720h
```

| Flag | Default | Purpose |
|---|---|---|
| `-policy` | | Compiled policy snapshot; upstreams are resolved from it |
| `-listen` | `127.0.0.1:8090` | Loopback by default; put it behind your network policy |
| `-out` | `pairs.jsonl` | JSONL pair file, mode 0600 |
| `-pair-key-file` | | Base64 32-byte key: encrypt pairs at rest (AES-256-GCM) |
| `-upstream-headers` | | YAML/JSON `{upstreamName: {Header: value}}`; `${ENV}` expanded |
| `-budget-usd` | 50 | Stop accepting jobs at this *estimated* spend (each job reserves its worst case first) |
| `-price-in`, `-price-out` | 3, 15 | USD per million input and output tokens for the estimate |
| `-queue`, `-workers` | 64, 4 | Bounded queue (excess dropped) and replay workers |
| `-retention` | 720h | Prune pairs older than this (0 = keep forever) |

The auth token is read from the environment (`HALO_SHADOW_TOKEN`) and sent by the proxy as `X-Halo-Shadow-Token`; the proxy takes it from `--halo-shadow-token` or `HALO_PROXY_HALO_SHADOW_TOKEN`.

## Guarantees and non-guarantees

| | |
|---|---|
| Primary response and latency unaffected | Design goal: the mirror is async, bounded and dropped when the queue is full (`halo_proxy_shadow_dropped_total`). The effect on primary latency was **not measured**. |
| Candidate cost bounded | `sampleRate`, `maxSpendUSD` and halo-shadow's `-budget-usd` (an estimate from token prices, not a billing figure) |
| Prompts stored | Pairs contain prompts and responses. Encrypt at rest with `-pair-key-file`, set `-retention`, restrict the file. Treat as sensitive. |
| Client credentials | Never included in jobs; only `anthropic-version|beta` and `openai-beta` headers are forwarded |
| Tool calls | Never executed, on either arm. Pairs store responses only |
| Multi-turn quality | Measured per step, on the real prefix (`turns: all`). Whole-task success is not: use replay evals |

## Recommended recipe

1. **Shadow, `turns: all`.** Every step of real sessions, with fidelity vs the noise floor, invalid calls and premature stops. Zero user impact.
2. **Replay evals.** Whole tasks in a sandbox, where tools really run. Gates the candidate on outcomes.
3. **Canary.** Real sessions with gateway guardrails and auto-rollback. The only evidence that promotes.

Never promote on shadow alone.
