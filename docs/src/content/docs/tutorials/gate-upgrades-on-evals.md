---
title: Gate upgrades on evals
description: Run an eval suite on a control and a candidate, see the SHIP or BLOCK verdict, fail a pipeline on it, and watch for upstream upgrades.
---

An upgrade ships only if the candidate is not worse than what you run today. `halo eval run` replays tasks against a control and a candidate and prints a scorecard with a verdict: **SHIP**, **HOLD** or **BLOCK**. You will run it on your machine with a stand-in `claude`, fail on a regression, and run the upgrade watcher in dry-run.

**What was and was not run.** A real suite runs each trial in Docker with a pinned harness image (`evals/images/`) and calls a real model, which needs API credentials and a built image. This tutorial uses `--local`, which runs on the host with no isolation (testing only), and a shell script as `claude`, so the numbers prove the gate logic, not any model's quality. The Docker path was **not run** here; `scripts/package-check.sh` exercises it.

**Prerequisites:** a built `halo`, Go on `PATH` (the tasks run `go test`), and `REPO=/path/to/halos`.

## 1. Set up a suite and a stand-in CLI

```console
$ mkdir evals-try && cd evals-try && mkdir suites bin
$ ln -s $REPO/evals/tasks tasks && ln -s $REPO/evals/rubrics rubrics
$ cat > bin/claude <<'SH'
#!/bin/sh
# fixes the off-by-one in fix-failing-go-test, unless the model is "opus-bad"
case "$*" in *opus-bad*) ;; *) [ -f mean.go ] && sed 's|len(xs)-1)|len(xs))|' mean.go > /tmp/m.$$ && cat /tmp/m.$$ > mean.go;; esac
echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.001,"usage":{"input_tokens":1,"output_tokens":1}}'
SH
$ chmod +x bin/claude && export PATH="$PWD/bin:$PATH"
$ cat > suites/same.yaml <<'YAML'
name: same
tasks: [fix-failing-go-test]
control: current
repeats: 3
variants:
  - {name: current, harness: claude, version: "2.1.280", model: sonnet}
  - {name: candidate, harness: claude, version: "2.1.300", model: sonnet}
YAML
```

## 2. Run the gate: a candidate that is not worse

```console
$ halo eval run suites/same.yaml --local
# Eval scorecard: same

Control: `current`

**Gate: SHIP**

| Variant | Trials | pass@1 (95% CI) | pass@3 | pass^3 | Cost/task | … |
|---|---|---|---|---|---|---|
| current | 3 | 100.0% (100.0-100.0) | 100.0% | 100.0% | $0.0010 | … |
| candidate | 3 | 100.0% (100.0-100.0) | 100.0% | 100.0% | $0.0010 | … |

## Paired comparison vs control
…
## candidate vs current: SHIP

- non-inferior on 1 tasks: pass rate +0.0 pp (95% CI +0.0 to +0.0)
…
```

Trials run in temp directories on the host; each one runs the task's `go test ./...` check. The comparison is paired per task, with bootstrap confidence intervals.

## 3. Run it with a regression, and fail the pipeline

Copy `suites/same.yaml` to `suites/regress.yaml`, change its name to `regress`, and set the candidate's model to `opus-bad`. Then:

```console
$ halo eval run suites/regress.yaml --local --fail-on block --scorecard regress.json --report regress.md
# Eval scorecard: regress
…
**Gate: BLOCK**
…
| candidate | 3 | 0.0% (0.0-0.0) | 0.0% | 0.0% | $0.0010 | … |
…
## candidate vs current: BLOCK

- pass rate significantly worse: -100.0 pp (95% CI -100.0 to -100.0)
- 1 tasks regressed (max 0)
…
Regressed tasks:

- `fix-failing-go-test`: 100% -> 0%
error: eval gate: block
$ echo $?
3
```

`--fail-on block` (or `hold`) exits 3 when the verdict is at least that severe, so CI can stop an upgrade. `--scorecard` writes JSON and `--report` writes the Markdown for a PR comment. With the default `--fail-on none` the command exits 0 and you read the verdict yourself.

## 4. Watch for upstream upgrades

`halo upgrade check` finds new CLI versions and models, verifies their artifacts, runs this gate and opens a PR on SHIP or HOLD. `--dry-run` only reports. This points it at a stub npm registry that answers with a newer version:

```console
$ cat > npmstub.py <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.lstrip('/').replace('%2f','/').replace('%2F','/').removesuffix('/latest')
        body = json.dumps({"name": name, "version": "2.1.330" if "claude" in name else "0.101.0"}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.send_header('content-length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',8765),H).serve_forever()
PY
$ python3 npmstub.py &
$ cp -r $REPO/examples/acme-corp policy && cd policy
$ printf 'profile: engineering-next\nsuite: ../../evals/suites/upgrade-gate.yaml\nharnesses: [claude-code, codex]\n' > ../stub-upgrade.yaml
$ halo upgrade check --dry-run --config ../stub-upgrade.yaml --npm-registry http://127.0.0.1:8765
KIND   TARGET                  FROM            TO              ARTIFACTS   GATE   PR / NOTE
cli    claude-code             2.1.312         2.1.330         UNVERIFIED  -      artifacts not verified: release: resolve claude-code@2.1.330 artifacts: GET https://downloads.claude.ai/claude-code-releases/2.1.330/manifest.json: status 404
cli    codex                   0.100.0         0.101.0         UNVERIFIED  -      artifacts not verified: release: resolve codex@0.101.0 artifacts: npm returned @openai/codex/0.101.0@0.101.0, want @openai/codex@0.101.0
```

Both candidates are found from the pins in `engineering-next`. They show `UNVERIFIED` because the stub serves no real artifacts and `2.1.330` does not exist on the vendor's download host. A version with no verified artifacts is reported but never pinned, because `halod` would refuse those bytes. Stop the stub with `kill %1`.

## What just happened

- The gate compared each candidate to the control on the same tasks, with CIs, and returned a verdict from the thresholds in the suite's `gate:` block (defaults here): a significant pass-rate drop or a regressed task blocks.
- `--fail-on` turned the verdict into an exit code a pipeline can act on.
- `upgrade check --dry-run` discovered candidates and refused to pin unverified bytes. Without `--dry-run`, a SHIP or HOLD candidate gets a PR; BLOCK opens nothing. Nothing is ever merged for you.
- **Not covered:** Docker-isolated trials, the judge grader (`upgrade-gate.yaml` needs a gateway and `HALO_EVAL_GATEWAY_TOKEN`), and a real PR.

## Next

- [Evals](/halos/concepts/evals/): verdict rules, flaky tasks and graders
- [Reliable upgrades](/halos/guides/reliable-upgrades/) and [Writing evals](/halos/guides/writing-evals/)
- [Roll out a Claude Code upgrade safely](/halos/tutorials/claude-code-upgrade/)
