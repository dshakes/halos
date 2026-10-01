# evals

Offline replay tasks and suites for `halo eval`. Layout:

- `tasks/<name>/task.yaml` plus a small fixture repo (`repo/`).
- `suites/*.yaml`: tasks and the variants (harness + version + model + optional
  settings file) to compare.

Task fields: `id`, `repo` (git URL or dir relative to the task), `setup`
(shell commands), `prompt`, `check` (shell, exit 0 = pass), `timeout`,
`budget_usd`, `max_turns`, `tags`.

Rough Harbor mapping: `prompt` = `instruction.md`, `check` = `tests/test.sh`,
`repo`+`setup` = the `environment/` Dockerfile, `timeout` = agent timeout.
Harbor's reward-file scoring is not read; only the exit code counts.

Runs use container images `ghcr.io/dshakes/eval-<harness>:<version>`
(with `go` installed for these tasks); override with `DockerRunner.Image`.
