# Fleet load generator

Simulates N `halod` devices against a real `halo-server` and reports per-endpoint latency percentiles, error rates and the server's CPU and RSS. It complements `test/load` (the `halo-proxy` data plane) with the control plane: what a 10k-developer fleet costs a `halo-server` replica.

```
make load-fleet                                         # 1000, 5000, 10000 devices; file mode, then Postgres via Docker
LOAD_FLEET_SCENARIOS="1000x1" LOAD_FLEET_MODES=file make load-fleet
```

`scripts/load-fleet.sh` builds the binaries, starts a fresh `halo-server` per scenario (with `--dev-insecure-user`, a laptop portal config, a kill-switch key and `--metrics-listen`), runs the generator and writes `load-fleet-out/summary.md` plus `<mode>-<devices>x<scale>/report.{md,json}`. The generator builds only with `-tags loadfleet`, so `go test ./...` never runs it.

## What a simulated device does

Each device follows `cmd/halod`'s loop (`loop`, `Once`, `PollKill`):

1. Enrolls once: `POST /api/v1/launch/laptop` (a single-use token, as the dev user) then `POST /api/v1/enroll`, and parses `deviceToken` from the returned `halod.yaml`. Devices arrive uniformly over `-ramp`, a morning rush.
2. Runs a cycle at start and every `-interval` (15m, halod's default): the signed kill list (`gateway.KillSwitch.Refresh`, the code halod runs, so the Ed25519 verification is real), `GET /api/v1/fleet/ring?user=&host=`, and `POST /api/v1/fleet/report` with a `server.Report` body.
3. Polls the kill list every `-kill-interval` (1m, halod's default) in between.

`-operators N` adds console users polling `GET /api/v1/fleet` and `/api/v1/devices` every `-operator-interval`. `-scale S` divides both intervals by S: `x10` offers ten times the real request rate from the same device count, to find the headroom.

## Not simulated

- The OCI registry pull (`bundle.PullRing`) of a real cycle. It never touches `halo-server`; size the registry separately.
- Distinct users: `--dev-insecure-user` makes every enrollment the same user, so ring resolution is the same lookup for all. Hosts and device ids are distinct, which is what the fleet table and device store key on.
- One process per device: by default devices share one connection pool (HTTP keep-alive, like halod's kill poll every minute). `-conn-per-device` gives each its own pool; it needs about two file descriptors per device on each side (`ulimit -n`).
- Halod has no jitter; devices drift apart through enrollment time and network. `-jitter` (5%) adds a little more. A synchronized restart herd is `-ramp 1s`.

## Reading a report

Two phases: *ramp* (enrollment) and *steady state*. Latencies are client-side, from request start to response headers, in 5% histogram buckets (quantiles are bucket upper bounds). The *halo-server process* table samples `ps` every 2s (CPU is percent of one core; `ps` cputime has coarse resolution, so short runs read low). The *server-side* table is halo-server's own `/metrics` mean per route. A run fails when any steady-state endpoint's error rate exceeds 0.1% or an enrollment fails.

On a shared or loaded machine the generator competes with the server for CPU: read the load average printed with each run, compare runs with each other, and prefer a dedicated host (the `load-fleet` workflow) for numbers you quote.
