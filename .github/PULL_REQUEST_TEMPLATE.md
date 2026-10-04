## What and why

<!-- One paragraph. Link the issue or ADR. -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Harness adapter change
- [ ] Docs / ADR
- [ ] Breaking change to policy schema (requires ADR)

## Checklist

- [ ] `gofmt -l .` empty; `go build ./... && go vet ./... && go test -race ./...` pass (or N/A)
- [ ] `cd docs && npm run build` passes and new pages are in the sidebar (docs changes)
- [ ] Golden / e2e tests added or updated (adapters, traffic plane)
- [ ] Docs and `CHANGELOG.md` updated
- [ ] Any claim about a harness's behavior cites a source or is marked unverified
- [ ] No new trust boundary or relaxed guardrail (or an ADR is linked)
- [ ] Commits signed off (`git commit -s`)

## How I verified

<!-- Paste the commands you ran and their output. Label anything you could not run UNVERIFIED and say why. -->
