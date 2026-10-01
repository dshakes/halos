## What and why

<!-- One paragraph. Link the issue or ADR. -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Harness adapter change
- [ ] Docs / ADR
- [ ] Breaking change to policy schema (requires ADR)

## Checklist

- [ ] `go build ./... && go test ./... -race` pass (or N/A)
- [ ] Golden / e2e tests added or updated (adapters, traffic plane)
- [ ] Docs and `CHANGELOG.md` updated
- [ ] Any claim about a harness's behavior cites a source or is marked unverified
- [ ] No new trust boundary or relaxed guardrail (or an ADR is linked)
- [ ] Commits signed off (`git commit -s`)

## How I verified

<!-- Paste command output. Say what you could not run. -->
