.PHONY: build test lint vuln docs compose-up e2e obs-e2e smoke
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	mkdir -p bin
	for c in halo halod halo-shadow halo-server halo-proxy halo-kong; do go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$$c ./cmd/$$c; done

test:
	go test -race ./...

lint:
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

docs:
	cd docs && npm ci && npm run build

compose-up:
	docker compose -f deploy/compose/docker-compose.yml up --build

# Cross-component e2e (test/e2e): real binaries + registry:2 (Docker) + mock IdP/LLMs.
e2e:
	./scripts/e2e.sh

# Evidence plane (collector -> ClickHouse -> analyze/Grafana) with synthetic telemetry (Docker + network).
obs-e2e:
	./scripts/obs-e2e.sh

# Real Claude Code in a Debian container via halod's verified install (Docker + network).
smoke:
	./scripts/smoke-claude.sh

# Packaging checks (local only, never pushes). See scripts/package-check.sh.
# goreleaser snapshot: archives, checksums, SBOMs (if syft is installed), images.
snapshot:
	./scripts/package-check.sh snapshot

# Snapshot images + eval images smoke-tested against Docker (incl. a stub-CLI eval run).
images:
	./scripts/package-check.sh snapshot images

# Dev Container Feature end to end (local TLS registry, signed release, firewall).
feature-test:
	./scripts/package-check.sh feature
