# Eval image for the codex harness: ghcr.io/dshakes/eval-codex:<CLI version>.
# Build: docker build --build-arg CLI_VERSION=0.58.0 -t ghcr.io/dshakes/eval-codex:0.58.0 evals/images/codex
# Bases are pinned by digest; bump tag and digest together.
FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS go

FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
ARG CLI_VERSION=0.58.0
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && apt-get clean && find /var/lib/apt/lists -type f -delete \
 && npm install -g --ignore-scripts "@openai/codex@${CLI_VERSION}" && npm cache clean --force
COPY --from=go /usr/local/go /usr/local/go
# DockerRunner runs as 1000:1000 (the image's default node user is replaced) with
# -w /work; /work must exist and be owned by that user for docker cp.
RUN userdel -r node && useradd -m -u 1000 -s /bin/bash eval \
 && install -d -o eval -g eval /work
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local HOME=/home/eval
USER eval
WORKDIR /work
