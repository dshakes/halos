# Test-only image: the eval-claude image with `claude` replaced by a stub, to
# exercise DockerRunner (setup -> agent -> check in fresh containers) without API keys.
# Build: docker build -t ghcr.io/halos-dev/eval-claude:fake evals/images/fake
ARG BASE=ghcr.io/halos-dev/eval-claude:2.1.280
FROM ${BASE}
USER root
COPY --chmod=0755 claude-stub /usr/local/bin/claude
USER eval
