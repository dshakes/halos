# UAT-only images for `make uat-k8s` (never published). The context is a staging
# dir holding prebuilt linux binaries (scripts/uat-k8s.sh). The product images
# (halo-server/proxy/shadow) are built from deploy/docker/Dockerfile.service.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS infra
RUN apk add --no-cache curl git git-daemon busybox-extras ca-certificates
COPY bin/uatidp bin/mockllm bin/halod bin/halo /usr/local/bin/
# halod download served to the enroll script (busybox httpd -h /srv).
COPY bin/halod /srv/dl/halod-linux-arm64
COPY bin/halod /srv/dl/halod-linux-amd64

# halo-server plus git and a recording `gh` for controller PRs against the
# in-cluster git remote (the chart's controller.policyRepo.image contract).
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS server-git
RUN apk add --no-cache git
COPY bin/halo-server /usr/local/bin/halo-server
COPY gh /usr/local/bin/gh
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/halo-server"]
