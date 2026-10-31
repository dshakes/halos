---
title: "ADR-0038: External key management and FIPS builds"
description: Release and kill-switch keys addressed by URI (file, AWS KMS, external signer), ECDSA P-256 verified next to ed25519 with the algorithm recorded and bound per signature, and FIPS 140-3 build variants on Go's frozen FIPS module with the crypto paths tested in fips140=only mode.
status: accepted
date: 2026-10-31
---

# ADR-0038: External key management and FIPS builds

- Status: accepted
- Date: 2026-10-31

## Context and problem statement

The release and ring-pointer signing key ([ADR-0005](/halos/adr/0005-signed-oci-bundles/), [ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/)) and the kill-list key ([ADR-0009](/halos/adr/0009-signed-kill-switch/)) are ed25519 PEM files. `halod` verifies ed25519 only; a KMS could hold only a cosign co-signature that `halod` ignores. There was no FIPS build.

Regulated buyers ask for two things this blocks:

- **Keys in a KMS or HSM.** The private half must never sit in a file on a CI runner or a server.
- **FIPS 140-3 validated cryptography** in the binaries they run.

## Decision drivers

- The key that `halod` verifies must be the one in the KMS or HSM, not a side signature.
- Keep ed25519 file keys working unchanged, and keep every release ever published verifiable (invariant 6: releases are immutable; nothing is re-signed).
- No new dependency: the AWS SDK core (credentials chain, SigV4) is already in `go.mod`, `service/kms` is not. No GCP, Azure, Vault or PKCS#11 SDKs.
- One algorithm per key, checked per signature: a label on the wire never chooses which key or algorithm verifies.
- FIPS without a fork: Go 1.24+ ships a FIPS 140-3 module selected at build time.

## Considered options

### Algorithms

1. **Ed25519 only, Ed25519 KMS keys.** AWS KMS offers `ECC_NIST_EDWARDS25519`, but not in every region and not on every HSM. Rejected as the only path.
2. **Add ECDSA P-256 / SHA-256 next to ed25519.** Chosen. Every KMS and HSM signs P-256; both are approved in FIPS 186-5 and inside Go's module.
3. **Add RSA and P-384 too.** More verification code and key types in `halod` for no requirement anyone has stated.

### KMS access

1. **Add `github.com/aws/aws-sdk-go-v2/service/kms`.** A new module (and its `go.sum` lines) needs approval.
2. **KMS JSON API over the SDK core already present.** Chosen: two operations, `GetPublicKey` and `Sign`, SigV4-signed with the SDK's signer and default credential chain, the same pattern as the Bedrock signer (`internal/gateway/upstreamauth`). Swapping in `service/kms` later changes one file.
3. **Only cosign's KMS support.** `halod` does not run cosign as root; rejected in ADR-0008.

### Other KMSs and HSMs

1. **Built-in backends per vendor.** One SDK each.
2. **An external-signer protocol.** Chosen: `exec://` runs an operator-supplied program with a JSON request on stdin (`halos.signer.v1`). PKCS#11, GCP, Azure and Vault adapters live outside Halos.

### FIPS

1. **BoringCrypto (`GOEXPERIMENT=boringcrypto`).** Needs cgo, Linux/amd64-and-arm64 only, and is superseded.
2. **Go's native module, `GOFIPS140=v1.0.0`.** Chosen: pure Go, every platform, frozen module source, `fips140=on` by default and `GODEBUG=fips140=only` to forbid everything else.

## Decision outcome

### Signers and key URIs

`bundle.KeySigner` is a `Signer` that knows its public key; only a `KeySigner` can be a release's primary signer. `internal/signer.Open` resolves a key URI:

| URI | Backend |
|---|---|
| `file://PATH`, `PATH` | PKCS#8 PEM, ed25519 or ECDSA P-256 (today's default) |
| `awskms://KEY?region=&fips=&endpoint=` | KMS `ECC_NIST_P256` (`ECDSA_SHA_256`, `MessageType=DIGEST`) or `ECC_NIST_EDWARDS25519` (`ED25519_SHA_512`, `RAW`) |
| `exec:///ABS/PATH?arg=&key=&timeout=` (Unix), `exec:///C:/path/to/signer.exe?...` (Windows, file-URI style) | `halos.signer.v1` external signer; a host component and UNC paths are refused |

Remote backends fetch the public key once, check that `KeyUsage` is `SIGN_VERIFY` and the key spec maps to a native algorithm, and **verify every signature they return** before Halos uses it. An alias is resolved to its key ARN once, and `Sign` names the ARN. KMS endpoints must be https on an AWS domain or loopback. `exec://` runs without a shell, inherits the environment (PINs go there, not in arguments), is bounded by a timeout and a 64 KiB output cap, and rejects unknown response fields and trailing output.

CLI: `--key-uri` on every signing command (`HALO_KEY_URI`), `--co-key-uri` for a second native key of the other algorithm during rotation, `halo keys public --key-uri` to export the public key and key id. `halo-server --killswitch-key-uri` for the kill list.

### Verification

- Algorithm names: `ed25519` and `ecdsa-p256-sha256` (ECDSA P-256 over SHA-256 of the message, ASN.1 DER).
- Release, pointer and attestation manifests already record the algorithm (`dev.halos.signature.type`); they now also record the signing key id (`dev.halos.signature.keyid`, informational). Kill envelopes gain `alg` and `keyId`; an envelope without `alg` is ed25519.
- `bundle.VerifyAs(v, alg, msg, sig)` refuses an algorithm the verifier does not accept (including an empty one) and tries only the verifier's keys of that algorithm. `bundle.Keyring` holds keys of both algorithms; each key is bound to one algorithm by its type, so an ed25519 key never checks an ECDSA signature or the reverse.
- A manifest is accepted when its primary signature, or a co-signature under `dev.halos.signature.<alg>`, verifies under its own algorithm with a trusted key.
- `halod` (`pubkey`, `pubkeys`, `revokedKeys`), `halo-proxy`, `halo-kong`, the portal, `halo export`, the MDM export and artifact signatures accept ECDSA P-256 public keys. Key ids: ed25519 is unchanged (SHA-256 of the raw key, so existing `revokedKeys` entries still match); ECDSA is SHA-256 of the PKIX DER.

### Rotation across algorithms

`MultiSigner{new, old}` co-signs releases, attestations and ring pointers with the old native key. A `halod` that predates this ADR reads the co-signature of its own algorithm first, so it keeps verifying while it still trusts only the old ed25519 key. A co-signer of the primary's algorithm is refused, because that older `halod` would read it instead of the primary.

### Randomized signatures

ECDSA signatures are randomized, so re-signing the same release would produce a new manifest and trip tag immutability. `publish` (and `Stage`) reuse a version tag only when its manifest is exactly what this publish would write apart from the signature bytes: same config and layer, the same annotation keys (a pre-ADR-0038 manifest without the key id also counts), a primary signature of the publisher's algorithm that its key verifies, and a verifying co-signature from every native co-signer the publish carries (a cosign co-signature must be present). Anything else, including a co-signer added or removed since, fails as immutable: a co-signature is never silently dropped.

### Kill-list signing cost

Gateways and devices poll the kill list every few seconds and the server signs per response. With a remote signer (`Remote()`), the signed envelope is reused for up to 30 seconds while the list is unchanged; a change is signed at once with `issuedAt` strictly after the cached one.

The remote signature runs detached from the poll (`context.WithoutCancel` plus its own 30-second timeout), is shared by concurrent polls for the same list, and the cache mutex is never held across it. At most one remote sign runs at a time: a poll for another list takes the single pending slot (replacing an older pending list, whose waiters are told it was superseded), signed when the running one ends, so a hanging signer costs one goroutine and one call however many lists change. If it fails, or the poll stops waiting, an unchanged list is answered from the cache while it is younger than 3 minutes (well under the pollers' 10-minute max age), counted in `halo_server_killswitch_stale_served_total` and logged; failures are counted in `halo_server_killswitch_sign_failures_total`. A changed list is never served from the cache: the poll gets an error.

Pollers accept a list with exactly the kills they hold and the same or an older `issuedAt` as a no-op (a cached envelope, or another replica a little behind; `version` is per replica and ignored here). An older list with different kills is still refused as a replay.

### FIPS builds

- `make build-fips` and goreleaser build every binary but `halo-kong` with `GOFIPS140=v1.0.0` into `*_fips_*` archives and `-fips` image tags (`deploy/docker/Dockerfile.service-fips`), alongside, never instead of, the standard artifacts.
- `make test-fips` (CI job `fips`) runs the signing, verification, TLS, session and encryption packages with `GODEBUG=fips140=only`, and a test fails the run if FIPS mode is not actually on.
- Shadow-pair sealing moved to `cipher.NewGCMWithRandomNonce`: `fips140=only` refuses a GCM nonce chosen outside the module. The row layout is unchanged. With pair keys configured, an unsealed row is refused when reading; `--allow-plaintext-pairs` (`halo eval`), `-allow-plaintext-pairs` (`halo-shadow decrypt-pairs`) or `allow_plaintext_pairs: true` (MCP `eval_harvest`) migrates a store sealed part way through, and each error names its own switch.
- HMAC keys: Go's module panics in `hmac.New` on a key under 112 bits. `internal/hmackey` checks every operator-supplied HMAC key at config load: the `halo-proxy` unit salt, the controller notification webhook secret, the SIEM webhook `hmacSecret` and the GitHub cloud-agent webhook secrets. In FIPS mode (`fips140=on` or `only`) a short key refuses to start, naming the setting; otherwise it logs a warning (existing deployments keep running). Tests switch the mode through `internal/hmackey/hmackeytest`, which a guard test keeps out of production code. Keys are never stretched. The GitHub webhook verifier skips such a key, and webhook signing and verification (`controller.SignChecked`, used by notifications and the SIEM webhook sink) return `ErrUnusableKey`, instead of panicking.
- KMS from a FIPS build defaults to the `kms-fips` endpoint unless `fips=false` is explicit. cosign co-signatures run in the external `cosign` program, outside Go's module.

## Threat model

| Threat | Control |
|---|---|
| Release key exfiltrated from CI | Key stays in KMS or the HSM; CI holds only `kms:Sign` on it, which can be revoked and is logged by CloudTrail |
| Algorithm confusion (relabel an ed25519 signature as ECDSA, or the reverse) | `VerifyAs` checks only keys of the recorded algorithm; each key has one algorithm |
| Unknown or downgraded algorithm label | Refused before any verification |
| KMS alias re-pointed to an attacker key mid-run | Signing pins the resolved key ARN; each signature is verified against the public key fetched at open |
| Buggy or malicious external signer returns a wrong signature | Halos verifies it against the signer's public key and fails the publish |
| SigV4-signed KMS request sent to a third party via `endpoint=` | Only KMS hosts (`kms[-fips].<region>.amazonaws.com[.cn]`, `kms[-fips].<region>.api.aws`, `vpce-*.kms.<region>.vpce.amazonaws.com`) of the SigV4 signing region, or loopback; no other AWS host (API Gateway, S3) |
| Secrets in an `exec://` URI leaked via `ps` | Documented: pass them in the environment, named with `env=` |
| Halos' own credentials (cloud keys, tokens) read by an external signer | The signer gets only `PATH`, `HOME`, `HALOS_SIGNER_*` and `env=` names |
| A PIN or key handle in a signer's stderr reaching logs, CI output or error reports | stderr is never put in an error; it is logged at debug level, truncated |
| A hung signer's helper keeping an HSM session open | On timeout its process group is killed (Unix) |
| A replaced signer binary signing releases | Before every run: binary, symlink target and every ancestor directory owned by root or the current user and not group- or world-writable (sticky directories allowed); optional `sha256=` pin. A swap between check and exec remains possible (documented) |
| A helper the signer backgrounds outliving it | Its process group is killed after every exit (Unix) |
| A helper resolved from the inherited working directory or a relative `PATH` entry | The signer runs in `/` with absolute `PATH` entries only |
| A slow or hanging KMS growing goroutines and calls | One sign in flight, one pending (newest list) |
| A KMS endpoint host that folds to an allowed name (Unicode) | Non-ASCII hosts refused before lower-casing |
| `halo keys public` exporting a key the attacker controls (trust on first use) | Documented: compare the key id with the one recorded at key creation; the fleet pins installed public keys and never fetches them |
| Kill-list cache serves a stale kill state | Any change is signed at once; the cached envelope is at most 30 s old while the signer is healthy, far below pollers' 10-minute max age |
| **KMS outage delays propagation of new kills** | Accepted risk with a remote kill key: an unchanged list keeps being served for up to 3 minutes, but a new kill or unkill cannot be signed until KMS recovers (the endpoint answers 500; gateways keep their last list). The guide recommends a local kill key; the kill key cannot sign releases |
| Republish silently drops a newly added co-signature | The existing manifest is reused only when it carries exactly the signatures this publish writes; otherwise immutable |
| HMAC key Go's module refuses crashes a goroutine at runtime | Checked at config load; FIPS mode refuses to start |
| Plaintext rows injected into a sealed shadow store | Refused when pair keys are configured unless `--allow-plaintext-pairs` |
| Replay of an older kill list | Strictly-newer `issuedAt` required for any change; an older list with the same kills is a no-op |

## Consequences

- Positive: the root of trust can live in KMS or an HSM; FIPS deployments have artifacts to run; old releases, old `halod`s (with co-signing) and old `revokedKeys` entries keep working.
- Negative: ECDSA public keys need an upgraded `halod`; operators must upgrade `halod` before adding one. A FIPS deployment with an HMAC secret or salt under 14 bytes no longer starts until it is lengthened. A remote kill key makes new kills depend on KMS availability. A store with unsealed shadow rows written before sealing needs `--allow-plaintext-pairs` once keys are configured.
- The workload-credential key (`--workload-key-file`) has no KMS backend yet.
- The KMS client is hand-written against the KMS JSON API; adopting `service/kms` would need dependency approval.

## Implementation status (2026-10-31)

Implemented: `internal/bundle/keys.go` (algorithms, `Keyring`, `VerifyAs`, parsing, key ids), `internal/bundle/pointer.go` (`verifyManifest`, `signAnnotations`), `internal/bundle/bundle.go` (`alreadyPublished`), `internal/signer` (file, awskms, exec), `internal/gateway/killswitch.go`, `internal/server/killswitch.go` (`killSigCache`), `cmd/halo` (`--key-uri`, `--co-key-uri`, `halo keys public`), `cmd/halod/keys.go`, `internal/hmackey`, the FIPS Makefile targets, CI job, goreleaser and Dockerfile. Tested against a fake KMS (`httptest`, SigV4 checked) and fake external signers (the test binary and a shell script); not against a live AWS account or a hardware HSM.
