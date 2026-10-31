---
title: FIPS 140-3 builds
description: The _fips archives and -fips images built on the Go Cryptographic Module, which algorithms Halos uses inside it, how to run in fips140=only mode, and what is not claimed.
---

Regulated deployments need validated cryptography and keys outside the application. Keys are covered in [signing keys in a KMS or HSM](/halos/guides/key-management/); this page covers the cryptographic module ([ADR-0038](/halos/adr/0038-external-key-management-and-fips-builds/)).

## What ships

| Artifact | Standard | FIPS |
|---|---|---|
| Archives | `halod_<version>_<os>_<arch>.tar.gz` | `halod_fips_<version>_<os>_<arch>.tar.gz` (also `halo`, `halo-server`, `halo-proxy`, `halo-shadow`) |
| Images | `ghcr.io/dshakes/halo-server:<version>` | `ghcr.io/dshakes/halo-server:<version>-fips`, `latest-fips` (also `halo-proxy`, `halo-shadow`) |
| From source | `make build` | `make build-fips` (into `bin/fips/`) |

The FIPS artifacts are the same code built with `GOFIPS140=v1.0.0`: Go's frozen FIPS 140-3 module, **Go Cryptographic Module v1.0.0**, the version the Go team submitted for CMVP validation. Check the [CMVP listing](https://csrc.nist.gov/projects/cryptographic-module-validation-program) for its current certificate status and operational environments. They are signed, checksummed and attested like the standard artifacts. `halo-kong` has no FIPS variant: it runs inside the Kong container, whose own cryptography is Kong's.

Check a binary:

```bash
go version -m halod | grep GOFIPS140      # build GOFIPS140=v1.0.0-c2097c7c
```

## Modes

A FIPS build runs the module's power-on self-tests and defaults to `GODEBUG=fips140=on`: Go's crypto packages use the module, and approved algorithms are used where Halos has a choice. The `-fips` images set `GODEBUG=fips140=on` explicitly.

`GODEBUG=fips140=only` additionally makes every non-approved algorithm, key size or mode fail with an error or panic. Use it where policy requires that nothing outside the boundary can run. Halos' CI runs the signing, verification, TLS, session and encryption packages in this mode (`make test-fips`, the `fips` job): `internal/bundle`, `internal/signer`, `internal/gateway` (kill switch), `internal/gateway/upstreamauth` (SigV4), `internal/server` (sessions, cookies, JWTs, webhooks), `internal/identity`, `internal/a2a`, `internal/supplychain`, `internal/release`, `internal/shadow`, `internal/hmackey`, `internal/telemetry` (gateway metrics), `internal/controller` (notifications), `internal/cloudagents` (GitHub webhooks), `internal/ledger`, `halo`, `halod`, `halo-server`, `halo-kong`, `halo-shadow` and `halo-proxy`. A test asserts the run really is in FIPS mode.

## Algorithms

Everything Halos uses is inside the module and approved:

| Purpose | Algorithm | Standard |
|---|---|---|
| Release, pointer, attestation and kill-list signatures | Ed25519, or ECDSA P-256 with SHA-256 | FIPS 186-5 |
| Workload and agent credentials | Ed25519 (EdDSA JWTs) | FIPS 186-5 |
| Inbound IdP and CI tokens | RS256 (RSA 2048+), ES256, EdDSA | FIPS 186-5 |
| Digests, content addresses, audit chain | SHA-256 | FIPS 180-4 |
| Session cookie, webhooks, pseudonyms, SigV4 | HMAC-SHA256 | FIPS 198-1 |
| Shadow pairs at rest | AES-256-GCM, 96-bit nonce generated inside the module | SP 800-38D |
| TLS (SIEM syslog, AgentCards, all outbound HTTPS) | `crypto/tls`, restricted by the module to approved versions, suites and curves | SP 800-52 |

Ed25519 became approved in FIPS 186-5; it is inside the Go module, so file and KMS Ed25519 keys work in `fips140=only`. Halos imports no MD5, SHA-1, DES or RC4 and no `golang.org/x/crypto`.

**Outside the module:** an optional cosign co-signature (`--cosign-key`, `--cosign-keyless`) is made by the external `cosign` program, with its own cryptography, not Go's FIPS module in Halos. `halod` never verifies it. Leave cosign off where everything must run inside a validated module. External signers (`exec://`) and AWS KMS sign with their own modules (KMS uses FIPS 140-3 validated HSMs; a FIPS build calls the `kms-fips` endpoint by default). Your HSM's or adapter's validation is yours to check.

Shadow pairs used to be sealed with a nonce chosen outside the AEAD, which `fips140=only` refuses. They are now sealed with `cipher.NewGCMWithRandomNonce`; the row format (`nonce || ciphertext || tag`) did not change, so existing rows still decrypt.

## Operator requirements in fips140=only

The module refuses HMAC keys shorter than 112 bits (14 bytes) by panicking inside `hmac.New`. Halos checks every operator-supplied HMAC key when it loads its config. In FIPS mode (`crypto/fips140.Enabled()`, which is true in every FIPS build) a shorter key **refuses to start**, naming the setting; outside FIPS mode it only logs a warning, so existing deployments keep running. Keys are never stretched or hashed: receivers such as GitHub compute the HMAC with the raw secret.

| Key | Setting named in the error |
|---|---|
| `halo-proxy` telemetry unit salt | `telemetry.unitSalt (--telemetry-unit-salt-file)` |
| Controller notification webhook secret | `--notify-webhook-secret-file` |
| SIEM `webhook` sink secret | `--audit-config sinks[<name>].hmacSecret` |
| GitHub cloud-agent webhook secrets | `--cloud-webhook-secret-file` (also required to be 16 characters in every mode) |

Use 32 random bytes (`openssl rand -hex 32`). The session-ledger salt is already required to be 16 bytes and the session key 32 bytes; AWS secret access keys are 40 characters, so SigV4 is unaffected. The GitHub webhook handler also skips, rather than panics on, a secret that is too short in FIPS mode.

The module also refuses RSA keys under 2048 bits, so an IdP or CI issuer that signs with a smaller key fails verification in this mode (AgentCard keys under 2048 bits are already skipped in every mode).

## What is not claimed

- Halos holds no FIPS 140-3 certificate. The FIPS builds use a module; whether that satisfies your program depends on the module's certificate, its operational environments and your assessor.
- The standard archives and images make no FIPS claim.
- `fips140=only` is tested on the packages above, not the whole tree.
- cosign co-signatures, external signers and KMS are outside Halos' module (above).
- TLS for `halo-server`, `halo-proxy` and `halo-shadow` is terminated in front of them; that terminator's module is yours to choose.
