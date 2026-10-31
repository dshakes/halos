---
title: Signing keys in a KMS or HSM
description: Keep the release and kill-switch signing keys in AWS KMS or an HSM with key URIs (file://, awskms://, exec://), export their public keys for halod, and rotate between keys and algorithms without a flag day.
---

The release signing key is the root of trust for the fleet: whoever holds it can ship a hook to every developer. Since [ADR-0038](/halos/adr/0038-external-key-management-and-fips-builds/) the private key can stay in AWS KMS or an HSM, and `halod` verifies either of two algorithms:

| Algorithm | Recorded as | Key sources |
|---|---|---|
| Ed25519 (RFC 8032), over the message | `ed25519` | `halo keys generate`, AWS KMS `ECC_NIST_EDWARDS25519`, an HSM |
| ECDSA P-256 over SHA-256, ASN.1 DER | `ecdsa-p256-sha256` | AWS KMS `ECC_NIST_P256`, most HSMs, a PKCS#8 file |

Every release, ring pointer and attestation manifest records the algorithm (`dev.halos.signature.type`) and the key id (`dev.halos.signature.keyid`). `halod` checks a signature only under the algorithm it records and only with its configured keys of that algorithm; any other algorithm name is refused. The key id is for audit and rotation: verification never trusts it to pick a key. Releases signed before ADR-0038 are ed25519 and keep verifying.

## Key URIs

Signing commands take `--key PATH` (a PEM file, as before) or `--key-uri URI` (`HALO_KEY_URI` in CI). `halo-server` takes `--killswitch-key-file` or `--killswitch-key-uri` for the kill list.

| URI | Backend |
|---|---|
| `file://PATH` or `PATH` | PKCS#8 PEM private key, ed25519 or ECDSA P-256 |
| `awskms://KEY[?region=R&fips=true&endpoint=URL]` | AWS KMS. `KEY` is a key id, key ARN, multi-Region key id, `alias/NAME` or alias ARN |
| `exec:///ABS/PATH[?arg=A&arg=B&env=NAME&key=ID&timeout=30s]` | An external signer program ([protocol](#external-signers)) |

Remote backends fetch the public key once when they open, and Halos verifies every signature they return against it before using it. A KMS or HSM that signs with the wrong key, algorithm or encoding fails at signing time, not on the fleet.

Export the public key for `halod` (`pubkey`, `pubkeys`), `halo-proxy` / `halo-kong` / `halod` kill-switch config, the portal and `--pubkey`:

```bash
halo keys public --key-uri awskms://alias/halos-release?region=us-east-1 --out release.pub
# algorithm ecdsa-p256-sha256, key id sha256:3f1c...
```

The key id it prints is what `halod` logs at startup and what `revokedKeys` takes.

**This is trust on first use.** `halo keys public` believes whatever the KMS or signer program answers at that moment: it proves which key the backend holds now, not that it is the key you meant. Compare the key id with the one recorded when the key was created (`aws kms get-public-key`, your HSM's inventory) before distributing it. The fleet never fetches keys: `halod`, the gateways and the portal pin the public keys you install in their config, so a backend that later answers with another key cannot make devices trust it; its signatures simply fail.

## AWS KMS

1. Create an asymmetric key with usage **Sign and verify** and key spec `ECC_NIST_P256` (available in every commercial and GovCloud region) or `ECC_NIST_EDWARDS25519` (Ed25519; check that your region offers it). Any other key spec is refused.
2. Grant the publishing role only `kms:GetPublicKey` and `kms:Sign` on that key. Nothing else in Halos calls KMS.

   ```json
   {"Effect": "Allow", "Action": ["kms:GetPublicKey", "kms:Sign"],
    "Resource": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}
   ```

3. Credentials come from the AWS SDK default chain: environment, shared config and SSO, web identity (IRSA, GitHub OIDC), ECS or EC2 instance roles. The region comes from `?region=`, the key ARN, or `AWS_REGION`.
4. `fips=true` sends requests to `kms-fips.<region>.amazonaws.com`. A FIPS build (`_fips` archive, `-fips` image) does so by default; pass `fips=false` to use the standard endpoint. `endpoint=` points at another KMS endpoint, for example a VPC endpoint. It must be `https` to a KMS host of the signing region: `kms[-fips].<region>.amazonaws.com[.cn]`, `kms[-fips].<region>.api.aws` or `vpce-*.kms.<region>.vpce.amazonaws.com`, with no path, query or user info (loopback is accepted for tests). Any other AWS host, such as an API Gateway or S3 endpoint, could belong to someone else and is refused, so SigV4-signed requests never reach a third party.

An alias is resolved to its key ARN when the signer opens, and every `Sign` names that ARN: re-pointing the alias does not switch the key behind a running publish.

`halo-server` signs the kill list on gateway and device polls. With a KMS or external key it re-uses a signed list for up to 30 seconds while the list is unchanged; a kill or unkill is signed at once. The remote signature runs detached from the poll that asked for it, with its own 30-second timeout, so a slow KMS call is not abandoned when a poller gives up; the next poll gets its result.

**A kill key in KMS makes new kills depend on KMS.** During a KMS outage `halo-server` keeps serving the last signed list while it is unchanged, for up to 3 minutes (well under the pollers' 10-minute limit), and counts this in `halo_server_killswitch_stale_served_total` (failures: `halo_server_killswitch_sign_failures_total`). A kill or unkill made during the outage cannot be signed: the endpoint answers 500 instead of presenting the old list as current, and gateways keep their last accepted list until KMS recovers. The kill switch is the emergency path, so **we recommend a local kill key** (`--killswitch-key-file`, a file in a Kubernetes secret) and KMS for the release key; the kill key cannot sign a release.

Halos talks to KMS through its JSON API with the AWS SDK's credential chain and SigV4 signer, which are already dependencies; it does not link `service/kms`.

## External signers

`exec://` runs a program you provide, once per operation, with no shell. Halos writes one JSON request to its stdin, closes it, and reads one JSON response from stdout. Exit 0 with no `error` field is success.

- **Environment:** only `PATH`, `HOME`, every `HALOS_SIGNER_*` variable, and the variables named with `env=` (repeatable, for example `env=PKCS11_PIN`). Nothing else from Halos' environment (cloud credentials, `HALO_TOKEN`) reaches the program. Pass PINs and tokens this way, never in the URI: arguments show in `ps`.
- **stderr** is logged at debug level, truncated to 512 bytes, and never appears in an error message (it may carry a PIN or a key handle).
- **Timeout:** 30 seconds by default (`timeout=` up to 10m). On timeout or cancellation the program's whole process group is killed (Unix), so a helper it spawned cannot keep the key session open. On Windows only the program itself is killed.
- **The binary** (and, for a symlink, its target) must be owned by root or the user running Halos and must not be group- or world-writable; otherwise it is refused before it runs. On Windows this check does not apply: install the signer where only administrators can write.
- Output is capped at 64 KiB.

Protocol `halos.signer.v1`:

```text
-> {"protocol":"halos.signer.v1","op":"public","keyId":"<key= param>"}
<- {"protocol":"halos.signer.v1","algorithm":"ecdsa-p256-sha256","publicKey":"-----BEGIN PUBLIC KEY-----\n..."}

-> {"protocol":"halos.signer.v1","op":"sign","keyId":"...","algorithm":"ecdsa-p256-sha256",
    "message":"<base64 of the bytes to sign>","sha256":"<base64 SHA-256 of message>"}
<- {"protocol":"halos.signer.v1","signature":"<base64>"}

<- {"protocol":"halos.signer.v1","error":"token not present"}      (any op)
```

- `algorithm` is `ed25519` or `ecdsa-p256-sha256`; `publicKey` is a PKIX PEM of that type.
- `ed25519` signs `message` itself (pure Ed25519). `ecdsa-p256-sha256` signs the `sha256` digest and returns **ASN.1 DER**, not raw `r||s`.
- Messages are short (a digest string or a domain-separated statement, under 200 bytes).
- Unknown response fields and trailing output are errors.

This is how a PKCS#11 HSM (`pkcs11-tool --sign --mechanism ECDSA`), GCP Cloud KMS (`gcloud kms asymmetric-sign`), Azure Key Vault (`az keyvault key sign`) or Vault transit plugs in without Halos taking their SDKs. Adapters are yours to write and test; Halos ships none.

## Rotation

`halod` accepts a release signed by any key in `pubkey` plus `pubkeys`, so rotation overlaps old and new keys. The same steps move a fleet from a file key to a KMS key, between KMS keys, or from ed25519 to ECDSA:

1. Create the new key and export it: `halo keys public --key-uri awskms://... --out release-new.pub`.
2. Add it to `pubkeys` in every `halod.yaml` (MDM, dev container rebuild, portal enrollment) next to the old one. ECDSA public keys need `halod` from a release that includes ADR-0038; upgrade `halod` first.
3. Publish every ring with the new key: `halo release publish ... --key-uri awskms://...`. When the new key uses the other algorithm, add `--co-key-uri <old key>` during the overlap: the old key co-signs the release, its attestations and the ring pointer, so devices that trust only the old key, including a `halod` older than ADR-0038, keep verifying. A co-signing key of the same algorithm is refused (old `halod`s read one signature per algorithm); for a same-algorithm rotation, finish step 2 first.
4. Stop passing `--co-key-uri`, remove the old key from `pubkey`/`pubkeys`, schedule its deletion in KMS (or destroy the file), and, if it may be compromised, add its key id to `revokedKeys`.

KMS automatic key rotation does not apply to asymmetric keys; rotate by creating a new key as above. Keep the old key until no ring pointer signed by it is younger than the pointer TTL (7 days) and every device has the new public key.

The kill-switch key has one public key per poller (`killSwitch.pubkey`, `killSwitch.pubkeyFile`, `killswitch_pubkey`), so its rotation is a coordinated restart; see [operations](/halos/guides/operations/).

## What is not covered

- The workload-credential key (`--workload-key-file`, CI and agent JWTs) is still an ed25519 file.
- Real AWS KMS and HSM signing is exercised in tests against a fake KMS and fake signers, not a live account or device.
- No threshold or multi-party signing: one key signs a release.
