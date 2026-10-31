---
title: "halo keys public"
description: "Export the public key (PEM) and key id of a signing key: file://, awskms:// or exec://"
---

Export the public key (PEM) and key id of a signing key: file://, awskms:// or exec://

Opens the key the URI names and prints its public key as PKIX PEM, plus its algorithm and key id
(the fingerprint halod logs and revokedKeys takes). Key URIs:
  file://PATH (or PATH)                 PKCS#8 PEM ed25519 or ECDSA P-256 private key
  awskms://KEY[?region=R&fips=true]     AWS KMS SIGN_VERIFY key, ECC_NIST_P256 or ECC_NIST_EDWARDS25519;
                                        KEY is a key id, key ARN, alias/<name> or alias ARN; needs kms:GetPublicKey
  exec:///ABS/PATH[?arg=A&key=ID]       external signer (halos.signer.v1 JSON protocol over stdin/stdout);
                                        on Windows exec:///C:/path/to/signer.exe

## Usage

```console
halo keys public [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--key-uri` |  | string |  | signing key URI (file://, awskms://, exec://) |
| `--out` |  | string |  | also write the PEM to this file (refuses to overwrite) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo keys`](/halos/reference/cli/keys/)
