---
title: "halo dlp test"
description: "Dry-run the gateway's secret and prompt-injection scan on a file, locally"
---

Dry-run the gateway's secret and prompt-injection scan on a file, locally

Scans &lt;file> the way halo-proxy and halo-kong scan a model call, without sending anything. A JSON model-call body (Anthropic messages, OpenAI Responses input, Gemini contents) is scanned as a request; any other file is scanned as a tool result, so the prompt-injection signals apply too. With --policy-dir the policy's gateway.dlp, its rules for --ring and --unit, and its org patterns apply; without it every built-in detector runs in monitor mode. Findings show the detector, an 8-hex SHA-256 prefix and the JSON path, never the secret. Exit 0 when nothing is found, 2 when something is.

## Usage

```console
halo dlp test <file> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--as` |  | string |  | request \| tool-result (default: request for a JSON model-call body, else tool-result) |
| `--injection` |  | string |  | override the injection action for this run: off \| monitor \| block |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--protocol` |  | string |  | wire protocol of a request body: anthropic-messages \| openai-responses \| gemini \| bedrock-invoke (default: from the body) |
| `--ring` |  | string |  | ring the caller is routed to (selects gateway.dlp.rules) |
| `--secrets` |  | string |  | override the secret action for this run: off \| monitor \| redact \| block |
| `--show-redacted` |  | bool | false | print the redacted body (redact action only) |
| `--unit` |  | string |  | org unit the caller belongs to (selects gateway.dlp.rules; its ancestors match too) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo dlp`](/halos/reference/cli/dlp/)
