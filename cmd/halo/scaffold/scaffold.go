// Package scaffold generates a minimal, valid Halos policy repo.
package scaffold

import (
	"bytes"
	"fmt"
	"text/template"
)

var files = map[string]string{
	"halos.yaml": `apiVersion: halos.dev/v1
kind: Halos
org: {{.Org}}
`,
	"gateway.yaml": `apiVersion: halos.dev/v1
kind: Gateway
name: {{.Org}}-gateway
baseURL: https://ai.{{.Org}}.example
protocols:
  claude-code: anthropic-messages
auth:
  helperCommand: /usr/local/bin/{{.Org}}-token
  ttlSeconds: 3300
  identityHeader: x-{{.Org}}-user
upstreams:
  anthropic-direct:
    url: https://api.anthropic.com
    kind: anthropic
models:
  sonnet:
    upstream: anthropic-direct
    model: claude-sonnet-4-5
`,
	"profiles/base.yaml": `apiVersion: halos.dev/v1
kind: Profile
name: base
harnesses:
  claude-code:
    version: 2.1.280
models:
  default: sonnet
  allowed: [sonnet]
  enforce: true
permissions:
  mode: default
  disableBypass: true
  sandbox: workspace-write
  deny:
    - Read(./.env)
    - Read(~/.ssh/**)
mcp:
  managedOnly: true
hooks:
  managedOnly: true
telemetry:
  enabled: true
  otlpEndpoint: https://otel.{{.Org}}.example:4318
  protocol: http/protobuf
egress:
  allowedDomains:
    - ai.{{.Org}}.example
    - otel.{{.Org}}.example
    - github.com
instructions: |
  # {{.Org}} engineering
  - Run tests before proposing a commit.
  - Never paste secrets into prompts.
`,
	"rings/ring0-canary.yaml": `apiVersion: halos.dev/v1
kind: Ring
name: ring0-canary
order: 0
profile: base
membership:
  percent: 5
`,
	"rings/ring1-ga.yaml": `apiVersion: halos.dev/v1
kind: Ring
name: ring1-ga
order: 1
profile: base
membership:
  default: true
`,
}

// Files returns relative path -> content for a new policy repo for org.
func Files(org string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(files))
	for p, src := range files {
		t, err := template.New(p).Parse(src)
		if err != nil {
			return nil, fmt.Errorf("scaffold: parse %s: %w", p, err)
		}
		var b bytes.Buffer
		if err := t.Execute(&b, struct{ Org string }{org}); err != nil {
			return nil, fmt.Errorf("scaffold: render %s: %w", p, err)
		}
		out[p] = b.Bytes()
	}
	return out, nil
}
