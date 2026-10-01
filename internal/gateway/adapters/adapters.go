// Package adapters renders the "put halo-proxy in front of / behind stack X"
// config snippets shipped under deploy/integrations. The static files there are
// generated from these templates (go test ./internal/gateway/adapters -update)
// and a test fails if they drift.
package adapters

import (
	"bytes"
	"embed"
	"fmt"
	"text/template"
)

//go:embed templates/*.tmpl
var fsys embed.FS

// Params tunes a snippet. Zero values are filled with defaults.
type Params struct {
	Host           string // halo-proxy host as the gateway sees it (default "halo-proxy")
	Port           int    // default 8088
	TimeoutSeconds int    // read/idle timeout for streams (default 600)
}

func (p Params) TimeoutMillis() int { return p.TimeoutSeconds * 1000 }

func (p Params) withDefaults() Params {
	if p.Host == "" {
		p.Host = "halo-proxy"
	}
	if p.Port == 0 {
		p.Port = 8088
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 600
	}
	return p
}

// Outputs maps an adapter name to its path under deploy/integrations.
var Outputs = map[string]string{
	"kong":  "kong/kong.yml",
	"envoy": "envoy/envoy.yaml",
	"nginx": "nginx/halo-proxy.conf",
	"apigw": "aws-api-gateway/openapi.yaml",
}

var templateFiles = map[string]string{
	"kong": "templates/kong.yml.tmpl", "envoy": "templates/envoy.yaml.tmpl",
	"nginx": "templates/nginx.conf.tmpl", "apigw": "templates/apigw-openapi.yaml.tmpl",
}

// Render returns the snippet for adapter name.
func Render(name string, p Params) ([]byte, error) {
	f, ok := templateFiles[name]
	if !ok {
		return nil, fmt.Errorf("adapters: unknown adapter %q", name)
	}
	t, err := template.ParseFS(fsys, f)
	if err != nil {
		return nil, fmt.Errorf("adapters: parse %s: %w", f, err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, p.withDefaults()); err != nil {
		return nil, fmt.Errorf("adapters: render %s: %w", name, err)
	}
	return b.Bytes(), nil
}
