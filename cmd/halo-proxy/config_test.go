package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryFlagsAndEnv(t *testing.T) {
	dir := t.TempDir()
	salt := filepath.Join(dir, "salt")
	if err := os.WriteFile(salt, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--policy", "p.json", "--telemetry-otlp-endpoint", "http://otel:4318"}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr bool
		proto   string
		iv      time.Duration
		salt    string
	}{
		{name: "flags", args: append([]string{"--telemetry-protocol", "http/json", "--telemetry-interval", "30s", "--telemetry-unit-salt-file", salt}, base...), proto: "http/json", iv: 30 * time.Second, salt: "s3cret"},
		{name: "env", args: base, env: map[string]string{"HALO_PROXY_TELEMETRY_PROTOCOL": "http/json", "HALO_PROXY_TELEMETRY_INTERVAL": "5s", "HALO_PROXY_TELEMETRY_UNIT_SALT_FILE": salt}, proto: "http/json", iv: 5 * time.Second, salt: "s3cret"},
		{name: "flag beats env", args: append([]string{"--telemetry-interval", "20s"}, base...), env: map[string]string{"HALO_PROXY_TELEMETRY_INTERVAL": "5s"}, iv: 20 * time.Second},
		{name: "defaults", args: base},
		{name: "bad protocol", args: append([]string{"--telemetry-protocol", "grpc"}, base...), wantErr: true},
		{name: "interval too small", args: append([]string{"--telemetry-interval", "100ms"}, base...), wantErr: true},
		{name: "missing salt file", args: append([]string{"--telemetry-unit-salt-file", filepath.Join(dir, "none")}, base...), wantErr: true},
		{name: "empty salt file", args: append([]string{"--telemetry-unit-salt-file", empty}, base...), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(tc.args, env(tc.env), io.Discard)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got := cfg.Telemetry; got.Protocol != tc.proto || got.Interval != tc.iv || got.UnitSalt != tc.salt {
				t.Fatalf("telemetry=%+v", got)
			}
		})
	}
}

func TestRouteConfig(t *testing.T) {
	write := func(y string) string {
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := loadConfig([]string{"--config", write("policy: p.json\nupstreamHosts: [pe.corp]\nallowInsecureUpstreams: true\nroute: {maxAttempts: 2, breakerFailures: 3, breakerCooldown: 5s}\n")}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Route.MaxAttempts != 2 || cfg.Route.BreakerFailures != 3 || cfg.Route.BreakerCooldown != 5*time.Second || !cfg.AllowInsecureUpstreams || cfg.UpstreamHosts[0] != "pe.corp" {
		t.Fatalf("%+v", cfg)
	}
	if cfg, err = loadConfig([]string{"--policy", "p.json"}, func(string) string { return "" }, io.Discard); err != nil || cfg.Route.MaxAttempts != 3 || cfg.Route.BreakerCooldown != 30*time.Second {
		t.Fatalf("defaults: %+v %v", cfg.Route, err)
	}
	if _, err := loadConfig([]string{"--config", write("policy: p.json\nroute: {maxAttempts: 0, breakerFailures: 1, breakerCooldown: 1s}\n")}, func(string) string { return "" }, io.Discard); err == nil {
		t.Fatal("maxAttempts 0 must be rejected")
	}
}
