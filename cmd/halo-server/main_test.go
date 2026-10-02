package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/server"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		err  string
		chk  func(options) bool
	}{
		{"required", []string{"--listen", ":1"}, "required", nil},
		{"bad cidr", []string{"--policy-dir", "p", "--token-file", "t", "--trusted-proxy-cidrs", "10.0.0.0/8,nope"}, "trusted-proxy-cidrs", nil},
		{"unknown flag", []string{"--nope"}, "not defined", nil},
		{"killswitch key without gateway token", []string{"--policy-dir", "p", "--token-file", "t", "--killswitch-key-file", "k"}, "set together", nil},
		{"gateway token alone serves posture", []string{"--policy-dir", "p", "--token-file", "t", "--gateway-token-file", "g", "--posture-max-age", "30m"}, "",
			func(o options) bool { return o.gatewayTokenFile == "g" && o.postureMaxAge == 30*time.Minute }},
		{"posture max age too short", []string{"--policy-dir", "p", "--token-file", "t", "--posture-max-age", "10s"}, "at least 1m", nil},
		{"controller without clickhouse", []string{"--policy-dir", "p", "--token-file", "t", "--controller", "--data-dir", "d"}, "--clickhouse-url", nil},
		{"controller without data dir", []string{"--policy-dir", "p", "--token-file", "t", "--controller", "--clickhouse-url", "http://ch"}, "--data-dir", nil},
		{"controller interval too short", []string{"--policy-dir", "p", "--token-file", "t", "--controller", "--clickhouse-url", "http://ch", "--data-dir", "d", "--interval", "5s"}, "at least 1m", nil},
		{"killswitch without data dir", []string{"--policy-dir", "p", "--token-file", "t", "--killswitch-key-file", "k", "--gateway-token-file", "g"}, "requires --data-dir", nil},
		{"deprecated spellings", []string{"--policy-dir", "p", "--token-file", "t", "--verdicts", "v.json", "--controller-interval", "2m"}, "",
			func(o options) bool { return o.verdicts == "v.json" && o.interval == 2*time.Minute }},
		{"canonical spellings", []string{"--policy-dir", "p", "--token-file", "t", "--verdicts-file", "v.json", "--interval", "3m"}, "",
			func(o options) bool { return o.verdicts == "v.json" && o.interval == 3*time.Minute }},
		{"controller ok", []string{"--policy-dir", "p", "--token-file", "t", "--controller", "--clickhouse-url", "http://ch", "--data-dir", "d",
			"--killswitch-key-file", "k", "--gateway-token-file", "g", "--policy-repo-dir", "r"}, "",
			func(o options) bool {
				return o.controller && o.interval == 5*time.Minute && o.policyRepoBase == "main" && o.killKeyFile == "k" && o.gatewayTokenFile == "g" && o.policyRepoDir == "r"
			}},
		{"ok", []string{"--policy-dir", "p", "--token-file", "t", "--trusted-proxy-cidrs", " 10.1.2.3/8 ,", "--dev-insecure-groups", "a, b,", "--dev-insecure-admin", "--device-ttl", "24h"}, "",
			func(o options) bool {
				return o.policyDir == "p" && o.listen == "127.0.0.1:8080" && len(o.trusted) == 1 && o.trusted[0].String() == "10.0.0.0/8" &&
					strings.Join(o.devGroups, "|") == "a|b" && o.devAdmin && o.deviceTTL == 24*time.Hour
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseFlags(tc.args)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("want %q error, got %v", tc.err, err)
				}
				return
			}
			if err != nil || !tc.chk(o) {
				t.Fatalf("%+v %v", o, err)
			}
		})
	}
}

func TestPolicyWriterSameCloneGuard(t *testing.T) {
	root := t.TempDir()
	served, clone := filepath.Join(root, "served"), filepath.Join(root, "clone")
	for _, d := range []string{served, clone} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if w, err := policyWriter(server.Portal{}, served); w != nil || err != nil {
		t.Fatalf("no repo dir: %v %v", w, err)
	}
	for _, bad := range []string{served, served + "/.", filepath.Join(served, "sub"), root} {
		if _, err := policyWriter(server.Portal{PolicyRepoDir: bad}, served); err == nil {
			t.Errorf("clone %s overlapping served %s accepted", bad, served)
		}
	}
	w, err := policyWriter(server.Portal{PolicyRepoDir: clone, PolicyBase: "trunk"}, served)
	if err != nil {
		t.Fatal(err)
	}
	if g := w.(*server.GitPolicyWriter); g.RepoDir != clone || g.ServedDir != served || g.Base != "trunk" {
		t.Fatalf("%+v", g)
	}
}

func TestNewControllerWiring(t *testing.T) {
	root := t.TempDir()
	served, portalDir, clone := filepath.Join(root, "served"), filepath.Join(root, "portal"), filepath.Join(root, "ctrl")
	for _, d := range []string{served, portalDir, clone} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := server.New(server.Config{PolicyDir: served, Token: "t", DevUser: "d"})
	if err != nil {
		t.Fatal(err)
	}
	kills, err := controller.OpenKillStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kills.Close() }()
	portal := server.Portal{PolicyRepoDir: portalDir}
	pw, err := policyWriter(portal, served)
	if err != nil {
		t.Fatal(err)
	}
	base := options{policyDir: served, dataDir: t.TempDir(), chURL: "http://ch", interval: time.Minute, policyRepoBase: "main"}
	with := func(f func(*options)) options { o := base; f(&o); return o }
	for _, tc := range []struct {
		name       string
		o          options
		kills      *controller.KillStore
		err        string
		wantWriter any // nil, pw, or "new"
		wantKill   bool
	}{
		{"no clone, no kill key", base, nil, "", nil, false},
		{"kill key served", base, kills, "", nil, true},
		{"shares the portal clone", with(func(o *options) { o.policyRepoDir = portalDir + "/" }), kills, "", pw, true},
		{"portal clone, other base", with(func(o *options) { o.policyRepoDir = portalDir; o.policyRepoBase = "dev" }), nil, "must match", nil, false},
		{"dedicated clone", with(func(o *options) { o.policyRepoDir = clone }), nil, "", "new", false},
		{"clone is the served dir", with(func(o *options) { o.policyRepoDir = served }), nil, "separate clone", nil, false},
		{"clone inside the portal clone", with(func(o *options) { o.policyRepoDir = filepath.Join(portalDir, "sub") }), nil, "separate clone", nil, false},
		{"bad password file", with(func(o *options) { o.chPasswordFile = filepath.Join(root, "missing") }), nil, "--clickhouse-password-file", nil, false},
		{"bad notifier file", with(func(o *options) { o.slackURLFile = filepath.Join(root, "missing") }), nil, "--notify-slack-url-file", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newController(tc.o, portal, pw, srv, tc.kills)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("want %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.State.Close() }()
			switch tc.wantWriter {
			case nil:
				if c.Writer != nil {
					t.Fatalf("writer = %#v", c.Writer)
				}
			case "new":
				if g, ok := c.Writer.(*server.GitPolicyWriter); !ok || g == pw || g.RepoDir != clone || g.ServedDir != served {
					t.Fatalf("writer = %#v", c.Writer)
				}
			default:
				if c.Writer != tc.wantWriter {
					t.Fatalf("writer = %#v, want the portal writer", c.Writer)
				}
			}
			if (c.Kill != nil) != tc.wantKill || (c.Kills != nil) != tc.wantKill || c.State == nil || c.Metrics == nil || c.Org == nil {
				t.Fatalf("%+v", c)
			}
		})
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tokFile := write("tok", "fleet-token\n")
	gwFile := write("gw", "gateway-token-0123456789")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := write("kill.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	notExist := "no such file" // the OS's wording of ErrNotExist
	if runtime.GOOS == "windows" {
		notExist = "cannot find the file"
	}
	common := []string{"--policy-dir", "../../examples/acme-corp", "--token-file", tokFile, "--listen", "127.0.0.1:0", "--dev-insecure-user", "dev"}
	for _, tc := range []struct {
		name string
		args []string
		err  string
	}{
		{"bad flags", []string{"--nope"}, "not defined"},
		{"missing token file", []string{"--policy-dir", "p", "--token-file", filepath.Join(dir, "missing")}, notExist},
		{"missing portal config", append(common, "--portal-config", filepath.Join(dir, "missing")), notExist},
		{"unknown portal key", append(common, "--portal-config", write("portal.json", `{"nope":1}`)), "portal config"},
		{"bad kill key", append(common, "--data-dir", t.TempDir(), "--killswitch-key-file", tokFile, "--gateway-token-file", gwFile), "--killswitch-key-file"},
		{"short gateway token", append(common, "--data-dir", t.TempDir(), "--killswitch-key-file", keyFile, "--gateway-token-file", tokFile), "at least 16"},
		{"serves until cancelled", append(common, "--data-dir", t.TempDir(), "--killswitch-key-file", keyFile, "--gateway-token-file", gwFile), ""},
		{"with controller", append(common, "--data-dir", t.TempDir(), "--controller", "--clickhouse-url", "http://127.0.0.1:1", "--metrics-listen", "127.0.0.1:0"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := run(ctx, tc.args)
			if tc.err == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("want %q, got %v", tc.err, err)
			}
		})
	}
}
