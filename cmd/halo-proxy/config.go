package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/halos-dev/halos/internal/identity"
	"github.com/halos-dev/halos/internal/telemetry/gwmetrics"
)

// Config is halo-proxy's configuration. Precedence: defaults < YAML (--config)
// < HALO_PROXY_* environment < flags.
type Config struct {
	Listen string `yaml:"listen"`
	// AdminListen serves /healthz and /metrics (unauthenticated); "" disables.
	// Loopback by default: expose it only to the kubelet / Prometheus.
	AdminListen string `yaml:"adminListen"`
	// Policy is the compiled snapshot (`halo gateway compile`); re-read on change.
	Policy string `yaml:"policy"`
	// NextHop, when set, receives every request instead of the decided
	// upstream (an existing Kong / auth gateway / LiteLLM).
	NextHop string `yaml:"nextHop"`
	// DefaultUpstream serves requests the policy has no route for (e.g. /v1/models).
	DefaultUpstream string `yaml:"defaultUpstream"`
	// ForwardAuth keeps the client's Authorization / x-api-key on the forwarded
	// request. Off by default: the caller's IdP token is not a provider credential.
	ForwardAuth bool `yaml:"forwardAuth"`
	// UpstreamHeaders are added per policy upstream name; values expand ${ENV}.
	UpstreamHeaders map[string]map[string]string `yaml:"upstreamHeaders"`
	// SignHosts are extra hostnames (besides *.amazonaws.com, *.amazonaws.com.cn,
	// *.api.aws) for which a kind: bedrock upstream may be SigV4-signed, e.g. a
	// private VPC endpoint DNS name. Signing for any other host is refused (502).
	SignHosts []string `yaml:"signHosts"`

	Identity IdentityConfig `yaml:"identity"`
	Shadow   ShadowConfig   `yaml:"shadow"`
	// KillSwitch polls halo-server's signed kill list; killed experiments get
	// control routing and no shadow. Empty URL disables.
	KillSwitch KillSwitchConfig `yaml:"killSwitch"`
	// Telemetry exports per-request OTLP metrics (halo.gateway.*) for
	// experiment analysis. Empty otlpEndpoint disables.
	Telemetry gwmetrics.Config `yaml:"telemetry"`

	MaxBodyBytes          int64         `yaml:"maxBodyBytes"`
	ReadHeaderTimeout     time.Duration `yaml:"readHeaderTimeout"`
	ReadTimeout           time.Duration `yaml:"readTimeout"`           // whole request incl. body; responses are never time-limited
	IdleTimeout           time.Duration `yaml:"idleTimeout"`           // keep-alive
	UpstreamHeaderTimeout time.Duration `yaml:"upstreamHeaderTimeout"` // wait for response headers; streams then run unbounded
	ShutdownTimeout       time.Duration `yaml:"shutdownTimeout"`
}

type IdentityConfig struct {
	Mode              string   `yaml:"mode"` // jwt | trusted_header | none
	Issuer            string   `yaml:"issuer"`
	Audience          string   `yaml:"audience"`
	UserClaim         string   `yaml:"userClaim"`
	GroupsClaim       string   `yaml:"groupsClaim"`
	IdentityHeader    string   `yaml:"identityHeader"`
	GroupsHeader      string   `yaml:"groupsHeader"`
	TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
	// AllowAnonymous lets callers that fail verification (e.g. opaque API keys
	// meant for the next hop) through with default routing instead of 401.
	AllowAnonymous bool `yaml:"allowAnonymous"`
}

type ShadowConfig struct {
	URL      string `yaml:"url"`      // halo-shadow /mirror endpoint; empty disables mirroring
	Token    string `yaml:"token"`    // prefer HALO_PROXY_HALO_SHADOW_TOKEN
	MaxBytes int    `yaml:"maxBytes"` // larger bodies are not mirrored (default 1 MiB)
}

func (c Config) identityOptions() identity.Options {
	i := c.Identity
	return identity.Options{Mode: i.Mode, Issuer: i.Issuer, Audience: i.Audience, UserClaim: i.UserClaim,
		GroupsClaim: i.GroupsClaim, IdentityHeader: i.IdentityHeader, GroupsHeader: i.GroupsHeader,
		TrustedProxyCIDRs: i.TrustedProxyCIDRs}
}

func defaults() Config {
	return Config{
		Listen:            ":8088",
		AdminListen:       "127.0.0.1:9090",
		MaxBodyBytes:      32 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		// Models may think a long time before the first byte; after that the
		// stream is bounded only by the client.
		UpstreamHeaderTimeout: 10 * time.Minute,
		ShutdownTimeout:       30 * time.Second,
		Shadow:                ShadowConfig{MaxBytes: 1 << 20},
	}
}

// loadConfig resolves flags, env and YAML. getenv is os.Getenv in production.
func loadConfig(args []string, getenv func(string) string, usage io.Writer) (Config, error) {
	cfg := defaults()
	path := getenv("HALO_PROXY_CONFIG")
	for i, a := range args {
		switch {
		case a == "--config" || a == "-config":
			if i+1 < len(args) {
				path = args[i+1]
			}
		case strings.HasPrefix(a, "--config="):
			path = strings.TrimPrefix(a, "--config=")
		case strings.HasPrefix(a, "-config="):
			path = strings.TrimPrefix(a, "-config=")
		}
	}
	if path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path is the point
		if err != nil {
			return cfg, fmt.Errorf("halo-proxy: read config: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return cfg, fmt.Errorf("halo-proxy: parse config %s: %w", path, err)
		}
	}

	fs := flag.NewFlagSet("halo-proxy", flag.ContinueOnError)
	fs.SetOutput(usage)
	fs.String("config", path, "YAML config file (env HALO_PROXY_CONFIG)")
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address (proxied model traffic only)")
	fs.StringVar(&cfg.AdminListen, "admin-listen", cfg.AdminListen, "address for /healthz and /metrics (unauthenticated; empty disables)")
	fs.StringVar(&cfg.Policy, "policy", cfg.Policy, "compiled policy snapshot path (hot-reloaded)")
	fs.StringVar(&cfg.NextHop, "next-hop", cfg.NextHop, "forward everything to this URL instead of the decided upstream")
	fs.StringVar(&cfg.DefaultUpstream, "default-upstream", cfg.DefaultUpstream, "upstream for requests the policy has no route for")
	fs.BoolVar(&cfg.ForwardAuth, "forward-auth", cfg.ForwardAuth, "keep the client's Authorization/x-api-key on the forwarded request")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", cfg.MaxBodyBytes, "request body limit; larger => 413")
	fs.StringVar(&cfg.Identity.Mode, "identity-mode", cfg.Identity.Mode, "jwt | trusted_header | none (default: jwt when an issuer is known)")
	fs.StringVar(&cfg.Identity.Issuer, "issuer", cfg.Identity.Issuer, "OIDC issuer (default: policy identity.issuer)")
	fs.StringVar(&cfg.Identity.Audience, "audience", cfg.Identity.Audience, "expected JWT audience (default: policy identity.audience/clientID)")
	fs.StringVar(&cfg.Identity.IdentityHeader, "identity-header", cfg.Identity.IdentityHeader, "trusted_header: user id header")
	fs.StringVar(&cfg.Identity.GroupsHeader, "groups-header", cfg.Identity.GroupsHeader, "trusted_header: groups header")
	fs.Func("trusted-proxy-cidrs", "trusted_header: comma-separated CIDRs allowed to set identity headers", func(s string) error {
		cfg.Identity.TrustedProxyCIDRs = nil
		for _, c := range strings.Split(s, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cfg.Identity.TrustedProxyCIDRs = append(cfg.Identity.TrustedProxyCIDRs, c)
			}
		}
		return nil
	})
	fs.BoolVar(&cfg.Identity.AllowAnonymous, "allow-anonymous", cfg.Identity.AllowAnonymous, "unverified callers get default routing instead of 401")
	fs.StringVar(&cfg.Shadow.URL, "halo-shadow-url", cfg.Shadow.URL, "halo-shadow /mirror endpoint; empty disables mirroring")
	fs.StringVar(&cfg.Shadow.Token, "halo-shadow-token", cfg.Shadow.Token, "halo-shadow token (prefer env HALO_PROXY_HALO_SHADOW_TOKEN)")
	fs.StringVar(&cfg.KillSwitch.URL, "killswitch-url", cfg.KillSwitch.URL, "halo-server /api/v1/gateway/killswitch URL; empty disables")
	fs.StringVar(&cfg.KillSwitch.TokenFile, "killswitch-token-file", cfg.KillSwitch.TokenFile, "file holding the halo-server gateway token")
	fs.StringVar(&cfg.KillSwitch.PubkeyFile, "killswitch-pubkey-file", cfg.KillSwitch.PubkeyFile, "ed25519 PEM public key verifying the kill list")
	fs.DurationVar(&cfg.KillSwitch.Interval, "killswitch-interval", cfg.KillSwitch.Interval, "kill list poll interval (default 10s)")
	fs.StringVar(&cfg.Telemetry.OTLPEndpoint, "telemetry-otlp-endpoint", cfg.Telemetry.OTLPEndpoint, "OTLP/HTTP collector base URL for halo.gateway.* request metrics; empty disables")
	fs.StringVar(&cfg.Telemetry.Protocol, "telemetry-protocol", cfg.Telemetry.Protocol, "OTLP protocol: http/protobuf (default) | http/json")
	fs.DurationVar(&cfg.Telemetry.Interval, "telemetry-interval", cfg.Telemetry.Interval, "OTLP export interval (default 10s, min 1s)")
	var saltFile string
	fs.StringVar(&saltFile, "telemetry-unit-salt-file", "", "file holding the halo.unit hash salt, shared by all replicas (no inline flag: flags leak via ps)")
	fs.StringVar(&cfg.Telemetry.TokenFile, "telemetry-token-file", cfg.Telemetry.TokenFile, "file holding the bearer token for the collector's gateway receiver (otlp/gateway, :4319)")
	fs.DurationVar(&cfg.ReadTimeout, "read-timeout", cfg.ReadTimeout, "max time to read a request")
	fs.DurationVar(&cfg.UpstreamHeaderTimeout, "upstream-header-timeout", cfg.UpstreamHeaderTimeout, "max wait for upstream response headers")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", cfg.ShutdownTimeout, "graceful shutdown budget (in-flight streams)")

	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		env := "HALO_PROXY_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v := getenv(env); v != "" && f.Name != "config" {
			if err := fs.Set(f.Name, v); err != nil && envErr == nil {
				envErr = fmt.Errorf("halo-proxy: %s: %w", env, err)
			}
		}
	})
	if envErr != nil {
		return cfg, envErr
	}
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if saltFile != "" {
		b, err := os.ReadFile(saltFile) //nolint:gosec // operator-supplied path is the point
		if err != nil {
			return cfg, fmt.Errorf("halo-proxy: telemetry unit salt file: %w", err)
		}
		if cfg.Telemetry.UnitSalt = strings.TrimSpace(string(b)); cfg.Telemetry.UnitSalt == "" {
			return cfg, fmt.Errorf("halo-proxy: telemetry unit salt file %s is empty", saltFile)
		}
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.Policy == "" {
		return errors.New("halo-proxy: --policy is required")
	}
	if c.MaxBodyBytes <= 0 {
		return errors.New("halo-proxy: maxBodyBytes must be > 0")
	}
	if err := c.Telemetry.Validate(); err != nil {
		return fmt.Errorf("halo-proxy: %w", err)
	}
	for name, v := range map[string]string{"nextHop": c.NextHop, "defaultUpstream": c.DefaultUpstream} {
		if v == "" {
			continue
		}
		if _, err := parseBase(v); err != nil {
			return fmt.Errorf("halo-proxy: %s: %w", name, err)
		}
	}
	return nil
}

func parseBase(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an http(s) URL", s)
	}
	return u, nil
}
