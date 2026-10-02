package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is halod.yaml (see defaultConfigPath for the per-OS location).
type Config struct {
	// Registry is the OCI repository, e.g. ghcr.io/acme/halos-releases.
	Registry string `yaml:"registry"`
	// Org must equal the org in the signed ring pointer and release manifest.
	Org string `yaml:"org"`
	// Ring is a fixed ring name. If empty, RingEndpoint is asked instead.
	Ring         string `yaml:"ring"`
	RingEndpoint string `yaml:"ringEndpoint"` // GET ?user=&host= -> {"ring":"name"}
	PubKey       string `yaml:"pubkey"`       // ed25519 public key PEM path (single key; see PubKeys)
	// PubKeys are additional trusted release keys; a release signed by ANY of
	// PubKey/PubKeys verifies, so old and new keys overlap during rotation.
	PubKeys []string `yaml:"pubkeys"`
	// RevokedKeys are key fingerprints ("sha256:<hex>" of the raw ed25519
	// public key, printed by halod at startup) that are never trusted, even if
	// listed above.
	RevokedKeys []string `yaml:"revokedKeys"`
	Interval    string   `yaml:"interval"` // Go duration, default 15m
	OS          string   `yaml:"os"`       // default runtime.GOOS
	ReportURL   string   `yaml:"reportURL"`
	// DeviceToken authenticates ring and report calls (Authorization: Bearer). Prefer
	// DeviceTokenFile (mode 0600 on unix); LoadConfig reads it into DeviceToken.
	DeviceToken     string `yaml:"deviceToken"`
	DeviceTokenFile string `yaml:"deviceTokenFile"`
	PlainHTTP       bool   `yaml:"plainHTTP"` // registry over http (dev only)
	// AllowShellInstall permits the legacy manifest installCommand (curl|bash,
	// npm install -g with lifecycle scripts) run as root when no verified
	// artifact exists. INSECURE; default false.
	AllowShellInstall bool `yaml:"allowShellInstall"`
	// MaxBundleBytes caps the release tar halod downloads (default 256MiB).
	MaxBundleBytes int64 `yaml:"maxBundleBytes"`
	// Subject is the user id client-axis experiments are assigned by (the id
	// the gateway sees, e.g. the email; MDM tools template it). Optional: an
	// enrolled device gets it from ringEndpoint, which takes precedence. If
	// neither knows it, halod stays on the ring release (no_subject_for_experiment).
	Subject string `yaml:"subject"`
	// KillSwitch polls halo-server's signed kill list: a device whose
	// client-axis experiment is killed reverts to the ring release (control)
	// within one kill-poll interval, without waiting for a republish.
	KillSwitch KillSwitchConfig `yaml:"killSwitch"`
	// Immutable sets the system-immutable flag on every managed file after
	// halod writes it (macOS chflags schg, Linux chattr +i) and clears it just
	// before a rewrite or removal, so nothing short of root clearing the flag
	// can edit the file between runs. Default false. Ignored on Windows; a
	// missing tool or permission is logged and halod carries on without it.
	Immutable bool `yaml:"immutable"`
}

// KillSwitchConfig: enabled when PubKey is set.
type KillSwitchConfig struct {
	// URL defaults to <ringEndpoint scheme://host>/api/v1/fleet/killswitch.
	URL string `yaml:"url"`
	// PubKey is the kill-list ed25519 public key PEM path (not the release key).
	PubKey string `yaml:"pubkey"`
	// Interval is the kill-poll interval (Go duration, default 60s); polls do not pull releases.
	Interval string `yaml:"interval"`
}

// DefaultKillInterval is the kill-poll interval when killSwitch.interval is unset.
const DefaultKillInterval = time.Minute

// KillIntervalD is the validated kill-poll interval.
func (c Config) KillIntervalD() (time.Duration, error) {
	if c.KillSwitch.Interval == "" {
		return DefaultKillInterval, nil
	}
	d, err := time.ParseDuration(c.KillSwitch.Interval)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("invalid killSwitch.interval %q", c.KillSwitch.Interval)
	}
	return d, nil
}

// checkKillSwitch validates killSwitch and fills in the default URL.
func (c *Config) checkKillSwitch() error {
	k := &c.KillSwitch
	if k.PubKey == "" {
		if k.URL != "" || k.Interval != "" {
			return fmt.Errorf("killSwitch.pubkey is required when killSwitch is configured")
		}
		return nil
	}
	if k.URL == "" {
		u, err := url.Parse(c.RingEndpoint)
		if c.RingEndpoint == "" || err != nil || u.Host == "" {
			return fmt.Errorf("killSwitch.url is required without ringEndpoint")
		}
		k.URL = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/api/v1/fleet/killswitch"}).String()
	}
	if err := checkHTTPS(k.URL); err != nil {
		return fmt.Errorf("killSwitch.url: %w", err)
	}
	if _, err := c.KillIntervalD(); err != nil {
		return err
	}
	return nil
}

// maxSubjectLen bounds a subject id from config or the ring endpoint.
const maxSubjectLen = 256

// validSubject: a non-empty id without control characters or surrounding space.
func validSubject(s string) bool {
	if s == "" || len(s) > maxSubjectLen || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

var ringRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}$`)

func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path is the point
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.OS == "" {
		c.OS = runtime.GOOS
	}
	switch {
	case c.Registry == "":
		return c, fmt.Errorf("config %s: registry is required", path)
	case len(c.KeyFiles()) == 0:
		return c, fmt.Errorf("config %s: pubkey or pubkeys is required (halod never applies unsigned releases)", path)
	case c.Ring == "" && c.RingEndpoint == "":
		return c, fmt.Errorf("config %s: set ring or ringEndpoint", path)
	case c.Ring != "" && !ringRe.MatchString(c.Ring):
		return c, fmt.Errorf("config %s: invalid ring %q", path, c.Ring)
	case c.Org == "":
		return c, fmt.Errorf("config %s: org is required (ring pointers are org-scoped)", path)
	case c.MaxBundleBytes < 0:
		return c, fmt.Errorf("config %s: maxBundleBytes must be >= 0", path)
	case c.Subject != "" && !validSubject(c.Subject):
		return c, fmt.Errorf("config %s: invalid subject %q (1-%d chars, no control characters or surrounding space)", path, c.Subject, maxSubjectLen)
	}
	for name, u := range map[string]string{"ringEndpoint": c.RingEndpoint, "reportURL": c.ReportURL} {
		if err := checkHTTPS(u); err != nil {
			return c, fmt.Errorf("config %s: %s: %w", path, name, err)
		}
	}
	if _, err := c.IntervalD(); err != nil {
		return c, err
	}
	if err := c.checkKillSwitch(); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}
	if c.DeviceTokenFile != "" {
		tok, err := readTokenFile(c.DeviceTokenFile)
		if err != nil {
			return c, fmt.Errorf("config %s: %w", path, err)
		}
		c.DeviceToken = tok
	}
	if c.KillSwitch.PubKey != "" && c.DeviceToken == "" {
		return c, fmt.Errorf("config %s: killSwitch needs deviceToken or deviceTokenFile (the kill list is device-authenticated)", path)
	}
	return c, nil
}

// checkHTTPS allows "" or https URLs; plain http only to loopback (tests, local dev).
func checkHTTPS(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	switch h := u.Hostname(); {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && (h == "localhost" || net.ParseIP(h).IsLoopback()):
		return nil
	}
	return fmt.Errorf("%q must use https (http only for localhost)", raw)
}

// readTokenFile refuses files readable by group/other on unix: the token is a credential.
func readTokenFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("deviceTokenFile: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("deviceTokenFile %s has mode %04o; must not be accessible by group/other (chmod 600)", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("deviceTokenFile: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("deviceTokenFile %s is empty", path)
	}
	return tok, nil
}

// KeyFiles are the configured public key paths, pubkey first.
func (c Config) KeyFiles() []string {
	var out []string
	for _, p := range append([]string{c.PubKey}, c.PubKeys...) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) IntervalD() (time.Duration, error) {
	if c.Interval == "" {
		return 15 * time.Minute, nil
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("invalid interval %q", c.Interval)
	}
	return d, nil
}
