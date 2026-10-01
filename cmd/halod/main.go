// Command halod is the Halos fleet agent: pull the ring's signed release,
// verify it, apply it atomically, report status.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"oras.land/oras-go/v2"

	"github.com/dshakes/halos/internal/bundle"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "halod:", err)
		os.Exit(1)
	}
}

const usage = `usage: halod <command> [flags]

Commands:
  run      pull, verify and apply the ring's signed release every interval
  once     one pull/verify/apply/report cycle, then exit
  status   print the last status from the state file
  service  install|uninstall|print the launchd/systemd unit (windows: scheduled task)
  help     show this help (halod <command> -h for a command's flags)
`

var commandHelp = map[string]string{
	"run":     "Pull, verify and apply the ring's signed release every interval (config: interval).",
	"once":    "Run one pull/verify/apply/report cycle and exit non-zero on failure.",
	"status":  "Print the status recorded by the last run.",
	"service": "Manage the OS service: halod service install|uninstall|print [--exe PATH] [--start].",
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("missing command")
	}
	cmd := args[0]
	switch cmd {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	if _, ok := commandHelp[cmd]; !ok {
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	if cmd == "service" {
		return serviceCmd(args[1:], stdout)
	}
	fl := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fl.SetOutput(stdout)
	fl.Usage = func() {
		fmt.Fprintf(fl.Output(), "usage: halod %s [flags]\n\n%s\n\nFlags:\n", cmd, commandHelp[cmd])
		fl.PrintDefaults()
	}
	lay := layouts[runtime.GOOS]
	cfgPath := fl.String("config", lay.Config, "config file")
	root := fl.String("root", "", "filesystem root prefix (testing)")
	install := fl.Bool("install", true, "install pinned CLI versions from the signed manifest")
	statePath := fl.String("state", lay.State, "state file")
	var level slog.Level
	fl.TextVar(&level, "log-level", slog.LevelInfo, "log level: debug|info|warn|error (logs are JSON on stderr)")
	if err := fl.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &Agent{
		Root: *root, StatePath: *statePath, Install: *install, Now: time.Now, Arch: runtime.GOARCH, Log: log, Stdout: stdout,
		HTTP: &http.Client{Timeout: 30 * time.Second}, Download: &http.Client{Timeout: 20 * time.Minute},
	}
	if cmd == "status" {
		b, err := os.ReadFile(a.path(a.StatePath))
		if err != nil {
			return fmt.Errorf("read state: %w", err)
		}
		var s State
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("parse state: %w", err)
		}
		out, _ := json.MarshalIndent(s.Status, "", "  ") // plain struct: cannot fail
		_, err = fmt.Fprintln(stdout, string(out))
		return err
	}
	// halod runs as root: refuse to run if anyone but root could have replaced this binary.
	self, err := selfExe()
	if err != nil {
		return err
	}
	if err := checkExe(self); err != nil {
		return err
	}
	// halod runs as root and trusts these files: refuse if anyone but root could
	// have written them (or swapped a parent directory).
	if err := checkChain(*cfgPath); err != nil {
		return fmt.Errorf("insecure config: %w", err)
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if err := preflight(cfg, a.path(a.StatePath)); err != nil {
		return err
	}
	keys, fps, err := loadKeyring(cfg)
	if err != nil {
		return err
	}
	log.Info("trusted release keys", "fingerprints", fps, "revoked", cfg.RevokedKeys)
	a.Cfg, a.Verifier = cfg, keys
	if a.Kill, err = loadKillSwitch(cfg, log); err != nil {
		return err
	}
	if a.Kill != nil {
		log.Info("kill switch enabled", "url", cfg.KillSwitch.URL)
	}
	a.Host, _ = os.Hostname()
	a.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	a.ConsoleUser = func(ctx context.Context) string { return consoleUser(ctx, a.Run) }
	a.Open = func(ctx context.Context) (oras.ReadOnlyTarget, error) {
		return bundle.Repository(cfg.Registry, cfg.PlainHTTP)
	}
	if cmd == "once" {
		_, err := a.Once(ctx)
		return err
	}
	iv, _ := cfg.IntervalD() // validated by LoadConfig
	a.KillEvery, _ = cfg.KillIntervalD()
	a.loop(ctx, iv, time.After)
	return nil
}

// loop runs Once every iv and, with a kill switch, PollKill every
// KillEvery in between, until ctx is done; after is time.After in production
// and a fake clock in tests. Both run on this goroutine: state has one writer.
func (a *Agent) loop(ctx context.Context, iv time.Duration, after func(time.Duration) <-chan time.Time) {
	for {
		if _, err := a.Once(ctx); err != nil {
			a.log().Error("cycle failed; keeping last-good release", "err", err)
		}
		next := after(iv)
		for polling := true; polling; {
			var kill <-chan time.Time // nil: never fires
			if a.Kill != nil {
				ke := a.KillEvery
				if ke <= 0 {
					ke = DefaultKillInterval
				}
				kill = after(ke)
			}
			select {
			case <-ctx.Done():
				return
			case <-next:
				polling = false
			case <-kill:
				if err := a.PollKill(ctx); err != nil {
					a.log().Error("kill-switch apply failed; keeping last-good release", "err", err)
				}
			}
		}
	}
}

// preflight checks every trusted input besides the config itself.
func preflight(cfg Config, statePath string) error {
	for name, p := range map[string]string{"deviceTokenFile": cfg.DeviceTokenFile, "state": statePath} {
		if p == "" {
			continue
		}
		if err := checkChain(p); err != nil {
			return fmt.Errorf("insecure %s: %w", name, err)
		}
	}
	for _, p := range append(cfg.KeyFiles(), cfg.KillSwitch.PubKey) {
		if p == "" {
			continue
		}
		if err := checkChain(p); err != nil {
			return fmt.Errorf("insecure pubkey: %w", err)
		}
	}
	return nil
}

// seat0User parses `loginctl list-sessions --no-legend` (SESSION UID USER SEAT ...).
func seat0User(out string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 4 && f[3] == "seat0" && f[1] != "0" {
			return f[2]
		}
	}
	return ""
}

// serviceCmd parses `halod service <action> [flags]`; it needs no halod config.
func serviceCmd(args []string, stdout io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: halod service install|uninstall|print [--exe PATH] [--start]")
	}
	fl := flag.NewFlagSet("service", flag.ContinueOnError)
	fl.SetOutput(stdout)
	exe := fl.String("exe", "", "halod binary path in the unit (default: this binary; it must be root-owned)")
	start := fl.Bool("start", false, "install: also enable and start the service")
	if err := fl.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *exe == "" && args[0] == "install" {
		self, err := selfExe()
		if err != nil {
			return err
		}
		*exe = self
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	run := func(ctx context.Context, name string, a ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, a...).CombinedOutput()
	}
	return runService(ctx, runtime.GOOS, "", *exe, args[0], *start, stdout, run)
}
