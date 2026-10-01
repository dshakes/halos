package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// defaultExe is where each OS's package/MDM installs halod itself. halod
// refuses to run from a non-root-owned directory, so --exe must be one too.
var defaultExe = map[string]string{
	"darwin":  "/Library/Halos/bin/halod",
	"linux":   "/usr/local/lib/halos/halod",
	"windows": `C:\Program Files\Halos\halod.exe`,
}

const systemdUnit = `[Unit]
Description=Halos fleet agent
After=network-online.target
Wants=network-online.target
# Not enrolled until the operator writes the config; do not crash-loop before that.
ConditionPathExists={{.Config}}
[Service]
# halod refuses to start unless its binary dir, /etc/halos and /var/lib/halos
# (and the files in them) are root-owned and not group/other-writable.
ExecStart={{.Exe}} run --config {{.Config}} --state {{.State}}
StateDirectory=halos
StateDirectoryMode=0700
Restart=always
RestartSec=30
# halod writes root-owned managed settings, so it runs as root; keep the rest locked down.
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Install root:wheel 0644 in /Library/LaunchDaemons. halod refuses to start unless
     /Library/Halos/{bin,etc,var} and the files in them are root-owned and not
     group/other-writable. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.halos.halod</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Exe}}</string>
		<string>run</string>
		<string>--config</string>
		<string>{{.Config}}</string>
		<string>--state</string>
		<string>{{.State}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/Library/Halos/var/halod.log</string>
	<key>StandardErrorPath</key>
	<string>/Library/Halos/var/halod.log</string>
</dict>
</plist>
`

var serviceTmpl = map[string]*template.Template{
	"linux":  template.Must(template.New("systemd").Parse(systemdUnit)),
	"darwin": template.Must(template.New("launchd").Parse(launchdPlist)),
}

const (
	systemdPath = "/etc/systemd/system/halod.service"
	launchdPath = "/Library/LaunchDaemons/dev.halos.halod.plist"
	winTask     = "Halos"
)

// serviceSpec is what `service install` does on one OS: an optional unit
// file to write plus the commands that register (and, with --start, start) it.
type serviceSpec struct {
	Path, Content string
	Install       [][]string
	Start         [][]string
	Uninstall     [][]string
}

// planService renders the unit for goos. Windows has no native SCM service
// (halod is a console binary): it registers a SYSTEM scheduled task instead.
func planService(goos, exe string) (serviceSpec, error) {
	lay, ok := layouts[goos]
	if !ok {
		return serviceSpec{}, fmt.Errorf("service: unsupported OS %q", goos)
	}
	if exe == "" {
		exe = defaultExe[goos]
	}
	if strings.ContainsAny(exe, "\r\n\"<>&") {
		return serviceSpec{}, fmt.Errorf("service: unsafe --exe %q", exe)
	}
	if goos == "windows" {
		tr := fmt.Sprintf(`"%s" run --config "%s" --state "%s"`, exe, lay.Config, lay.State)
		return serviceSpec{
			Install:   [][]string{{"schtasks", "/Create", "/F", "/TN", winTask, "/RU", "SYSTEM", "/SC", "ONSTART", "/TR", tr}},
			Start:     [][]string{{"schtasks", "/Run", "/TN", winTask}},
			Uninstall: [][]string{{"schtasks", "/End", "/TN", winTask}, {"schtasks", "/Delete", "/F", "/TN", winTask}},
		}, nil
	}
	var b bytes.Buffer
	if err := serviceTmpl[goos].Execute(&b, map[string]string{"Exe": exe, "Config": lay.Config, "State": lay.State}); err != nil {
		return serviceSpec{}, fmt.Errorf("render %s unit: %w", goos, err)
	}
	if goos == "darwin" {
		return serviceSpec{
			Path: launchdPath, Content: b.String(),
			Install:   [][]string{{"launchctl", "bootstrap", "system", launchdPath}},
			Uninstall: [][]string{{"launchctl", "bootout", "system/dev.halos.halod"}},
		}, nil
	}
	return serviceSpec{
		Path: systemdPath, Content: b.String(),
		Install:   [][]string{{"systemctl", "daemon-reload"}},
		Start:     [][]string{{"systemctl", "enable", "--now", "halod"}},
		Uninstall: [][]string{{"systemctl", "disable", "--now", "halod"}},
	}, nil
}

// runService implements `halod service install|uninstall|print`. Files go under
// root (testing); run is exec.CommandContext in production.
func runService(ctx context.Context, goos, root, exe, action string, start bool, stdout io.Writer,
	run func(context.Context, string, ...string) ([]byte, error)) error {
	spec, err := planService(goos, exe)
	if err != nil {
		return err
	}
	exec := func(cmds [][]string, ignoreErr bool) error {
		for _, c := range cmds {
			if out, err := run(ctx, c[0], c[1:]...); err != nil && !ignoreErr {
				return fmt.Errorf("%s: %w: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	}
	dst := filepath.Join(root, spec.Path)
	switch action {
	case "print":
		if spec.Content == "" {
			return errors.New("service print: windows registers a scheduled task, there is no unit file")
		}
		_, err = io.WriteString(stdout, spec.Content)
		return err
	case "install":
		if spec.Path != "" {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // system unit dir
				return fmt.Errorf("service install: %w", err)
			}
			if err := os.WriteFile(dst, []byte(spec.Content), 0o644); err != nil { //nolint:gosec // units are world-readable
				return fmt.Errorf("service install: %w", err)
			}
		}
		if err := exec(spec.Install, false); err != nil {
			return err
		}
		if start {
			return exec(spec.Start, false)
		}
		fmt.Fprintln(stdout, "installed, not started: write the halod config, then re-run with --start")
		return nil
	case "uninstall":
		_ = exec(spec.Uninstall, true) // may not be running/registered
		if spec.Path != "" {
			if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("service uninstall: %w", err)
			}
			if goos == "linux" {
				return exec(spec.Install, false) // daemon-reload
			}
		}
		return nil
	}
	return fmt.Errorf("service: unknown action %q (install|uninstall|print)", action)
}
