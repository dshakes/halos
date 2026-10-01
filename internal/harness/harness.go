// Package harness defines the adapter contract every AI coding CLI implements.
// An adapter turns a resolved policy.Profile into the files that CLI reads
// as admin-enforced configuration, per OS.
package harness

import (
	"fmt"
	"sort"

	"github.com/dshakes/halos/internal/policy"
)

// OS is a target platform for rendered files.
type OS string

const (
	Darwin  OS = "darwin"
	Linux   OS = "linux"
	Windows OS = "windows"
)

// Capability is something an adapter can enforce centrally.
type Capability string

const (
	CapVersionPin   Capability = "version-pin"   // CLI refuses to run outside the pinned version
	CapModelLock    Capability = "model-lock"    // restrict selectable models
	CapMCPAllowlist Capability = "mcp-allowlist" // restrict MCP servers
	CapHooksLock    Capability = "hooks-lock"    // only managed hooks run
	CapPermissions  Capability = "permissions"   // tool allow/deny rules
	CapGateway      Capability = "gateway"       // route traffic through a custom base URL
	CapTelemetry    Capability = "telemetry"     // OTEL export
	CapInstructions Capability = "instructions"  // managed org-wide memory file
	CapHeaders      Capability = "headers"       // custom request headers (ring stamping)
)

// File is one rendered artifact.
type File struct {
	// Path is absolute on the target OS.
	Path string
	Mode uint32
	Data []byte
}

// Context carries everything an adapter needs beyond the profile.
type Context struct {
	Gateway *policy.Gateway
	Ring    string
	Release string // release digest or version label, stamped into headers/telemetry
	OS      OS
	// Experiment/Variant are set when rendering a client-axis variant release;
	// adapters stamp them into telemetry resource attributes (halo.experiment,
	// halo.variant) so CLI metrics are attributed to the variant. Never sent as
	// request headers: the gateway assigns and stamps x-halo-* itself.
	Experiment string
	Variant    string
}

// Adapter renders one harness.
type Adapter interface {
	Name() string
	Capabilities() []Capability
	// Render returns the admin-enforced files for the profile. Unsupported
	// profile fields must be reported as warnings, never silently dropped.
	Render(p *policy.Profile, c Context) (files []File, warnings []string, err error)
	// InstallCommand returns the shell command that installs exactly version on os.
	InstallCommand(version string, os OS) string
}

var registry = map[string]Adapter{}

// Register adds an adapter; called from adapter init().
func Register(a Adapter) {
	if _, dup := registry[a.Name()]; dup {
		panic(fmt.Sprintf("harness: duplicate adapter %q", a.Name()))
	}
	registry[a.Name()] = a
}

// Override replaces (or adds) the adapter registered under a.Name() and
// returns a func restoring the previous state. For tests that stand in for a
// real adapter in a binary that also links the real ones; not concurrency-safe.
func Override(a Adapter) (restore func()) {
	prev, had := registry[a.Name()]
	registry[a.Name()] = a
	return func() {
		if had {
			registry[a.Name()] = prev
		} else {
			delete(registry, a.Name())
		}
	}
}

// Get returns an adapter by name.
func Get(name string) (Adapter, bool) { a, ok := registry[name]; return a, ok }

// Names lists registered adapters, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Installer kinds for Meta.Installer.
const (
	InstallerNPM          = "npm"           // npm package tarball (Meta.NPMPackage)
	InstallerClaudeNative = "claude-native" // Anthropic's signed native-binary manifest
)

// Meta is optional per-adapter metadata that install and traffic code derive
// their harness lists from, so adding an adapter needs no edits elsewhere.
type Meta struct {
	Binary     string   // executable name, probed with `--version`
	Installer  string   // InstallerNPM | InstallerClaudeNative | "" (no verified installer)
	NPMPackage string   // npm package name when Installer is InstallerNPM
	UAPrefixes []string // lower-case User-Agent prefixes the CLI sends (none = never seen at the gateway)
	// ManagedDirs are the admin config directories (per OS) the adapter's
	// rendered files live under; halod refuses to write anywhere else.
	ManagedDirs map[OS][]string
	// ManagedFiles are single-file path.Match patterns outside ManagedDirs.
	ManagedFiles map[OS][]string
}

// Describer is implemented by adapters that publish Meta.
type Describer interface {
	Meta() Meta
}

// MetaOf returns the Meta of a registered adapter, if it publishes one.
func MetaOf(name string) (Meta, bool) {
	d, ok := registry[name].(Describer)
	if !ok {
		return Meta{}, false
	}
	return d.Meta(), true
}
