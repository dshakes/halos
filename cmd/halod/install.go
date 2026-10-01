package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dshakes/halos/internal/release"
)

// maxArtifactBytes caps a download whose manifest gives no exact size.
// Claude's native binaries are ~240MB.
const maxArtifactBytes = 512 << 20

// join joins target paths for the configured OS (paths are target-OS strings,
// mapped onto the host by a.path).
func (a *Agent) join(elem ...string) string {
	if a.Cfg.OS == "windows" {
		return strings.Join(elem, `\`)
	}
	return strings.Join(elem, "/")
}

func (a *Agent) lay() layout { return layouts[a.Cfg.OS] }

// artifactID identifies installed bytes (loop guard in state.json).
func artifactID(art release.Artifact) string {
	if art.SHA256 != "" {
		return "sha256:" + art.SHA256
	}
	return art.Integrity
}

// ensureHarness installs he.Version if the installed version differs. Order:
// verified artifact; else legacy installCommand only with allowShellInstall.
func (a *Agent) ensureHarness(ctx context.Context, name string, he release.HarnessEntry, prev State, next *State) (HarnessStatus, error) {
	art, hasArt := he.ArtifactFor(a.Cfg.OS, a.Arch)
	hs := HarnessStatus{Want: he.Version, Installed: a.installedVersion(ctx, name, art, hasArt)}
	if hasArt && prev.Installed[name] != "" {
		next.Installed[name] = prev.Installed[name]
	}
	if !a.Install || he.Version == "" || hs.Installed == he.Version {
		return hs, nil
	}
	if !hasArt {
		cmd := he.InstallCommand[a.Cfg.OS]
		if !a.Cfg.AllowShellInstall || cmd == "" {
			return hs, fmt.Errorf("no verified install artifact for %s-%s (legacy installCommand needs allowShellInstall: true)", a.Cfg.OS, a.Arch)
		}
		a.log().Warn("allowShellInstall is on; running unverified installCommand as root", "harness", name, "cmd", cmd)
		if err := a.runInstall(ctx, cmd); err != nil {
			return hs, err
		}
		hs.Installed = a.installedVersion(ctx, name, art, false)
		return hs, nil
	}
	// Loop guard: these exact verified bytes are already in place but the
	// version probe disagrees (e.g. odd --version output). Re-downloading
	// every cycle would not change anything.
	if prev.Installed[name] == artifactID(art) && a.managedPresent(art) {
		a.log().Warn("verified artifact already installed but reports a different version; not reinstalling",
			"harness", name, "artifact", artifactID(art), "reported", hs.Installed)
		return hs, nil
	}
	if err := a.installArtifact(ctx, art); err != nil {
		return hs, err
	}
	next.Installed[name] = artifactID(art)
	hs.Installed = a.installedVersion(ctx, name, art, true)
	return hs, nil
}

func (a *Agent) managedBin(art release.Artifact) string {
	return a.join(a.lay().Bin, art.BinPath)
}

func (a *Agent) npmPackageJSON(art release.Artifact) string {
	if a.Cfg.OS == "windows" {
		return a.join(a.lay().NPM, "node_modules", filepath.FromSlash(art.Package), "package.json")
	}
	return a.join(a.lay().NPM, "lib", "node_modules", art.Package, "package.json")
}

func (a *Agent) managedPresent(art release.Artifact) bool {
	p := a.managedBin(art)
	if art.Kind == release.KindNPMTgz {
		p = a.npmPackageJSON(art)
	}
	_, err := os.Stat(a.path(p))
	return err == nil
}

// installedVersion probes absolute, known paths only; it never relies on the
// service's PATH (launchd/systemd PATH differs from the user's). npm packages
// are read from package.json, since their bin shims need `node` on PATH.
func (a *Agent) installedVersion(ctx context.Context, name string, art release.Artifact, hasArt bool) string {
	if hasArt && art.Kind == release.KindNPMTgz {
		b, err := os.ReadFile(a.path(a.npmPackageJSON(art)))
		if err != nil {
			return ""
		}
		var pj struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &pj) != nil {
			return ""
		}
		return pj.Version
	}
	var candidates []string
	if hasArt {
		candidates = []string{a.managedBin(art)}
	} else if bin, ok := binaryFor(name); ok {
		candidates = []string{a.join(a.lay().Bin, bin)}
		if a.Cfg.OS != "windows" {
			candidates = append(candidates, "/usr/local/bin/"+bin, "/opt/homebrew/bin/"+bin, "/usr/bin/"+bin)
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(a.path(c)); err != nil {
			continue
		}
		out, err := a.Run(ctx, a.path(c), "--version")
		if err != nil {
			return ""
		}
		return versionRe.FindString(string(out))
	}
	return ""
}

// installArtifact downloads, verifies and installs art. Nothing is placed
// unless the hash matches.
func (a *Agent) installArtifact(ctx context.Context, art release.Artifact) error {
	if err := art.Validate(); err != nil {
		return err
	}
	if b := strings.TrimSuffix(art.BinPath, ".exe"); b == "halod" {
		return errors.New("artifact binPath may not replace halod")
	}
	lay := a.lay()
	root := a.path(lay.Bin)
	if art.Kind == release.KindNPMTgz {
		root = a.path(lay.NPM)
	}
	if err := mkdirManaged(root); err != nil {
		return err
	}
	if err := checkChain(root); err != nil {
		return fmt.Errorf("install dir: %w", err)
	}
	tmp, err := os.MkdirTemp(root, ".halod-dl-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // scratch dir; leftovers are harmless
	file := filepath.Join(tmp, "artifact")
	if art.Kind == release.KindNPMTgz {
		file += ".tgz" // npm treats a *.tgz path as a local tarball
	}
	if err := a.download(ctx, art, file); err != nil {
		return err
	}
	switch art.Kind {
	case release.KindBinary:
		if err := os.Chmod(file, 0o755); err != nil { //nolint:gosec // verified vendor binary must be executable
			return err
		}
		dst := a.path(a.managedBin(art))
		if err := os.Rename(file, dst); err != nil { // same dir tree: atomic
			return fmt.Errorf("place %s: %w", dst, err)
		}
		a.shim(art.BinPath, a.managedBin(art))
	case release.KindNPMTgz:
		if err := a.npmInstall(ctx, tmp, file); err != nil {
			return err
		}
		a.shim(art.BinPath, a.join(lay.NPM, "bin", art.BinPath))
	}
	return nil
}

// download streams art.URL (https only, redirects included) into dst, capped
// at art.Size (or maxArtifactBytes), and verifies sha256 and/or sha512.
func (a *Agent) download(ctx context.Context, art release.Artifact, dst string) error {
	c := *a.Download
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return fmt.Errorf("refusing redirect to %s", r.URL)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, art.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", art.URL, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: status %d", art.URL, resp.StatusCode)
	}
	limit := int64(maxArtifactBytes)
	if art.Size > 0 {
		limit = art.Size
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Sync below reports write errors; a failed download is discarded
	s256, s512 := sha256.New(), sha512.New()
	n, err := io.Copy(io.MultiWriter(f, s256, s512), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", art.URL, err)
	}
	if n > limit || (art.Size > 0 && n != art.Size) {
		return fmt.Errorf("download %s: size %d, want %d (limit %d)", art.URL, n, art.Size, limit)
	}
	if art.SHA256 != "" && hex.EncodeToString(s256.Sum(nil)) != art.SHA256 {
		return fmt.Errorf("download %s: sha256 mismatch", art.URL)
	}
	if art.Integrity != "" && "sha512-"+base64.StdEncoding.EncodeToString(s512.Sum(nil)) != art.Integrity {
		return fmt.Errorf("download %s: sha512 integrity mismatch", art.URL)
	}
	return f.Sync()
}

// nodeCandidates are root-owned node installs (nodejs.org pkg / distro).
// Homebrew is deliberately absent: /opt/homebrew is user-writable, and root
// must not execute user-replaceable code.
var nodeCandidates = map[string][][2]string{ // os -> {node, npm-cli.js}
	"darwin": {{"/usr/local/bin/node", "/usr/local/lib/node_modules/npm/bin/npm-cli.js"}},
	"linux": {
		{"/usr/bin/node", "/usr/lib/node_modules/npm/bin/npm-cli.js"},
		{"/usr/bin/node", "/usr/share/nodejs/npm/bin/npm-cli.js"},
		{"/usr/local/bin/node", "/usr/local/lib/node_modules/npm/bin/npm-cli.js"},
	},
	"windows": {{`C:\Program Files\nodejs\node.exe`, `C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js`}},
}

// npmInstall runs `node npm-cli.js install -g --ignore-scripts` on the
// verified local tarball with empty user/global npmrc, so no user-writable
// config (registry, scripts, prefix) is read and no lifecycle script runs.
// Transitive dependencies are still resolved by npm from the public registry.
func (a *Agent) npmInstall(ctx context.Context, tmp, tgz string) error {
	var node, cli string
	for _, c := range nodeCandidates[a.Cfg.OS] {
		n, c1 := a.path(c[0]), a.path(c[1])
		if _, err := os.Stat(c1); err != nil {
			continue
		}
		rn, err1 := filepath.EvalSymlinks(n)
		rc, err2 := filepath.EvalSymlinks(c1)
		if err1 != nil || err2 != nil {
			continue
		}
		if err := checkChain(rn); err != nil {
			return fmt.Errorf("node: %w", err)
		}
		if err := checkChain(rc); err != nil {
			return fmt.Errorf("npm: %w", err)
		}
		node, cli = rn, rc
		break
	}
	if node == "" {
		return errors.New("npm-tgz install needs a root-owned node/npm (nodejs.org installer or distro package); none found")
	}
	// Two distinct files: npm refuses one path as both user and global config
	// ("double-loading config ... as global, previously loaded as user").
	userRC, globalRC := filepath.Join(tmp, "empty-user-npmrc"), filepath.Join(tmp, "empty-global-npmrc")
	for _, f := range []string{userRC, globalRC} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			return err
		}
	}
	out, err := a.Run(ctx, node, cli, "install", "--global", "--ignore-scripts", "--no-audit", "--no-fund",
		"--userconfig", userRC, "--globalconfig", globalRC, "--prefix", a.path(a.lay().NPM), tgz)
	if err != nil {
		return fmt.Errorf("npm install: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// shim points <Shim>/<name> at target when that slot is free or already ours.
// It never replaces a foreign file, and skips untrusted (user-owned) shim dirs.
func (a *Agent) shim(name, target string) {
	dir := a.lay().Shim
	if dir == "" {
		return
	}
	link, tgt := a.path(a.join(dir, name)), a.path(target)
	if err := checkChain(filepath.Dir(link)); err != nil {
		a.log().Warn("not linking shim", "link", link, "err", err)
		return
	}
	if fi, err := os.Lstat(link); err == nil {
		cur, _ := os.Readlink(link)
		ours := strings.HasPrefix(cur, a.path(a.lay().Bin)) || strings.HasPrefix(cur, a.path(a.lay().NPM))
		if fi.Mode()&fs.ModeSymlink == 0 || !ours {
			a.log().Warn("shim path exists and is not managed by halod; leaving it", "link", link)
			return
		}
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		a.log().Warn("shim", "link", link, "err", err)
		return
	}
	tmp := link + ".halod-new"
	_ = os.Remove(tmp)
	if err := os.Symlink(tgt, tmp); err != nil {
		a.log().Warn("shim", "link", link, "err", err)
		return
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		a.log().Warn("shim", "link", link, "err", err)
	}
}
