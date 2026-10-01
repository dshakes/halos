package mdm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"howett.net/plist"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

var update = flag.Bool("update", false, "rewrite golden files")

type ad struct{}

func (ad) Name() string                             { return "claude-code" }
func (ad) Capabilities() []harness.Capability       { return nil }
func (ad) InstallCommand(string, harness.OS) string { return "" }
func (ad) Render(_ *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	p := "/Library/Application Support/ClaudeCode/managed-settings.json"
	if c.OS == harness.Windows {
		p = `C:\Program Files\ClaudeCode\managed-settings.json`
	}
	return []harness.File{{Path: p, Mode: 0o644, Data: []byte(`{"model":"opus","cleanupPeriodDays":30,"requiredMinimumVersion":"2.1.0","requiredMaximumVersion":"2.1.0","permissions":{"deny":["Bash(rm -rf:*)"]},"env":{"X":"it's"}}`)}}, nil, nil
}

type res struct{}

func (res) ResolveProfile(string) (*policy.Profile, error) {
	return &policy.Profile{Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.1.0"}}}, nil
}

func init() { harness.Register(ad{}) }

var okVerify Verifier = func(*release.Release) error { return nil }

// fixed seed => deterministic golden output
func testOpts() HalodOptions {
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	h := strings.Repeat("ab", 32)
	return HalodOptions{
		Registry: "ghcr.io/a/r", Org: "acme", Ring: "canary", DownloadURL: "https://d/{os}-{arch}/halod",
		PubKeyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		HalodSHA256: map[string]string{"darwin/arm64": h, "darwin/amd64": h, "windows/arm64": h, "windows/amd64": h},
	}
}

func rel(t *testing.T) *release.Release {
	t.Helper()
	r, err := release.Build(res{}, "p", "canary", release.Options{Org: "acme", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := "testdata/" + name
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from golden (run -update):\n%s", name, got)
	}
}

func TestJamf(t *testing.T) {
	r := rel(t)
	out, err := ExportJamf(r, okVerify)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if _, err := plist.Unmarshal(out, &root); err != nil {
		t.Fatalf("plist does not parse: %v", err)
	}
	pc := root["PayloadContent"].([]any)[0].(map[string]any)
	if pc["PayloadType"] != PlistDomain || pc["model"] != "opus" || pc["cleanupPeriodDays"] != uint64(30) {
		t.Fatalf("payload: %v", pc)
	}
	again, _ := ExportJamf(r, okVerify)
	if !bytes.Equal(out, again) {
		t.Fatal("not deterministic")
	}
	golden(t, "claudecode.mobileconfig", out)
	pi, err := JamfPostinstall(testOpts())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "postinstall.sh", pi)
	f := t.TempDir() + "/pi.sh"
	os.WriteFile(f, pi, 0o644)
	if b, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, b)
	}
	s := string(pi)
	for _, want := range []string{"shasum -a 256 -c", "/Library/Halos/bin/halod", "-o 0 -g 0 -m 0644", "org: acme", "/Library/Halos/var/state.json", "<<'CFG'", "<<'PUB'", "BEGIN PUBLIC KEY"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"/usr/local/bin", "release.pub -o", "<<CFG"} {
		if strings.Contains(s, bad) {
			t.Errorf("unexpected %q", bad)
		}
	}
	if b, err := exec.Command("shellcheck", "-s", "bash", f).CombinedOutput(); err != nil && !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("shellcheck: %v\n%s", err, b)
	}
}

func TestIntune(t *testing.T) {
	out, err := ExportIntune(rel(t), testOpts(), okVerify)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`HKLM:\SOFTWARE\Policies\ClaudeCode`, "-Name 'Settings'", "-PropertyType String", `"model":"opus"`, "halod.exe", "Get-FileHash -Algorithm SHA256", "throw \"halod sha256 mismatch", `icacls $d /setowner '*S-1-5-32-544'`, `/grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'`, `Lock-Dir 'C:\ProgramData\OpenAI\Codex'`, `Lock-Dir 'C:\ProgramData\gemini-cli'`, `\var\state.json`, "org: acme", `C:\Program Files\Halos`, "-Principal $principal", "@'"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	golden(t, "intune.ps1", out)
	if strings.Contains(s, "Invoke-WebRequest -UseBasicParsing -Uri 'https://k") || strings.Count(s, "Invoke-WebRequest") != 1 {
		t.Error("pubkey must not be downloaded")
	}
}

func TestInjectionRejected(t *testing.T) {
	bad := []string{"$(id)", "`id`", "a'b", `a"b`, "a\nb", "a;b", "a b", "a$b", "A", "-x", "", strings.Repeat("a", 64)}
	for _, v := range bad {
		if ValidateName(v) == nil {
			t.Errorf("ring %q accepted", v)
		}
		o := testOpts()
		o.Ring = v
		if _, err := JamfPostinstall(o); err == nil {
			t.Errorf("jamf accepted ring %q", v)
		}
		if _, err := ExportIntune(rel(t), o, okVerify); err == nil {
			t.Errorf("intune accepted ring %q", v)
		}
	}
	for _, v := range []string{"$(id)", "`id`", "a'b", `a"b`, "a\nb", "a;b", "a b", "a$b"} {
		for _, mut := range []func(*HalodOptions){
			func(o *HalodOptions) { o.Registry = "ghcr.io/" + v },
			func(o *HalodOptions) { o.DownloadURL = "https://d/" + v },
		} {
			o := testOpts()
			mut(&o)
			if _, err := JamfPostinstall(o); err == nil {
				t.Errorf("jamf accepted %q", v)
			}
			if _, err := ExportIntune(rel(t), o, okVerify); err == nil {
				t.Errorf("intune accepted %q", v)
			}
		}
	}
}

func TestOptionsRequired(t *testing.T) {
	for name, mut := range map[string]func(*HalodOptions){
		"no sha":     func(o *HalodOptions) { o.HalodSHA256 = nil },
		"bad sha":    func(o *HalodOptions) { o.HalodSHA256["darwin/arm64"] = "zz" },
		"http url":   func(o *HalodOptions) { o.DownloadURL = "http://d/halod" },
		"no org":     func(o *HalodOptions) { o.Org = "" },
		"bad org":    func(o *HalodOptions) { o.Org = "$(id)" },
		"no pem":     func(o *HalodOptions) { o.PubKeyPEM = "" },
		"url as pem": func(o *HalodOptions) { o.PubKeyPEM = "https://k/pub" },
	} {
		o := testOpts()
		mut(&o)
		if _, err := JamfPostinstall(o); err == nil {
			t.Errorf("%s: jamf accepted", name)
		}
	}
	o := testOpts()
	delete(o.HalodSHA256, "windows/arm64")
	if _, err := ExportIntune(rel(t), o, okVerify); err == nil {
		t.Error("intune accepted missing sha")
	}
}

func TestUnverifiedRefused(t *testing.T) {
	r := rel(t)
	if _, err := ExportJamf(r, nil); err == nil {
		t.Error("nil verifier accepted")
	}
	if _, err := ExportIntune(r, testOpts(), func(*release.Release) error { return errors.New("bad sig") }); err == nil {
		t.Error("failed verification accepted")
	}
}

func TestMissingHarness(t *testing.T) {
	r := rel(t)
	delete(r.Manifest.Harnesses, "claude-code")
	if _, err := ExportJamf(r, okVerify); err == nil {
		t.Fatal("want error")
	}
	if _, err := ExportIntune(r, HalodOptions{}, okVerify); err == nil {
		t.Fatal("want error")
	}
}
