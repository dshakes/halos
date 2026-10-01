package devcontainer

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/release"
)

const pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n"

var sha = strings.Repeat("ab", 32)

func TestExport(t *testing.T) {
	out, err := Export(nil, Options{Registry: "ghcr.io/a/r", Org: "acme", Ring: "canary", PubKeyPEM: pem, HalodSHA256: sha}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ID         string
		Entrypoint string
		Options    map[string]struct{ Default any }
		CapAdd     []string
	}
	if err := json.Unmarshal(out["devcontainer-feature.json"], &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != "halos" || doc.Options["registry"].Default != "ghcr.io/a/r" || doc.Options["ring"].Default != "canary" ||
		doc.Options["halodSha256"].Default != sha || !strings.HasPrefix(doc.Options["pubkeyPem"].Default.(string), "-----BEGIN PUBLIC KEY-----\\n") {
		t.Fatalf("defaults not applied: %+v", doc)
	}
	if _, ok := doc.Options["pubkeySha256"]; !ok {
		t.Fatal("pubkeySha256 option missing")
	}
	if doc.Entrypoint != "/usr/local/bin/halos-init-firewall" {
		t.Fatalf("firewall must start via entrypoint, got %q", doc.Entrypoint)
	}
	if len(doc.CapAdd) != 2 {
		t.Fatal("NET_ADMIN/NET_RAW must be declared")
	}
	inst := string(out["install.sh"])
	for _, want := range []string{"halod once --install", "sha256sum -c", "shasum -a 256 -c", "'halodSha256' option is required", "requires 'pubkeySha256'"} {
		if !strings.Contains(inst, want) {
			t.Errorf("install.sh missing %q", want)
		}
	}
	if strings.Contains(inst, "\n  /usr/local/bin/halos-init-firewall\n") {
		t.Error("install.sh must not run the firewall at build")
	}
	fw := string(out["init-firewall.sh"])
	for _, want := range []string{"ipset", "ip6tables", "pkg-containers.githubusercontent.com", "/etc/resolv.conf", "swap"} {
		if !strings.Contains(fw, want) {
			t.Errorf("init-firewall.sh missing %q", want)
		}
	}
	for n, b := range out {
		if !strings.HasSuffix(n, ".sh") {
			continue
		}
		if o, err := exec.Command("bash", "-c", "bash -n <<'EOF'\n"+string(b)+"\nEOF").CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v %s", n, err, o)
		}
	}
}

func TestExportRefusals(t *testing.T) {
	good := Options{PubKeyPEM: pem, HalodSHA256: sha}
	if _, err := Export(nil, Options{PubKeyPEM: "https://k/pub", HalodSHA256: sha}, nil); err == nil {
		t.Error("URL pubkey accepted")
	}
	if _, err := Export(nil, Options{PubKeyPEM: pem}, nil); err == nil {
		t.Error("missing sha accepted")
	}
	if _, err := Export(nil, Options{PubKeyPEM: pem, HalodSHA256: sha, Ring: "$(id)"}, nil); err == nil {
		t.Error("bad ring accepted")
	}
	r := &release.Release{}
	if _, err := Export(r, good, nil); err == nil {
		t.Error("nil verifier accepted")
	}
	if _, err := Export(r, good, func(*release.Release) error { return errors.New("bad sig") }); err == nil {
		t.Error("unverified release accepted")
	}
}
