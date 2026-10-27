package supplychain

import (
	"testing"
)

// The extensions Halos itself ships scan clean, or carry a suppression with a
// reason here. Suppressions are keyed by file sha256 like allowFindings, so
// editing a suppressed file needs a fresh human look: re-run
// `halo artifact scan <dir>` and update the digest below.
func TestShippedExtensionsScan(t *testing.T) {
	const invariant1 = "states AGENTS.md invariant 1 as a prohibition (\"never emit bypassPermissions\"); it is the rule, not a bypass"
	allow := map[[2]string]string{ // {file sha256, rule} -> reason
		{"e7200bf8bd28916c2f903e333c36e5e7a526e26213fb03622e59963289df94f8", "permission-bypass"}: invariant1, // skills/halos-author-policy/SKILL.md
		{"c4e0ee439078c72b2bea12813bc4524ac16386391fba396fc463dede64e4e187", "permission-bypass"}: invariant1, // skills/halos-autopilot/SKILL.md
		{"f581ee4da3ee734f8c952d2197d84bfa8f60d245fc38994fdd676fcca5f8103b", "permission-bypass"}: invariant1, // skills/halos-onboard/SKILL.md
		{"370acf030f6b1d7d086970a70b6ce5ca2185ad107d2e30b6882ef31ef585afdf", "permission-bypass"}: invariant1, // skills/halos-rollout/SKILL.md
	}
	used := map[[2]string]bool{}
	for _, dir := range []string{"../../plugins/claude-code", "../../examples/acme-corp/artifacts"} {
		tr, err := ReadPath(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		sums := tr.Sums()
		for _, f := range Scan(tr) {
			k := [2]string{sums[f.Path], f.Rule}
			if _, ok := allow[k]; ok {
				used[k] = true
				continue
			}
			t.Errorf("%s: %s (file sha256 %s): fix it, or add a justified suppression", dir, f, sums[f.Path])
		}
	}
	for k := range allow {
		if !used[k] {
			t.Errorf("suppression %v matches nothing: the file changed or the finding is gone; re-scan and update it", k)
		}
	}
}
