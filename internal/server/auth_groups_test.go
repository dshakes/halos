package server

import (
	"slices"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// TestPolicyGroupsKeepsToggleGroups: the session (and so the enrolled device)
// keeps groups that toggle rules target; dropping them made every group-targeted
// client toggle stay off on enrolled devices (found by make uat-k8s).
func TestPolicyGroupsKeepsToggleGroups(t *testing.T) {
	org := &policy.Org{
		Identity: policy.Identity{AdminGroups: []string{"adm"}},
		Rings:    []*policy.Ring{{Membership: policy.Membership{Groups: []string{"ring-g"}}}},
		Toggles:  []*policy.Toggle{{Rules: []policy.ToggleRule{{Groups: []string{"eng-x"}}}}},
	}
	got := policyGroups(org, []string{"eng-x", "ring-g", "adm", "unrelated", "eng-x"})
	if want := []string{"eng-x", "ring-g", "adm"}; !slices.Equal(got, want) {
		t.Fatalf("policyGroups = %v, want %v", got, want)
	}
}
