package harness_test

import (
	"reflect"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all"
)

func TestMatrix(t *testing.T) {
	m := harness.Matrix()
	want := map[string][]harness.Capability{
		"claude-code": {harness.CapVersionPin, harness.CapModelLock, harness.CapMCPAllowlist, harness.CapHooksLock, harness.CapPermissions, harness.CapGateway, harness.CapTelemetry, harness.CapInstructions, harness.CapHeaders, harness.CapExtensions},
		"codex":       {harness.CapModelLock, harness.CapGateway, harness.CapHeaders, harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions, harness.CapExtensions},
		"gemini-cli":  {harness.CapModelLock, harness.CapMCPAllowlist, harness.CapTelemetry, harness.CapGateway, harness.CapExtensions},
		"copilot-cli": {harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions, harness.CapExtensions},
		"cursor-agent": {},
		"opencode":     {harness.CapModelLock, harness.CapPermissions, harness.CapGateway, harness.CapHeaders, harness.CapInstructions},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("matrix = %v", m)
	}
	if got := harness.Names(); len(got) != 6 {
		t.Errorf("names = %v", got)
	}
}
