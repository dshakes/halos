package harness_test

import (
	"reflect"
	"testing"

	"github.com/halos-dev/halos/internal/harness"
	_ "github.com/halos-dev/halos/internal/harness/all"
)

func TestMatrix(t *testing.T) {
	m := harness.Matrix()
	want := map[string][]harness.Capability{
		"claude-code": {harness.CapVersionPin, harness.CapModelLock, harness.CapMCPAllowlist, harness.CapHooksLock, harness.CapPermissions, harness.CapGateway, harness.CapTelemetry, harness.CapInstructions, harness.CapHeaders},
		"codex":       {harness.CapModelLock, harness.CapGateway, harness.CapHeaders, harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions},
		"gemini-cli":  {harness.CapModelLock, harness.CapMCPAllowlist, harness.CapTelemetry, harness.CapGateway},
		"copilot-cli": {harness.CapTelemetry, harness.CapMCPAllowlist, harness.CapPermissions},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("matrix = %v", m)
	}
	if got := harness.Names(); len(got) != 4 {
		t.Errorf("names = %v", got)
	}
}
