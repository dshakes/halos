package copilot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/halos-dev/halos/internal/harness"
	"github.com/halos-dev/halos/internal/harness/hutil/hutiltest"
	"github.com/halos-dev/halos/internal/policy"
)

func TestRender(t *testing.T) {
	p, g := hutiltest.Fixture()
	files, warns, err := Adapter{}.Render(p, harness.Context{Gateway: g, OS: harness.Linux})
	if err != nil || len(files) != 1 || files[0].Path != "/etc/github-copilot/managed-settings.json" {
		t.Fatalf("files=%v err=%v", files, err)
	}
	var m map[string]any
	if err := json.Unmarshal(files[0].Data, &m); err != nil {
		t.Fatal(err)
	}
	if m["permissions"].(map[string]any)["disableBypassPermissionsMode"] != "disable" {
		t.Errorf("permissions = %v", m["permissions"])
	}
	if _, ok := m["allowedMcpServers"]; !ok {
		t.Error("missing allowedMcpServers")
	}
	all := strings.Join(warns, "\n")
	for _, want := range []string{"gateway not rendered", "COPILOT_PROVIDER_BASE_URL", `"models.allowed"`, "self-enforce version"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning %q in\n%s", want, all)
		}
	}
	hutiltest.Golden(t, "linux_managed-settings.json", files[0].Data)
}

func TestTelemetryGRPCWarnsNotDrops(t *testing.T) {
	p, _ := hutiltest.Fixture()
	p.Telemetry.Protocol = "grpc"
	files, warns, err := Adapter{}.Render(p, harness.Context{OS: harness.Linux})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files[0].Data), "telemetry") || !strings.Contains(strings.Join(warns, "\n"), "grpc is not supported") {
		t.Errorf("data=%s warns=%v", files[0].Data, warns)
	}
}

func TestMCPWithoutURLOrCommandErrors(t *testing.T) {
	p, _ := hutiltest.Fixture()
	p.MCP.Servers = []policy.MCPServer{{Name: "x"}}
	if _, _, err := (Adapter{}).Render(p, harness.Context{OS: harness.Linux}); err == nil {
		t.Error("want error")
	}
}
