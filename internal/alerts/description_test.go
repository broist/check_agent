package alerts

import (
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
	"strings"
	"testing"
)

func TestActionableDescription(t *testing.T) {
	disk := Describe(storage.Alert{RuleKey: "disk_critical", Resource: "/srv/customer's data", Value: 97, Threshold: 95})
	if !strings.Contains(disk.Action, "'/srv/customer'\"'\"'s data'") || !strings.Contains(disk.Measurement, "97.0%") {
		t.Fatalf("unsafe or missing path: %+v", disk)
	}
	alert := WithReport(storage.Alert{AgentID: "web", RuleKey: "http_failed", Resource: "health"}, model.Report{Hostname: "web-production", HTTPChecks: []model.HTTPStatus{{Name: "health", URL: "https://example.test/health"}}})
	if alert.Hostname != "web-production" || alert.Resource != "health" || !strings.Contains(Describe(alert).Measurement, "https://example.test/health") {
		t.Fatalf("missing endpoint context: %+v", alert)
	}
}
