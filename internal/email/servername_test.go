package email

import (
	"testing"

	"github.com/broist/check_agent/internal/storage"
)

func TestServerNameUsesDisplayName(t *testing.T) {
	for _, test := range []struct {
		alert storage.Alert
		want  string
	}{
		{storage.Alert{AgentID: "prod-01", Hostname: "ip-10-0-0-1", DisplayName: "AcuWall éles"}, "AcuWall éles (ip-10-0-0-1)"},
		{storage.Alert{AgentID: "prod-01", Hostname: "ip-10-0-0-1"}, "ip-10-0-0-1"},
		{storage.Alert{AgentID: "prod-01", DisplayName: " "}, "prod-01"},
		{storage.Alert{AgentID: "prod-01", Hostname: "web", DisplayName: "web"}, "web"},
	} {
		if got := ServerName(test.alert); got != test.want {
			t.Errorf("ServerName(%+v) = %q, want %q", test.alert, got, test.want)
		}
	}
}
