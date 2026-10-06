package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/broist/check_agent/internal/alerts"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

type filesystemView struct {
	model.Filesystem
	Level  string
	Change string
}

type serverView struct {
	model.Report
	Online  bool
	Fresh   bool
	Missing bool
	Files   []filesystemView
	Issues  []string
}

func formatBytes(value uint64) string {
	number := float64(value)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for number >= 1024 && i < len(units)-1 {
		number /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", number, units[i])
}

func (s *Server) dashboardView(ctx context.Context, reports []model.Report, active []storage.Alert) (dashboardData, error) {
	data := dashboardData{Alerts: active, SMTPReady: s.cfg.SMTP.Enabled, SMTPAddress: s.cfg.SMTP.Address}
	var err error
	data.Preferences, err = s.notificationPreferences(ctx)
	if err != nil {
		return data, err
	}
	lastSeen, err := s.store.AgentLastSeen(ctx)
	if err != nil {
		return data, err
	}
	seen := make(map[string]time.Time)
	present := make(map[string]bool)
	for _, agent := range lastSeen {
		seen[agent.AgentID] = agent.LastSeen
	}
	for i, alert := range data.Alerts {
		for _, report := range reports {
			if alert.AgentID == report.AgentID {
				data.Alerts[i] = alerts.WithReport(alert, report)
				break
			}
		}
	}
	for _, alert := range active {
		if alert.State == "firing" && alert.Severity == "critical" {
			data.CriticalCount++
		}
	}
	sort.SliceStable(data.Alerts, func(i, j int) bool {
		a, b := data.Alerts[i], data.Alerts[j]
		if a.State != b.State {
			return a.State == "firing"
		}
		return a.Severity == "critical" && b.Severity != "critical"
	})
	for _, report := range reports {
		present[report.AgentID] = true
		view := serverView{Report: report, Online: time.Since(seen[report.AgentID]) <= s.cfg.AgentOfflineAfter, Fresh: time.Since(report.Timestamp) <= s.cfg.AgentOfflineAfter}
		if view.Online {
			data.OnlineCount++
		}
		previous, err := s.store.PreviousReport(ctx, report.AgentID, report.Timestamp)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return data, err
		}
		for _, fs := range report.Filesystems {
			if !fs.Monitorable() {
				continue
			}
			item := filesystemView{Filesystem: fs, Level: "ok", Change: "Nincs összehasonlítható korábbi mérés"}
			if fs.UsedPercent > s.cfg.DiskCriticalThreshold {
				item.Level = "critical"
			} else if fs.UsedPercent > s.cfg.DiskWarningThreshold {
				item.Level = "warning"
			}
			for _, old := range previous.Filesystems {
				if old.Mountpoint != fs.Mountpoint || old.Device != fs.Device || old.TotalBytes != fs.TotalBytes {
					continue
				}
				elapsed := formatHungarianDuration(report.Timestamp.Sub(previous.Timestamp))
				item.Change = "Változatlan · " + elapsed
				if fs.UsedBytes > old.UsedBytes {
					item.Change = "+" + formatBytes(fs.UsedBytes-old.UsedBytes) + " · " + elapsed
				}
				if fs.UsedBytes < old.UsedBytes {
					item.Change = "−" + formatBytes(old.UsedBytes-fs.UsedBytes) + " · " + elapsed
				}
				break
			}
			view.Files = append(view.Files, item)
			data.DiskCount++
		}
		sort.SliceStable(view.Files, func(i, j int) bool { return view.Files[i].UsedPercent > view.Files[j].UsedPercent })
		for _, service := range report.Services {
			if service.ActiveState != "active" || service.Error != "" {
				view.Issues = append(view.Issues, "Szolgáltatás: "+service.Name+" · "+labelServiceState(service.ActiveState)+" "+service.Error)
			}
		}
		if report.Docker.Enabled && !report.Docker.Available {
			view.Issues = append(view.Issues, "A Docker állapota nem ellenőrizhető. Ellenőrizd az agent hozzáférését a Docker sockethez. "+report.Docker.Error)
		}
		for _, c := range report.Docker.Containers {
			if c.State != "running" || c.Health == "unhealthy" {
				view.Issues = append(view.Issues, "Konténer: "+c.Name+" · "+labelContainerState(c.State)+" / "+labelContainerState(c.Health))
			}
		}
		for _, check := range report.HTTPChecks {
			if !check.OK {
				view.Issues = append(view.Issues, "Webes végpont: "+check.Name+" · "+check.URL+" · "+check.Error)
			}
		}
		for _, check := range report.TCPChecks {
			if !check.Reachable {
				view.Issues = append(view.Issues, "TCP-kapcsolat sikertelen: "+check.Address+". Ellenőrizd a szolgáltatás portját és a tűzfalat. "+check.Error)
			}
		}
		data.Reports = append(data.Reports, view)
	}
	for _, agent := range s.cfg.AgentTokens {
		if !present[agent.AgentID] {
			data.Reports = append(data.Reports, serverView{Report: model.Report{AgentID: agent.AgentID, Hostname: agent.AgentID}, Missing: true})
			present[agent.AgentID] = true
		}
	}
	return data, nil
}
