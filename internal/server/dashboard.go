package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	Online       bool
	Fresh        bool
	Missing      bool
	Files        []filesystemView
	Issues       []string
	PackageLevel string
	Images       []imageView

	// Map card and detail panel.
	Name, Description             string
	CustomName, CustomDescription string
	Level, LevelLabel             string
	Selected, Renaming            bool
	SelectURL, RenameURL          string
	Tabs                          []tabView
	Disk                          filesystemView
	Meters                        []meterView
	Rings                         []ringView
	Mini, Chart                   chartView
	Endpoints                     []endpointView
	PageLeaves, ServiceLeaves     []leafView
	SecurityLeaves                []leafView
	SecurityCount                 string
	PagesUp                       int
	ServicesUp, ServicesTotal     int
	OpenAlerts                    []alertView
	Firing, Faults, Broken        int
	FixableCritical               int
}

type imageView struct {
	model.ImageVulnerabilities
	Level string

	Short                          string
	CritWidth, HighWidth, MedWidth float64
	HighX, MedX                    float64
	Fixable                        int
	FixClass                       string
}

// securityView derives the dashboard levels and issue lines of the
// "Biztonság" section from the latest report.
func securityView(view *serverView) {
	if packages := view.Packages; packages != nil {
		view.PackageLevel = "ok"
		if packages.Security > 0 || packages.RebootRequired || packages.Error != "" {
			view.PackageLevel = "warning"
		}
		if packages.RebootRequired {
			issue := "Újraindítás szükséges a telepített frissítések miatt"
			if len(packages.RebootPackages) > 0 {
				issue += " (" + strings.Join(packages.RebootPackages, ", ") + ")"
			}
			view.Issues = append(view.Issues, issue+". Karbantartási ablakban: sudo reboot.")
		}
	}
	if view.Vulnerabilities == nil {
		return
	}
	for _, image := range view.Vulnerabilities.Images {
		item := imageView{ImageVulnerabilities: image, Level: "ok"}
		switch {
		case image.FixableCritical > 0:
			item.Level = "critical"
			view.Issues = append(view.Issues, fmt.Sprintf(
				"Javítható kritikus CVE: %s (%d db). Frissítsd a képet vagy az alapképét, majd telepítsd újra a konténert.",
				image.Image, image.FixableCritical))
		case image.FixableHigh > 0 || image.FixableMedium > 0 || image.Error != "":
			item.Level = "warning"
		}
		view.Images = append(view.Images, item)
	}
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
		securityView(&view)
		if interval := report.Timestamp.Sub(previous.Timestamp); !previous.Timestamp.IsZero() && interval > 0 &&
			(data.ReportEvery == 0 || interval < data.ReportEvery) {
			data.ReportEvery = interval.Round(time.Second)
		}
		data.Reports = append(data.Reports, view)
	}
	for _, agent := range s.cfg.AgentTokens {
		if !present[agent.AgentID] {
			data.Reports = append(data.Reports, serverView{Report: model.Report{AgentID: agent.AgentID, Hostname: agent.AgentID}, Missing: true})
			present[agent.AgentID] = true
		}
	}
	return data, s.mapView(ctx, &data)
}

// mapView adds the infrastructure map, the detail panels, the status line
// and the timeline to the dashboard data.
func (s *Server) mapView(ctx context.Context, data *dashboardData) error {
	now := time.Now()
	labels, err := s.store.AgentLabels(ctx)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(data.Reports))
	for _, view := range data.Reports {
		ids = append(ids, view.AgentID)
	}
	metrics, availability, err := s.recentHistory(ctx, ids, now)
	if err != nil {
		return err
	}
	names := make(map[string]string, len(data.Reports))
	status := statusView{HostsTotal: len(data.Reports), HostsUp: data.OnlineCount}
	onlySecurity := true
	for i := range data.Reports {
		view := &data.Reports[i]
		decorateImages(view)
		s.decorate(view, labels[view.AgentID], data.Alerts, metrics[view.AgentID], availability[view.AgentID], now)
		names[view.AgentID] = view.Name
		for _, image := range view.Images {
			view.FixableCritical += image.FixableCritical
		}
		status.PagesUp += view.PagesUp
		status.PagesTotal += len(view.HTTPChecks)
		status.OpenAlerts += view.Firing
		if view.Level == "bad" {
			status.Down++
		}
		for _, alert := range view.OpenAlerts {
			if alert.State == "firing" && !securityRules[alert.RuleKey] {
				onlySecurity = false
			}
		}
	}
	switch {
	case status.Down > 0:
		status.Emphasis = fmt.Sprintf("%d gépen hiba van", status.Down)
		status.Detail = "A pirossal jelölt gépre kattintva látod, mi nem működik."
	case status.OpenAlerts > 0:
		status.Lead = "Minden fut — "
		status.Emphasis = fmt.Sprintf("%d dolog figyelmet kér", status.OpenAlerts)
		status.Detail = "Leállás nincs. A nyitott tételek részletei a gépekre kattintva láthatók."
		if onlySecurity {
			status.Detail = "Leállás nincs. A nyitott tételek a biztonsági vizsgálatból jönnek — részletek a gépekre kattintva."
		}
	case len(data.Reports) == 0:
		status.Lead, status.Detail = "Még nincs csatlakoztatott gép", "Az első agent jelentése után itt jelennek meg a mérések."
	default:
		status.Lead, status.Detail = "Minden rendben", "Nincs nyitott riasztás."
	}
	data.Status = status
	history, err := s.store.TimelineAlerts(ctx, now.Add(-timelineWindow), timelineLimit)
	if err != nil {
		return err
	}
	data.Timeline = buildTimeline(history, names, "all", now)
	data.Hub = publicHost(s.cfg.PublicURL)
	data.HubInterval = reportInterval(data.ReportEvery)
	data.UpdatedAt = now.Local().Format("15:04")
	applyState(data, viewState{})
	return nil
}

func levelRank(level string) int {
	switch level {
	case "bad":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

// applyState marks the selected machine, detail tab and timeline filter.
func applyState(data *dashboardData, state viewState) {
	selected := ""
	for _, view := range data.Reports {
		if view.AgentID == state.Agent {
			selected = view.AgentID
		}
	}
	if selected == "" {
		rank := -1
		for _, view := range data.Reports {
			if levelRank(view.Level) > rank {
				selected, rank = view.AgentID, levelRank(view.Level)
			}
		}
	}
	tab := "ov"
	for _, item := range panelTabs {
		if item.Key == state.Tab {
			tab = item.Key
		}
	}
	filter := "all"
	filters := []filterView{{Key: "all", Label: "Mind"}, {Key: "open", Label: "Nyitott"}, {Key: "done", Label: "Megoldott"}}
	for _, view := range data.Reports {
		filters = append(filters, filterView{Key: "agent:" + view.AgentID, Label: view.Name})
	}
	for _, item := range filters {
		if item.Key == state.Filter {
			filter = item.Key
		}
	}
	for i := range filters {
		filters[i].On = filters[i].Key == filter
		filters[i].URL = state.url(selected, tab, filters[i].Key, false) + "#mi-tortent"
	}
	data.Filters, data.Selected, data.Tab, data.Filter = filters, selected, tab, filter
	for i := range data.Reports {
		view := &data.Reports[i]
		view.Selected = view.AgentID == selected
		view.Renaming = view.Selected && state.Rename
		view.SelectURL = state.url(view.AgentID, "", filter, false)
		view.RenameURL = state.url(view.AgentID, tab, filter, true) + "#atnevezes-" + view.AgentID
		view.Tabs = view.Tabs[:0]
		for _, item := range panelTabs {
			count := 0
			if item.Key == "al" {
				count = len(view.OpenAlerts)
			}
			view.Tabs = append(view.Tabs, tabView{Key: item.Key, Label: item.Label, Count: count,
				On: item.Key == tab, URL: state.url(view.AgentID, item.Key, filter, false)})
		}
	}
	data.TimelineEmpty = true
	for d := range data.Timeline {
		day := &data.Timeline[d]
		day.Hidden = true
		for e := range day.Events {
			day.Events[e].Hidden = !matchesFilter(day.Events[e], filter)
			if !day.Events[e].Hidden {
				day.Hidden, data.TimelineEmpty = false, false
			}
		}
	}
}
