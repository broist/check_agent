package server

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/broist/check_agent/internal/alerts"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

const (
	metricStep       = 10 * time.Minute
	historyWindow    = 24 * time.Hour
	timelineWindow   = 7 * 24 * time.Hour
	timelineLimit    = 400
	timelineMaxItems = 200
	historyCacheTTL  = time.Minute
	httpCells        = int(historyWindow / storage.HTTPBucketSize)
)

// Side panel tabs and timeline filters accepted from the query string.
var panelTabs = []struct{ Key, Label string }{
	{"ov", "Áttekintés"}, {"ep", "Oldalak"}, {"sec", "Biztonság"}, {"al", "Riasztások"},
}

// Short Hungarian alert titles of the timeline and the alert tab.
var shortRules = map[string]string{
	"vulnerability_critical":   "Javítható kritikus sérülékenység",
	"http_failed":              "Nem válaszolt egy oldal",
	"agent_offline":            "Nem érkezett adat a gépről",
	"cpu_high":                 "Tartósan magas CPU-terhelés",
	"systemd_unavailable":      "Leállt egy szolgáltatás",
	"security_updates_pending": "Biztonsági frissítés vár",
	"reboot_required":          "Újraindítás szükséges",
	"memory_high":              "Kevés a memória",
	"disk_warning":             "Telítődik a lemez",
	"disk_critical":            "Megtelt a lemez",
	"vulnerability_scan_stale": "Elavult sérülékenység-vizsgálat",
	"tls_expiring":             "Lejár a tanúsítvány",
	"docker_stopped":           "Leállt egy konténer",
	"docker_unhealthy":         "Hibás egy konténer",
}

// Firing alerts of these rules mean the machine itself has a fault.
var faultRules = map[string]bool{
	"agent_offline": true, "disk_critical": true, "http_failed": true,
	"systemd_unavailable": true, "docker_stopped": true, "docker_unhealthy": true,
}

var securityRules = map[string]bool{
	"vulnerability_critical": true, "vulnerability_scan_stale": true,
	"security_updates_pending": true, "reboot_required": true,
}

func shortRule(rule string) string {
	if label, ok := shortRules[rule]; ok {
		return label
	}
	return labelRule(rule)
}

type viewState struct {
	Agent, Tab, Filter string
	Rename             bool
}

func parseViewState(query url.Values) viewState {
	state := viewState{Agent: query.Get("agent"), Tab: query.Get("tab"), Filter: query.Get("tl"),
		Rename: query.Get("rename") == "1"}
	if !validAgentID(state.Agent) {
		state.Agent = ""
	}
	return state
}

func (v viewState) url(agent, tab, filter string, rename bool) string {
	values := url.Values{}
	if agent != "" {
		values.Set("agent", agent)
	}
	if tab != "" && tab != "ov" {
		values.Set("tab", tab)
	}
	if filter != "" && filter != "all" {
		values.Set("tl", filter)
	}
	if rename {
		values.Set("rename", "1")
	}
	if len(values) == 0 {
		return "/"
	}
	return "/?" + values.Encode()
}

type statusView struct {
	Down, Warn             int
	Lead, Emphasis, Detail string
	HostsUp, HostsTotal    int
	PagesUp, PagesTotal    int
	OpenAlerts             int
}

type meterView struct {
	Label   string
	Percent float64
	Level   string
}

type ringView struct {
	Percent  float64
	Level    string
	Circ     string
	Offset   string
	Caption  string
	Subtitle string
}

type chartView struct {
	CPULine, CPUArea, MemLine, MemArea string
	Empty                              bool
	From                               string
}

type leafView struct {
	Class, Text, Small, Title string
}

type endpointView struct {
	Name, URL, Short, Meta, Availability string
	OK                                   bool
	Cells                                []string
}

type alertView struct {
	storage.Alert
	Title, Target, Since, Action string
}

type tabView struct {
	Key, Label, URL string
	Count           int
	On              bool
}

type timelineEvent struct {
	AgentID, AgentName, Title, Resource string
	Time, Note, Duration, Level, State  string
	Count                               int
	Hidden                              bool
	started                             time.Time
	total                               time.Duration
	rule                                string
	open                                bool
}

type timelineDay struct {
	Label  string
	Hidden bool
	Events []timelineEvent
}

type filterView struct {
	Key, Label, URL string
	On              bool
}

// historyCache keeps the 24-hour series for a minute: the dashboard fragment
// is refreshed after every report, the buckets change every ten minutes.
type historyCache struct {
	mu      sync.Mutex
	expires time.Time
	metrics map[string][]storage.HistoryPoint
	http    map[string]map[string][]storage.HTTPBucket
}

func (s *Server) recentHistory(ctx context.Context, agents []string, now time.Time) (map[string][]storage.HistoryPoint, map[string]map[string][]storage.HTTPBucket, error) {
	s.history24.mu.Lock()
	defer s.history24.mu.Unlock()
	if now.Before(s.history24.expires) && s.history24.metrics != nil {
		complete := true
		for _, agent := range agents {
			if _, ok := s.history24.metrics[agent]; !ok {
				complete = false
			}
		}
		if complete {
			return s.history24.metrics, s.history24.http, nil
		}
	}
	since := now.Add(-historyWindow)
	metrics := make(map[string][]storage.HistoryPoint, len(agents))
	for _, agent := range agents {
		points, err := s.store.MetricBuckets(ctx, agent, since.Truncate(metricStep), metricStep)
		if err != nil {
			return nil, nil, err
		}
		metrics[agent] = points
	}
	availability, err := s.store.HTTPAvailability(ctx, since.Add(storage.HTTPBucketSize))
	if err != nil {
		return nil, nil, err
	}
	s.history24.metrics, s.history24.http, s.history24.expires = metrics, availability, now.Add(historyCacheTTL)
	return metrics, availability, nil
}

func levelFor(percent, warning, critical float64) string {
	switch {
	case percent >= critical:
		return "bad"
	case percent >= warning:
		return "warn"
	default:
		return "ok"
	}
}

func clampPercent(value float64) float64 {
	if math.IsNaN(value) || value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func newRing(percent float64, level, caption, subtitle string) ringView {
	const radius = 32.0
	circumference := 2 * math.Pi * radius
	percent = clampPercent(percent)
	return ringView{Percent: percent, Level: level, Caption: caption, Subtitle: subtitle,
		Circ:   strconv.FormatFloat(circumference, 'f', 2, 64),
		Offset: strconv.FormatFloat(circumference*(1-percent/100), 'f', 2, 64)}
}

// buildChart renders CPU peak and memory series as SVG path data on a
// time axis; gaps longer than two buckets break the line.
func buildChart(points []storage.HistoryPoint, start, end time.Time, width, height float64) chartView {
	chart := chartView{Empty: len(points) == 0, From: start.Local().Format("15:04")}
	if chart.Empty || !end.After(start) {
		chart.Empty = true
		return chart
	}
	span := end.Sub(start).Seconds()
	x := func(t time.Time) float64 {
		value := t.Add(metricStep/2).Sub(start).Seconds() / span * width
		return math.Max(0, math.Min(width, value))
	}
	y := func(v float64) float64 { return height - clampPercent(v)/100*(height-6) - 3 }
	number := func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
	var segments [][]storage.HistoryPoint
	for i, point := range points {
		if i == 0 || point.Timestamp.Sub(points[i-1].Timestamp) > 2*metricStep {
			segments = append(segments, nil)
		}
		segments[len(segments)-1] = append(segments[len(segments)-1], point)
	}
	paths := func(value func(storage.HistoryPoint) float64) (string, string) {
		var line, area strings.Builder
		for _, segment := range segments {
			if len(segment) == 1 {
				// A single bucket is drawn as a short flat line.
				only := segment[0]
				segment = []storage.HistoryPoint{only, {Timestamp: only.Timestamp.Add(metricStep / 2),
					CPUPercent: only.CPUPercent, MemoryPercent: only.MemoryPercent}}
			}
			first, last := x(segment[0].Timestamp), x(segment[len(segment)-1].Timestamp)
			area.WriteString("M" + number(first) + " " + number(height))
			for i, point := range segment {
				command := "L"
				if i == 0 {
					command = "M"
				}
				coordinates := number(x(point.Timestamp)) + " " + number(y(value(point)))
				line.WriteString(command + coordinates + " ")
				area.WriteString(" L" + coordinates)
			}
			area.WriteString(" L" + number(last) + " " + number(height) + "Z ")
		}
		return strings.TrimSpace(line.String()), strings.TrimSpace(area.String())
	}
	chart.CPULine, chart.CPUArea = paths(func(p storage.HistoryPoint) float64 { return p.CPUPercent })
	chart.MemLine, chart.MemArea = paths(func(p storage.HistoryPoint) float64 { return p.MemoryPercent })
	return chart
}

// availabilityCells maps 30-minute buckets onto the last 48 half hours.
func availabilityCells(buckets []storage.HTTPBucket, now time.Time) ([]string, string) {
	cells := make([]string, httpCells)
	for i := range cells {
		cells[i] = "no"
	}
	first := now.UTC().Truncate(storage.HTTPBucketSize).Add(-time.Duration(httpCells-1) * storage.HTTPBucketSize)
	var ok, fail int64
	for _, bucket := range buckets {
		index := int(bucket.Start.Sub(first) / storage.HTTPBucketSize)
		if index < 0 || index >= httpCells {
			continue
		}
		ok += bucket.OK
		fail += bucket.Fail
		switch {
		case bucket.Fail > 0:
			cells[index] = "bad"
		case bucket.OK > 0:
			cells[index] = "ok"
		}
	}
	if ok+fail == 0 {
		return cells, "—"
	}
	if fail == 0 {
		return cells, "100%"
	}
	return cells, strings.Replace(strconv.FormatFloat(float64(ok)*100/float64(ok+fail), 'f', 1, 64), ".", ",", 1) + "%"
}

var shaTag = regexp.MustCompile(`:(sha-)?[0-9a-f]{7,64}$`)

// shortImage drops the registry, repository path and commit-hash tags.
func shortImage(image string) string {
	if at := strings.Index(image, "@"); at > 0 {
		image = image[:at]
	}
	if slash := strings.LastIndex(image, "/"); slash >= 0 {
		image = image[slash+1:]
	}
	return shaTag.ReplaceAllString(image, "")
}

func shortURL(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if trimmed := strings.TrimSuffix(raw, "/"); trimmed != "" {
		return trimmed
	}
	return raw
}

// clock formats a time of the day, with the date if it is not today.
func clock(value, now time.Time) string {
	value, now = value.Local(), now.Local()
	if value.Year() == now.Year() && value.YearDay() == now.YearDay() {
		return value.Format("15:04")
	}
	return value.Format("01. 02. 15:04")
}

func dayLabel(value, now time.Time) string {
	value, now = value.Local(), now.Local()
	day := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()) }
	switch day(now).Sub(day(value)).Round(time.Hour) / (24 * time.Hour) {
	case 0:
		return "Ma"
	case 1:
		return "Tegnap"
	default:
		return value.Format("01. 02.")
	}
}

func lastedFor(value time.Duration) string {
	minutes := int(math.Max(1, math.Round(value.Minutes())))
	days, hours, rest := minutes/1440, minutes%1440/60, minutes%60
	switch {
	case days > 0 && hours > 0:
		return fmt.Sprintf("%d nap %d óráig tartott", days, hours)
	case days > 0:
		return fmt.Sprintf("%d napig tartott", days)
	case hours > 0 && rest > 0:
		return fmt.Sprintf("%d óra %d percig tartott", hours, rest)
	case hours > 0:
		return fmt.Sprintf("%d óráig tartott", hours)
	default:
		return fmt.Sprintf("%d percig tartott", rest)
	}
}

func reportInterval(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	if value < time.Minute {
		return fmt.Sprintf("%d mp-enként", int(math.Round(value.Seconds())))
	}
	return fmt.Sprintf("%d percenként", int(math.Round(value.Minutes())))
}

func agentName(label storage.AgentLabel, report model.Report) string {
	if label.DisplayName != "" {
		return label.DisplayName
	}
	if report.Hostname != "" {
		return report.Hostname
	}
	return report.AgentID
}

func agentDescription(label storage.AgentLabel, report model.Report, name string) string {
	if label.Description != "" {
		return label.Description
	}
	parts := []string{}
	for _, value := range []string{report.AgentID, report.Hostname} {
		if value != "" && value != name && (len(parts) == 0 || parts[0] != value) {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " · ")
}

// decorate derives the map card and the detail panel of one machine.
func (s *Server) decorate(view *serverView, label storage.AgentLabel, active []storage.Alert, metrics []storage.HistoryPoint, availability map[string][]storage.HTTPBucket, now time.Time) {
	view.Name = agentName(label, view.Report)
	view.Description = agentDescription(label, view.Report, view.Name)
	view.CustomName, view.CustomDescription = label.DisplayName, label.Description
	for _, alert := range active {
		if alert.AgentID != view.AgentID {
			continue
		}
		description := alerts.Describe(alert)
		target := alert.Target
		if target == "" {
			target = alert.Resource
		}
		if alert.RuleKey == "vulnerability_critical" {
			target = shortImage(target)
		}
		view.OpenAlerts = append(view.OpenAlerts, alertView{Alert: alert, Title: shortRule(alert.RuleKey),
			Target: shortURL(target), Since: clock(alert.StartedAt, now), Action: description.Action})
		if alert.State == "firing" {
			view.Firing++
			if faultRules[alert.RuleKey] {
				view.Faults++
			}
		}
	}
	for _, check := range view.HTTPChecks {
		cells, availabilityText := availabilityCells(availability[check.Name], now)
		meta := fmt.Sprintf("HTTP %d · %.0f ms", check.StatusCode, check.ResponseMS)
		if check.TLSDaysLeft != nil && *check.TLSDaysLeft > 0 {
			meta += fmt.Sprintf(" · TLS %d nap", int(math.Floor(*check.TLSDaysLeft)))
		}
		if !check.OK && check.Error != "" {
			meta += " · " + check.Error
		}
		view.Endpoints = append(view.Endpoints, endpointView{Name: check.Name, URL: check.URL,
			Short: shortURL(check.URL), Meta: meta, OK: check.OK, Cells: cells, Availability: availabilityText})
		class := "ok"
		if !check.OK {
			class = "bad"
			view.Broken++
		} else {
			view.PagesUp++
		}
		view.PageLeaves = append(view.PageLeaves, leafView{Class: class, Text: shortURL(check.URL),
			Small: fmt.Sprintf("%.0f ms", check.ResponseMS), Title: fmt.Sprintf("%s · HTTP %d", check.URL, check.StatusCode)})
	}
	for _, service := range view.Services {
		class := "svc"
		if service.ActiveState != "active" || service.Error != "" {
			class = "bad"
			view.Broken++
		} else {
			view.ServicesUp++
		}
		view.ServiceLeaves = append(view.ServiceLeaves, leafView{Class: class,
			Text: strings.TrimSuffix(service.Name, ".service"), Title: service.Name + " · " + labelServiceState(service.ActiveState)})
	}
	for _, check := range view.TCPChecks {
		class := "svc"
		if !check.Reachable {
			class = "bad"
			view.Broken++
		} else {
			view.ServicesUp++
		}
		view.ServiceLeaves = append(view.ServiceLeaves, leafView{Class: class, Text: check.Name,
			Small: "TCP", Title: check.Address})
	}
	view.ServicesTotal = len(view.Services) + len(view.TCPChecks)
	if containers := view.Docker.Containers; len(containers) > 0 {
		running := 0
		for _, container := range containers {
			if container.State == "running" && container.Health != "unhealthy" {
				running++
			}
		}
		leaf := leafView{Class: "svc", Text: fmt.Sprintf("%d konténer", len(containers))}
		if running < len(containers) {
			leaf = leafView{Class: "bad", Text: fmt.Sprintf("%d/%d konténer fut", running, len(containers))}
			view.Broken++
		}
		view.ServiceLeaves = append(view.ServiceLeaves, leaf)
	}
	// Security group of the card.
	for _, image := range view.Images {
		if image.FixableCritical > 0 {
			view.SecurityLeaves = append(view.SecurityLeaves, leafView{Class: "warn", Text: image.Short,
				Small: fmt.Sprintf("%d krit.", image.FixableCritical), Title: image.Image})
		}
	}
	if packages := view.Packages; packages != nil {
		if packages.Security > 0 {
			view.SecurityLeaves = append(view.SecurityLeaves, leafView{Class: "warn",
				Text: fmt.Sprintf("%d biztonsági frissítés", packages.Security)})
		}
		if packages.RebootRequired {
			view.SecurityLeaves = append(view.SecurityLeaves, leafView{Class: "warn", Text: "Újraindítás kell",
				Title: strings.Join(packages.RebootPackages, ", ")})
		}
	}
	if len(view.SecurityLeaves) == 0 {
		text := "Nincs biztonsági adat"
		switch {
		case len(view.Images) > 0:
			text = "Nincs javítható kritikus"
		case view.Packages != nil && view.Packages.Error == "" && view.Packages.Security == 0:
			text = "Csomagok naprakészek"
		}
		view.SecurityLeaves = append(view.SecurityLeaves, leafView{Class: "ok", Text: text})
	}
	if view.Vulnerabilities != nil && len(view.Images) > 0 {
		view.SecurityCount = fmt.Sprintf("%d kép", len(view.Images))
	} else {
		view.SecurityCount = "nincs vizsgálat"
	}
	// Meters, rings and charts.
	if !view.Missing {
		disk := filesystemView{}
		for _, fs := range view.Files {
			if fs.Mountpoint == "/" {
				disk = fs
			}
		}
		if disk.Mountpoint == "" && len(view.Files) > 0 {
			disk = view.Files[0]
		}
		view.Disk = disk
		view.Meters = []meterView{
			{"CPU", clampPercent(view.CPUPercent), levelFor(view.CPUPercent, 75, 90)},
			{"RAM", clampPercent(view.Memory.UsedPercent), levelFor(view.Memory.UsedPercent, 75, 90)},
			{"Lemez", clampPercent(disk.UsedPercent), levelFor(disk.UsedPercent, s.cfg.DiskWarningThreshold, s.cfg.DiskCriticalThreshold)},
		}
		view.Rings = []ringView{
			newRing(view.CPUPercent, view.Meters[0].Level, "CPU", ""),
			newRing(view.Memory.UsedPercent, view.Meters[1].Level, "Memória",
				formatBytes(view.Memory.UsedBytes)+" / "+formatBytes(view.Memory.TotalBytes)),
			newRing(disk.UsedPercent, view.Meters[2].Level, "Lemez", formatBytes(disk.AvailBytes)+" szabad"),
		}
	}
	start := now.Add(-historyWindow)
	view.Mini = buildChart(metrics, start, now, 300, 38)
	view.Chart = buildChart(metrics, start, now, 380, 110)
	// Overall level of the machine.
	switch {
	case view.Missing:
		view.Level, view.LevelLabel = "bad", "Nincs jelentés"
	case !view.Online:
		view.Level, view.LevelLabel = "bad", "Nincs kapcsolat"
	case view.Broken > 0 || view.Faults > 0:
		view.Level, view.LevelLabel = "bad", "Hiba"
	case view.Firing > 0 || !view.Fresh:
		view.Level, view.LevelLabel = "warn", "Figyelmeztetés"
	default:
		view.Level, view.LevelLabel = "ok", "Rendben"
	}
}

func decorateImages(view *serverView) {
	for i := range view.Images {
		image := &view.Images[i]
		image.Short = shortImage(image.Image)
		total := float64(max(1, image.Critical+image.High+image.Medium))
		image.CritWidth = float64(image.Critical) / total * 100
		image.HighWidth = float64(image.High) / total * 100
		image.MedWidth = float64(image.Medium) / total * 100
		image.HighX, image.MedX = image.CritWidth, image.CritWidth+image.HighWidth
		image.Fixable = image.FixableCritical + image.FixableHigh + image.FixableMedium
		switch {
		case image.FixableCritical > 0:
			image.FixClass = "bad"
		case image.Fixable > 0:
			image.FixClass = "warn"
		default:
			image.FixClass = "ok"
		}
	}
	sort.SliceStable(view.Images, func(i, j int) bool {
		a, b := view.Images[i], view.Images[j]
		if a.FixableCritical != b.FixableCritical {
			return a.FixableCritical > b.FixableCritical
		}
		return a.Critical+a.High > b.Critical+b.High
	})
}

// buildTimeline groups the alerts of the last week by day, merging repeats
// of the same problem within the same hour.
func buildTimeline(history []storage.Alert, names map[string]string, filter string, now time.Time) []timelineDay {
	var events []timelineEvent
	for _, alert := range history {
		resource := alert.Resource
		if alert.RuleKey == "vulnerability_critical" {
			resource = shortImage(resource)
		}
		name := names[alert.AgentID]
		if name == "" {
			name = alert.AgentID
		}
		open := alert.ResolvedAt == nil
		last := len(events) - 1
		if last >= 0 && events[last].AgentID == alert.AgentID && events[last].rule == alert.RuleKey &&
			events[last].Resource == resource && events[last].open == open &&
			events[last].started.Local().Truncate(time.Hour).Equal(alert.StartedAt.Local().Truncate(time.Hour)) {
			events[last].Count++
			if !open {
				events[last].total += alert.ResolvedAt.Sub(alert.StartedAt)
				events[last].Duration = "összesen " + lastedFor(events[last].total)
			}
			continue
		}
		event := timelineEvent{AgentID: alert.AgentID, AgentName: name, Title: shortRule(alert.RuleKey),
			Resource: resource, Time: alert.StartedAt.Local().Format("15:04"), Count: 1,
			started: alert.StartedAt, rule: alert.RuleKey, open: open}
		switch {
		case !open:
			event.total = alert.ResolvedAt.Sub(alert.StartedAt)
			event.Level, event.State = "ok", "done"
			event.Note = "megoldódott " + clock(*alert.ResolvedAt, now)
			event.Duration = lastedFor(alert.ResolvedAt.Sub(alert.StartedAt))
		case alert.AcknowledgedAt != nil:
			event.Level, event.State, event.Note, event.Duration = "warn", "open", "nyugtázva, még fennáll", "folyamatban"
		default:
			event.Level, event.State, event.Note, event.Duration = "warn", "open", "nyitott", "folyamatban"
		}
		if open && alert.Severity == "critical" {
			event.Level = "bad"
		}
		events = append(events, event)
		if len(events) >= timelineMaxItems {
			break
		}
	}
	var days []timelineDay
	for _, event := range events {
		event.Hidden = !matchesFilter(event, filter)
		label := dayLabel(event.started, now)
		if len(days) == 0 || days[len(days)-1].Label != label {
			days = append(days, timelineDay{Label: label, Hidden: true})
		}
		day := &days[len(days)-1]
		day.Events = append(day.Events, event)
		if !event.Hidden {
			day.Hidden = false
		}
	}
	return days
}

func matchesFilter(event timelineEvent, filter string) bool {
	switch {
	case filter == "" || filter == "all":
		return true
	case filter == "open" || filter == "done":
		return event.State == filter
	default:
		return filter == "agent:"+event.AgentID
	}
}

func publicHost(publicURL string) string {
	if parsed, err := url.Parse(publicURL); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return "Monitorozo"
}
