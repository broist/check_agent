package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

func postLabel(app *Server, cookie *http.Cookie, csrf, agent, name, description, origin, accept string) *httptest.ResponseRecorder {
	values := url.Values{"csrf_token": {csrf}, "display_name": {name}, "description": {description}}
	request := httptest.NewRequest("POST", "/api/v1/agents/"+url.PathEscape(agent)+"/label", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	return response
}

func getPage(app *Server, cookie *http.Cookie, path string) string {
	request := httptest.NewRequest("GET", path, nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	return response.Body.String()
}

func TestAgentLabelEndpoint(t *testing.T) {
	app, _, cookie, csrf := notificationServer(t)
	origin := "http://example.test"
	if response := postLabel(app, nil, csrf, "node@01", "Név", "", origin, ""); response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated request: %d %s", response.Code, response.Header().Get("Location"))
	}
	if response := postLabel(app, cookie, "wrong", "node@01", "Név", "", origin, ""); response.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF token: %d", response.Code)
	}
	if response := postLabel(app, cookie, csrf, "node@01", "Név", "", "https://evil.test", ""); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: %d", response.Code)
	}
	if response := postLabel(app, cookie, csrf, "node@01", strings.Repeat("é", 65), "", origin, ""); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("too long name: %d", response.Code)
	}
	if response := postLabel(app, cookie, csrf, "node@01", "ok", strings.Repeat("x", 161), origin, ""); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("too long description: %d", response.Code)
	}
	if response := postLabel(app, cookie, csrf, "node@01", "két\nsor", "", origin, ""); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("control characters: %d", response.Code)
	}
	if response := postLabel(app, cookie, csrf, "ghost", "Név", "", origin, ""); response.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d", response.Code)
	}
	response := postLabel(app, cookie, csrf, "node@01", " <script>alert(1)</script> éles ", "cloud · licenc", origin, "")
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/?agent=node%4001" {
		t.Fatalf("form POST: %d %q", response.Code, response.Header().Get("Location"))
	}
	response = postLabel(app, cookie, csrf, "node@01", "<script>alert(1)</script> éles", "cloud · licenc", origin, "application/json")
	var message map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &message) != nil || message["message"] == "" {
		t.Fatalf("fetch POST: %d %s", response.Code, response.Body.String())
	}
	if err := app.store.SaveReport(context.Background(), model.Report{AgentID: "node@01", Hostname: "ip-10-0-0-1", Sequence: 1, Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	page := getPage(app, cookie, "/")
	if strings.Contains(page, "<script>alert(1)</script>") || !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt; éles") ||
		!strings.Contains(page, "cloud · licenc") || !strings.Contains(page, `value="&lt;script&gt;alert(1)&lt;/script&gt; éles"`) {
		t.Fatalf("display name not rendered safely:\n%s", page)
	}
	if response := postLabel(app, cookie, csrf, "node@01", "", "", origin, ""); response.Code != http.StatusSeeOther {
		t.Fatalf("reset: %d", response.Code)
	}
	if page := getPage(app, cookie, "/api/v1/dashboard"); !strings.Contains(page, `class="node-link" href="/?agent=node%4001">ip-10-0-0-1</a>`) {
		t.Fatalf("empty name must fall back to the hostname:\n%s", page)
	}
}

func TestNotificationsUseDisplayName(t *testing.T) {
	app, _, _, _ := notificationServer(t)
	mailer := &recordingMailer{}
	app.mailer = mailer
	ctx := context.Background()
	if err := app.store.SetAgentLabel(ctx, storage.AgentLabel{AgentID: "node@01", DisplayName: "AcuWall éles"}, "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SaveReport(ctx, model.Report{AgentID: "node@01", Hostname: "ip-10-0-0-1", Sequence: 1, Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.ApplyRule(ctx, storage.RuleEvaluation{AgentID: "node@01", RuleKey: "disk_critical", Resource: "/", Severity: "critical", Value: 99, Threshold: 95, Violated: true}, time.Now()); err != nil {
		t.Fatal(err)
	}
	app.processNotifications(ctx)
	if len(mailer.alerts) != 1 || mailer.alerts[0].DisplayName != "AcuWall éles" || mailer.alerts[0].Hostname != "ip-10-0-0-1" {
		t.Fatalf("notification context: %+v", mailer.alerts)
	}
}

func TestDashboardMapStateAndTimeline(t *testing.T) {
	app, _, cookie, _ := notificationServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		report := model.Report{AgentID: "node@01", Hostname: "production", Sequence: uint64(i + 1), Timestamp: now.Add(time.Duration(i-2) * 10 * time.Second),
			CPUPercent: 12, Memory: model.Memory{UsedPercent: 40, TotalBytes: 1 << 30, UsedBytes: 400 << 20},
			HTTPChecks: []model.HTTPStatus{{Name: "home", URL: "https://example.test/", StatusCode: 200, ResponseMS: 42, OK: true}},
			Services:   []model.ServiceStatus{{Name: "nginx.service", ActiveState: "active"}},
			Vulnerabilities: &model.VulnerabilityStatus{ScannedAt: now, Images: []model.ImageVulnerabilities{
				{Image: "ghcr.io/team/app:sha-0123abc", Critical: 2, High: 1, FixableCritical: 2}}}}
		if err := app.store.SaveReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(rule, resource string, at time.Time, violated bool) {
		if _, err := app.store.ApplyRule(ctx, storage.RuleEvaluation{AgentID: "node@01", RuleKey: rule, Resource: resource,
			Severity: "critical", Value: 1, Violated: violated}, at); err != nil {
			t.Fatal(err)
		}
	}
	apply("vulnerability_critical", "ghcr.io/team/app:sha-0123abc", now.Add(-time.Hour), true)
	apply("http_failed", "home", now.Add(-3*time.Hour), true)
	apply("http_failed", "home", now.Add(-3*time.Hour+31*time.Minute), false)
	page := getPage(app, cookie, "/?agent=node%4001&tab=sec&tl=done")
	for _, want := range []string{
		"1 gépen hiba van", "1/2 gép él", "1/1 oldal elérhető", "1 nyitott riasztás",
		`<article class="node sel" data-agent="node@01" data-level="warn" data-online="1">`,
		`<div class="pane" data-pane="sec">`, `<div class="pane" data-pane="ov" hidden>`,
		`<a href="/?agent=node%4001&amp;tab=sec&amp;tl=done" data-tab="sec" class="on" aria-current="true">`,
		`data-filter="done" class="on"`, "Javítható kritikus sérülékenység", "app", "2 krit.",
		"31 percig tartott", "folyamatban", "10 mp-enként", "example.test",
		`<i class="no"></i>`, `<i class="ok"></i></div>`, "100% elérhető", `class="cpu-line" d="M`,
		`action="/api/v1/agents/node@01/label"`, `<details class="rename" id="atnevezes-node@01">`,
		"Nincs jelentés",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard misses %q", want)
		}
	}
	// The open alert is hidden by the "done" filter, the resolved one stays visible.
	if !strings.Contains(page, `data-state="open" hidden>`) || !strings.Contains(page, `data-state="done">`) {
		t.Errorf("timeline filter not applied server-side")
	}
	if strings.Contains(page, `style="`) || strings.Contains(page, "<script>") {
		t.Errorf("inline styles or scripts break the CSP")
	}
	renamePage := getPage(app, cookie, "/?agent=node%4001&rename=1")
	if !strings.Contains(renamePage, `<details class="rename" id="atnevezes-node@01" open>`) {
		t.Errorf("rename query must open the form without JavaScript")
	}
	fallback := getPage(app, cookie, "/?agent=unknown&tab=bogus&tl=agent:nobody")
	if !strings.Contains(fallback, `data-selected="waiting" data-tab="ov" data-filter="all"`) {
		t.Errorf("invalid view state must fall back to defaults")
	}
}

func TestOverviewHelpers(t *testing.T) {
	now := time.Date(2026, 11, 26, 14, 10, 0, 0, time.UTC)
	first := now.Truncate(storage.HTTPBucketSize).Add(-47 * storage.HTTPBucketSize)
	cells, availability := availabilityCells([]storage.HTTPBucket{
		{Start: first.Add(-storage.HTTPBucketSize), OK: 5},
		{Start: first, OK: 3},
		{Start: first.Add(storage.HTTPBucketSize), OK: 1, Fail: 1},
		{Start: now.Truncate(storage.HTTPBucketSize), OK: 5},
	}, now)
	if len(cells) != 48 || cells[0] != "ok" || cells[1] != "bad" || cells[2] != "no" || cells[47] != "ok" || availability != "90,0%" {
		t.Fatalf("cells %v availability %q", cells, availability)
	}
	if _, availability := availabilityCells(nil, now); availability != "—" {
		t.Fatalf("empty availability %q", availability)
	}
	for in, want := range map[string]string{
		"ghcr.io/broist/weblap_higgsf:sha-4f1c2a9":               "weblap_higgsf",
		"postgres:16-alpine":                                     "postgres:16-alpine",
		"valkey/valkey:8.1-alpine":                               "valkey:8.1-alpine",
		"registry.example.com:5000/team/app@sha256:0123456789ab": "app",
		"ghcr.io/x/buksza-app:20261015140725-7994a4c916ac":       "buksza-app:20261015140725-7994a4c916ac",
	} {
		if got := shortImage(in); got != want {
			t.Errorf("shortImage(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[time.Duration]string{
		20 * time.Second: "1 percig tartott", 31 * time.Minute: "31 percig tartott", time.Hour: "1 óráig tartott",
		80 * time.Minute: "1 óra 20 percig tartott", 26 * time.Hour: "1 nap 2 óráig tartott", 48 * time.Hour: "2 napig tartott",
	} {
		if got := lastedFor(in); got != want {
			t.Errorf("lastedFor(%s) = %q, want %q", in, got, want)
		}
	}
	start := now.Add(-24 * time.Hour)
	chart := buildChart([]storage.HistoryPoint{
		{Timestamp: start, CPUPercent: 50, MemoryPercent: 20},
		{Timestamp: start.Add(10 * time.Minute), CPUPercent: 100, MemoryPercent: 20},
		{Timestamp: start.Add(5 * time.Hour), CPUPercent: 0, MemoryPercent: 20},
	}, start, now, 300, 38)
	if chart.Empty || strings.Count(chart.CPULine, "M") != 2 || strings.Count(chart.CPUArea, "Z") != 2 || !strings.Contains(chart.CPULine, " 3.0") {
		t.Fatalf("chart gap or scale wrong: %+v", chart)
	}
	if !buildChart(nil, start, now, 300, 38).Empty {
		t.Fatal("empty series must render no path")
	}
	resolved := func(started time.Time, minutes int) *time.Time {
		end := started.Add(time.Duration(minutes) * time.Minute)
		return &end
	}
	base := now.Add(-2 * time.Hour).Truncate(time.Hour)
	history := []storage.Alert{
		{AgentID: "a", RuleKey: "cpu_high", StartedAt: base.Add(40 * time.Minute), ResolvedAt: resolved(base.Add(40*time.Minute), 3)},
		{AgentID: "a", RuleKey: "cpu_high", StartedAt: base.Add(20 * time.Minute), ResolvedAt: resolved(base.Add(20*time.Minute), 2)},
		{AgentID: "a", RuleKey: "http_failed", Resource: "home", StartedAt: base.Add(10 * time.Minute), Severity: "critical"},
		{AgentID: "b", RuleKey: "cpu_high", StartedAt: now.Add(-50 * time.Hour), ResolvedAt: resolved(now.Add(-50*time.Hour), 90)},
	}
	days := buildTimeline(history, map[string]string{"a": "Éles"}, "all", now)
	if len(days) != 2 || len(days[0].Events) != 2 || days[0].Events[0].Count != 2 ||
		days[0].Events[0].Duration != "összesen 5 percig tartott" || days[0].Events[0].AgentName != "Éles" ||
		days[0].Events[1].Level != "bad" || days[0].Events[1].Duration != "folyamatban" ||
		days[1].Events[0].AgentName != "b" || days[1].Events[0].Duration != "1 óra 30 percig tartott" {
		t.Fatalf("unexpected timeline %+v", days)
	}
	if label := dayLabel(now.Add(-24*time.Hour), now); label != "Tegnap" {
		t.Fatalf("day label %q", label)
	}
	var buffer bytes.Buffer
	buffer.WriteString(reportInterval(10 * time.Second))
	if buffer.String() != "10 mp-enként" || reportInterval(2*time.Minute) != "2 percenként" || reportInterval(0) != "" {
		t.Fatalf("report interval %q", buffer.String())
	}
	if publicHost("https://monitor.acuwall.hu/") != "monitor.acuwall.hu" || publicHost("") != "Monitorozo" {
		t.Fatal("public host")
	}
}
