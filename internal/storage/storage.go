package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/migrations"
	_ "modernc.org/sqlite"
)

var ErrReplay = errors.New("report sequence is not newer")

type Store struct {
	db *sql.DB
}

type Alert struct {
	ID                int64
	AgentID           string
	RuleKey           string
	Resource          string
	Severity          string
	State             string
	Value             float64
	Threshold         float64
	StartedAt         time.Time
	FiringAt          *time.Time
	ResolvedAt        *time.Time
	AcknowledgedAt    *time.Time
	AcknowledgedBy    string
	NotificationState string
	LastNotifiedAt    *time.Time
	ViolationCount    int
}

type RuleEvaluation struct {
	AgentID     string
	RuleKey     string
	Resource    string
	Severity    string
	Value       float64
	Threshold   float64
	Violated    bool
	For         time.Duration
	Consecutive int
}

type AgentLastSeen struct {
	AgentID  string
	LastSeen time.Time
}

type HistoryPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	Samples       int64     `json:"samples"`
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)
	store := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	entries, err := fs.Glob(migrations.Files, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations
		(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("bootstrap migrations: %w", err)
	}
	for _, name := range entries {
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("invalid migration name %q", name)
		}
		var exists int
		if err := s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		sqlBytes, err := migrations.Files.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, string(sqlBytes)); err == nil {
			_, err = tx.ExecContext(ctx,
				"INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
				version, time.Now().UTC().Format(time.RFC3339Nano))
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SyncAgents(ctx context.Context, tokens []config.AgentToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM agent_tokens"); err != nil {
		return err
	}
	agentStmt, err := tx.PrepareContext(ctx, `INSERT INTO agents(agent_id)
		VALUES(?) ON CONFLICT(agent_id) DO NOTHING`)
	if err != nil {
		return err
	}
	defer agentStmt.Close()
	tokenStmt, err := tx.PrepareContext(ctx, `INSERT INTO agent_tokens(agent_id, token_hash)
		VALUES(?, ?)`)
	if err != nil {
		return err
	}
	defer tokenStmt.Close()
	for _, item := range tokens {
		if item.AgentID == "" || item.Hash == "" {
			return errors.New("agent token entries require agent_id and hash")
		}
		if _, err := agentStmt.ExecContext(ctx, item.AgentID); err != nil {
			return err
		}
		if _, err := tokenStmt.ExecContext(ctx, item.AgentID, item.Hash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) TokenHashes(ctx context.Context, agentID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT token_hash FROM agent_tokens WHERE agent_id = ?", agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(hashes) == 0 {
		return nil, sql.ErrNoRows
	}
	return hashes, nil
}

func (s *Store) SaveReport(ctx context.Context, report model.Report) error {
	report.Timestamp = report.Timestamp.UTC()
	if !report.BootTime.IsZero() {
		report.BootTime = report.BootTime.UTC()
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agents SET last_sequence=?, last_seen=?
		WHERE agent_id=? AND last_sequence < ?`,
		report.Sequence, time.Now().UTC().Format(time.RFC3339Nano), report.AgentID, report.Sequence)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrReplay
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO reports(
		agent_id, measured_at, received_at, sequence, cpu_percent, memory_percent,
		swap_percent, uptime_seconds, payload_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		report.AgentID, report.Timestamp.Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano), report.Sequence, report.CPUPercent,
		report.Memory.UsedPercent, report.Memory.SwapPercent, report.Uptime, payload)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) LatestReports(ctx context.Context) ([]model.Report, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.payload_json FROM reports r
		JOIN (SELECT agent_id, MAX(id) id FROM reports GROUP BY agent_id) latest
		ON latest.id = r.id ORDER BY r.agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []model.Report
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var report model.Report
		if err := json.Unmarshal(payload, &report); err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

func (s *Store) History(ctx context.Context, agentID string, since time.Time, rawRetention time.Duration, maxPoints int) ([]HistoryPoint, error) {
	if maxPoints < 1 {
		return nil, errors.New("maxPoints must be positive")
	}
	rawStart := time.Now().UTC().Add(-rawRetention)
	var points []HistoryPoint
	if since.Before(rawStart) {
		hourly, err := s.hourlyHistory(ctx, agentID, since, rawStart)
		if err != nil {
			return nil, err
		}
		points = append(points, hourly...)
		since = rawStart
	}
	raw, err := s.rawHistory(ctx, agentID, since)
	if err != nil {
		return nil, err
	}
	points = append(points, raw...)
	return downsample(points, maxPoints), nil
}

func (s *Store) rawHistory(ctx context.Context, agentID string, since time.Time) ([]HistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT measured_at, cpu_percent, memory_percent
		FROM reports WHERE agent_id=? AND measured_at>=? ORDER BY measured_at`,
		agentID, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []HistoryPoint
	for rows.Next() {
		var timestamp string
		var point HistoryPoint
		if err := rows.Scan(&timestamp, &point.CPUPercent, &point.MemoryPercent); err != nil {
			return nil, err
		}
		point.Timestamp, _ = time.Parse(time.RFC3339Nano, timestamp)
		point.Samples = 1
		points = append(points, point)
	}
	return points, rows.Err()
}

func (s *Store) hourlyHistory(ctx context.Context, agentID string, since, until time.Time) ([]HistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT hour_start, cpu_avg, memory_avg, samples
		FROM hourly_metrics WHERE agent_id=? AND hour_start>=? AND hour_start<?
		ORDER BY hour_start`, agentID, since.Format(time.RFC3339), until.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []HistoryPoint
	for rows.Next() {
		var timestamp string
		var point HistoryPoint
		if err := rows.Scan(&timestamp, &point.CPUPercent, &point.MemoryPercent, &point.Samples); err != nil {
			return nil, err
		}
		point.Timestamp, _ = time.Parse(time.RFC3339, timestamp)
		points = append(points, point)
	}
	return points, rows.Err()
}

func downsample(points []HistoryPoint, maximum int) []HistoryPoint {
	if len(points) <= maximum {
		return points
	}
	result := make([]HistoryPoint, 0, maximum)
	bucketSize := float64(len(points)) / float64(maximum)
	for bucket := 0; bucket < maximum; bucket++ {
		start := int(float64(bucket) * bucketSize)
		end := int(float64(bucket+1) * bucketSize)
		if end <= start {
			end = start + 1
		}
		if end > len(points) {
			end = len(points)
		}
		var cpu, memory float64
		var samples int64
		for _, point := range points[start:end] {
			weight := point.Samples
			if weight < 1 {
				weight = 1
			}
			cpu += point.CPUPercent * float64(weight)
			memory += point.MemoryPercent * float64(weight)
			samples += weight
		}
		result = append(result, HistoryPoint{
			Timestamp: points[start].Timestamp, CPUPercent: cpu / float64(samples),
			MemoryPercent: memory / float64(samples), Samples: samples,
		})
	}
	return result
}

func (s *Store) Maintain(ctx context.Context, now time.Time, rawRetention, aggregateRetention time.Duration) error {
	now = now.UTC()
	currentHour := now.Truncate(time.Hour)
	rawCutoff := now.Add(-rawRetention)
	aggregateCutoff := now.Add(-aggregateRetention)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO hourly_metrics(
		agent_id, hour_start, cpu_avg, cpu_min, cpu_max, memory_avg, memory_min,
		memory_max, samples)
		SELECT agent_id, strftime('%Y-%m-%dT%H:00:00Z', measured_at),
		AVG(cpu_percent), MIN(cpu_percent), MAX(cpu_percent), AVG(memory_percent),
		MIN(memory_percent), MAX(memory_percent), COUNT(*)
		FROM reports WHERE measured_at < ?
		GROUP BY agent_id, strftime('%Y-%m-%dT%H:00:00Z', measured_at)
		ON CONFLICT(agent_id, hour_start) DO UPDATE SET
		cpu_avg=excluded.cpu_avg, cpu_min=excluded.cpu_min, cpu_max=excluded.cpu_max,
		memory_avg=excluded.memory_avg, memory_min=excluded.memory_min,
		memory_max=excluded.memory_max, samples=excluded.samples`,
		currentHour.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("aggregate metrics: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reports WHERE measured_at < ?",
		rawCutoff.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("delete raw metrics: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM hourly_metrics WHERE hour_start < ?",
		aggregateCutoff.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("delete hourly metrics: %w", err)
	}
	return tx.Commit()
}

func (s *Store) ActiveAlerts(ctx context.Context) ([]Alert, error) {
	return s.queryAlerts(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE state IN ('pending', 'firing') ORDER BY started_at DESC`)
}

func (s *Store) UnacknowledgedActiveAlerts(ctx context.Context) ([]Alert, error) {
	return s.queryAlerts(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE state IN ('pending', 'firing') AND acknowledged_at IS NULL
		ORDER BY started_at DESC`)
}

func (s *Store) AlertHistory(ctx context.Context, limit int) ([]Alert, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	return s.queryAlerts(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE state='resolved' ORDER BY resolved_at DESC LIMIT ?`, limit)
}

const alertColumns = `id, agent_id, rule_key, resource, severity, state, value,
	threshold, started_at, firing_at, resolved_at, acknowledged_at,
	acknowledged_by, notification_state, last_notified_at, violation_count`

func (s *Store) queryAlerts(ctx context.Context, query string, args ...any) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []Alert
	for rows.Next() {
		item, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, item)
	}
	return alerts, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAlert(scanner rowScanner) (Alert, error) {
	var item Alert
	var started string
	var firing, resolved, acknowledged, acknowledgedBy, lastNotified sql.NullString
	err := scanner.Scan(&item.ID, &item.AgentID, &item.RuleKey, &item.Resource,
		&item.Severity, &item.State, &item.Value, &item.Threshold, &started,
		&firing, &resolved, &acknowledged, &acknowledgedBy,
		&item.NotificationState, &lastNotified, &item.ViolationCount)
	if err != nil {
		return item, err
	}
	item.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	item.FiringAt = parseNullableTime(firing)
	item.ResolvedAt = parseNullableTime(resolved)
	item.AcknowledgedAt = parseNullableTime(acknowledged)
	item.LastNotifiedAt = parseNullableTime(lastNotified)
	if acknowledgedBy.Valid {
		item.AcknowledgedBy = acknowledgedBy.String
	}
	return item, nil
}

func parseNullableTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &parsed
}

func (s *Store) ApplyRule(ctx context.Context, evaluation RuleEvaluation, now time.Time) (bool, error) {
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var existing Alert
	existing, err = scanAlert(tx.QueryRowContext(ctx, `SELECT `+alertColumns+`
		FROM alerts WHERE agent_id=? AND rule_key=? AND resource=?
		AND state IN ('pending', 'firing')`,
		evaluation.AgentID, evaluation.RuleKey, evaluation.Resource))
	hasActive := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	changed := false
	if evaluation.Violated && !hasActive {
		state := "pending"
		notification := "none"
		var firingAt any
		if evaluation.For <= 0 && evaluation.Consecutive <= 1 {
			state = "firing"
			notification = "pending"
			firingAt = now.Format(time.RFC3339Nano)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO alerts(agent_id, rule_key,
			resource, severity, state, value, threshold, started_at, firing_at,
			notification_state) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			evaluation.AgentID, evaluation.RuleKey, evaluation.Resource,
			evaluation.Severity, state, evaluation.Value, evaluation.Threshold,
			now.Format(time.RFC3339Nano), firingAt, notification)
		if err != nil {
			return false, err
		}
		if err := auditRuleTx(ctx, tx, evaluation, state); err != nil {
			return false, err
		}
		changed = true
	} else if evaluation.Violated && hasActive {
		nextCount := existing.ViolationCount + 1
		reachedCount := evaluation.Consecutive > 1 && nextCount >= evaluation.Consecutive
		reachedDuration := evaluation.Consecutive <= 1 &&
			now.Sub(existing.StartedAt) >= evaluation.For
		if existing.State == "pending" && (reachedCount || reachedDuration) {
			_, err := tx.ExecContext(ctx, `UPDATE alerts SET state='firing',
				firing_at=?, severity=?, value=?, threshold=?,
				notification_state='pending', violation_count=? WHERE id=?`,
				now.Format(time.RFC3339Nano), evaluation.Severity,
				evaluation.Value, evaluation.Threshold, nextCount, existing.ID)
			if err != nil {
				return false, err
			}
			if err := auditRuleTx(ctx, tx, evaluation, "firing"); err != nil {
				return false, err
			}
			changed = true
		} else {
			_, err := tx.ExecContext(ctx, `UPDATE alerts SET severity=?, value=?,
				threshold=?, violation_count=? WHERE id=?`, evaluation.Severity,
				evaluation.Value, evaluation.Threshold, nextCount, existing.ID)
			if err != nil {
				return false, err
			}
		}
	} else if !evaluation.Violated && hasActive {
		notification := "none"
		if existing.State == "firing" {
			notification = "pending"
			if existing.NotificationState == "suppressed" {
				notification = "suppressed"
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE alerts SET state='resolved',
			resolved_at=?, value=?, threshold=?, notification_state=? WHERE id=?`,
			now.Format(time.RFC3339Nano), evaluation.Value, evaluation.Threshold,
			notification, existing.ID)
		if err != nil {
			return false, err
		}
		if err := auditRuleTx(ctx, tx, evaluation, "resolved"); err != nil {
			return false, err
		}
		changed = true
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed, nil
}

func auditRuleTx(ctx context.Context, tx *sql.Tx, evaluation RuleEvaluation, state string) error {
	target := evaluation.AgentID + "/" + evaluation.RuleKey
	if evaluation.Resource != "" {
		target += "/" + evaluation.Resource
	}
	return auditTx(ctx, tx, "system", "alert."+state, target,
		fmt.Sprintf("value=%.2f threshold=%.2f severity=%s",
			evaluation.Value, evaluation.Threshold, evaluation.Severity))
}

func (s *Store) PendingNotifications(ctx context.Context, limit int) ([]Alert, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	return s.queryAlerts(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE notification_state='pending' AND state IN ('firing', 'resolved')
		ORDER BY id LIMIT ?`, limit)
}

func (s *Store) NotificationInCooldown(ctx context.Context, alert Alert, cooldown time.Duration, now time.Time) (bool, error) {
	if alert.State != "firing" || cooldown <= 0 {
		return false, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts
		WHERE agent_id=? AND rule_key=? AND resource=? AND id<>?
		AND notification_state='sent' AND last_notified_at>=?`,
		alert.AgentID, alert.RuleKey, alert.Resource, alert.ID,
		now.UTC().Add(-cooldown).Format(time.RFC3339Nano)).Scan(&count)
	return count > 0, err
}

func (s *Store) MarkAlertNotification(ctx context.Context, id int64, state string, now time.Time) error {
	if state != "sent" && state != "suppressed" {
		return errors.New("invalid notification state")
	}
	var notifiedAt any
	if state == "sent" {
		notifiedAt = now.UTC().Format(time.RFC3339Nano)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET notification_state=?,
		last_notified_at=COALESCE(?, last_notified_at) WHERE id=?`,
		state, notifiedAt, id)
	return err
}

func (s *Store) AcknowledgeAlert(ctx context.Context, id int64, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE alerts SET acknowledged_at=?,
		acknowledged_by=? WHERE id=? AND state IN ('pending', 'firing')
		AND acknowledged_at IS NULL`, now.UTC().Format(time.RFC3339Nano), actor, id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	if err := auditTx(ctx, tx, actor, "alert.acknowledged",
		strconv.FormatInt(id, 10), "alert acknowledged"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AgentLastSeen(ctx context.Context) ([]AgentLastSeen, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_id, last_seen FROM agents
		WHERE last_seen IS NOT NULL ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AgentLastSeen
	for rows.Next() {
		var item AgentLastSeen
		var value string
		if err := rows.Scan(&item.AgentID, &value); err != nil {
			return nil, err
		}
		item.LastSeen, _ = time.Parse(time.RFC3339Nano, value)
		result = append(result, item)
	}
	return result, rows.Err()
}

func auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, details string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log(occurred_at, actor, action,
		target, details) VALUES(?, ?, ?, ?, ?)`, time.Now().UTC().Format(time.RFC3339Nano),
		actor, action, target, details)
	return err
}
