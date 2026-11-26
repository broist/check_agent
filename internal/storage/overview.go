package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/broist/check_agent/internal/model"
)

const (
	// MaxDisplayNameLen and MaxDescriptionLen are character (rune) limits.
	MaxDisplayNameLen = 64
	MaxDescriptionLen = 160
	// HTTPBucketSize is the resolution of the stored endpoint availability.
	HTTPBucketSize = 30 * time.Minute
)

// ErrUnknownAgent reports that the agent is not registered.
var ErrUnknownAgent = errors.New("unknown agent")

// AgentLabel is the operator-defined display name and description of an agent.
type AgentLabel struct {
	AgentID     string
	DisplayName string
	Description string
}

// HTTPBucket is the availability of one HTTP check in one 30-minute window.
type HTTPBucket struct {
	Start time.Time
	OK    int64
	Fail  int64
}

// CleanLabelText trims a label and reports whether it is acceptable: valid
// UTF-8, no control characters and at most max characters.
func CleanLabelText(value string, max int) (string, bool) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > max {
		return value, false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || (character >= 0x80 && character < 0xa0) ||
			character == ' ' || character == ' ' {
			return value, false
		}
	}
	return value, true
}

// AgentLabels returns the stored labels by agent ID.
func (s *Store) AgentLabels(ctx context.Context) (map[string]AgentLabel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_id, display_name, description FROM agent_labels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := make(map[string]AgentLabel)
	for rows.Next() {
		var label AgentLabel
		if err := rows.Scan(&label.AgentID, &label.DisplayName, &label.Description); err != nil {
			return nil, err
		}
		labels[label.AgentID] = label
	}
	return labels, rows.Err()
}

// SetAgentLabel stores (or with two empty values removes) the label of a
// registered agent. Values must already be validated with CleanLabelText.
func (s *Store) SetAgentLabel(ctx context.Context, label AgentLabel, actor string, now time.Time) error {
	if _, ok := CleanLabelText(label.DisplayName, MaxDisplayNameLen); !ok {
		return errors.New("invalid display name")
	}
	if _, ok := CleanLabelText(label.Description, MaxDescriptionLen); !ok {
		return errors.New("invalid description")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE agent_id=?",
		label.AgentID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrUnknownAgent
	}
	if label.DisplayName == "" && label.Description == "" {
		_, err = tx.ExecContext(ctx, "DELETE FROM agent_labels WHERE agent_id=?", label.AgentID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_labels(agent_id, display_name,
			description, updated_at) VALUES(?, ?, ?, ?)
			ON CONFLICT(agent_id) DO UPDATE SET display_name=excluded.display_name,
			description=excluded.description, updated_at=excluded.updated_at`,
			label.AgentID, label.DisplayName, label.Description,
			now.UTC().Format(time.RFC3339Nano))
	}
	if err != nil {
		return err
	}
	if err := auditTx(ctx, tx, actor, "agent.label", label.AgentID,
		fmt.Sprintf("display_name=%q description=%q", label.DisplayName, label.Description)); err != nil {
		return err
	}
	return tx.Commit()
}

// recordHTTPChecksTx adds the HTTP check results of a report to their
// 30-minute availability buckets.
func recordHTTPChecksTx(ctx context.Context, tx *sql.Tx, report model.Report) error {
	if len(report.HTTPChecks) == 0 {
		return nil
	}
	statement, err := tx.PrepareContext(ctx, `INSERT INTO http_check_buckets(agent_id,
		check_name, bucket_start, ok_count, fail_count) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(agent_id, check_name, bucket_start) DO UPDATE SET
		ok_count=ok_count+excluded.ok_count, fail_count=fail_count+excluded.fail_count`)
	if err != nil {
		return err
	}
	defer statement.Close()
	bucket := report.Timestamp.UTC().Truncate(HTTPBucketSize).Format(time.RFC3339)
	for _, check := range report.HTTPChecks {
		ok, fail := 0, 1
		if check.OK {
			ok, fail = 1, 0
		}
		if _, err := statement.ExecContext(ctx, report.AgentID, check.Name, bucket, ok, fail); err != nil {
			return err
		}
	}
	return nil
}

// HTTPAvailability returns the HTTP check buckets that start at or after
// since, keyed by agent ID and check name, in chronological order.
func (s *Store) HTTPAvailability(ctx context.Context, since time.Time) (map[string]map[string][]HTTPBucket, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_id, check_name, bucket_start,
		ok_count, fail_count FROM http_check_buckets WHERE bucket_start>=?
		ORDER BY agent_id, check_name, bucket_start`,
		since.UTC().Truncate(HTTPBucketSize).Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]map[string][]HTTPBucket)
	for rows.Next() {
		var agentID, name, start string
		var bucket HTTPBucket
		if err := rows.Scan(&agentID, &name, &start, &bucket.OK, &bucket.Fail); err != nil {
			return nil, err
		}
		bucket.Start, _ = time.Parse(time.RFC3339, start)
		if result[agentID] == nil {
			result[agentID] = make(map[string][]HTTPBucket)
		}
		result[agentID][name] = append(result[agentID][name], bucket)
	}
	return result, rows.Err()
}

// MetricBuckets aggregates the raw reports of an agent since the given time
// into fixed buckets in SQL: CPUPercent is the bucket maximum (peak load),
// MemoryPercent the bucket average. Only the indexed numeric columns are
// read; report payloads are not decoded.
func (s *Store) MetricBuckets(ctx context.Context, agentID string, since time.Time, step time.Duration) ([]HistoryPoint, error) {
	seconds := int64(step / time.Second)
	if seconds < 1 {
		return nil, errors.New("bucket step must be at least one second")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(strftime('%s', measured_at) AS INTEGER) / ? AS bucket,
		MAX(cpu_percent), AVG(memory_percent), COUNT(*)
		FROM reports WHERE agent_id=? AND measured_at>=?
		GROUP BY bucket ORDER BY bucket`,
		seconds, agentID, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []HistoryPoint
	for rows.Next() {
		var bucket int64
		var point HistoryPoint
		if err := rows.Scan(&bucket, &point.CPUPercent, &point.MemoryPercent, &point.Samples); err != nil {
			return nil, err
		}
		point.Timestamp = time.Unix(bucket*seconds, 0).UTC()
		points = append(points, point)
	}
	return points, rows.Err()
}

// TimelineAlerts returns the alerts that reached the firing state and either
// started, resolved after since or are still active, newest first.
func (s *Store) TimelineAlerts(ctx context.Context, since time.Time, limit int) ([]Alert, error) {
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	cutoff := since.UTC().Format(time.RFC3339Nano)
	return s.queryAlerts(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE firing_at IS NOT NULL AND (started_at>=? OR resolved_at>=? OR state='firing')
		ORDER BY started_at DESC, id DESC LIMIT ?`, cutoff, cutoff, limit)
}
