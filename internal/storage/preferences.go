package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/broist/check_agent/internal/model"
)

type NotificationPreferences struct {
	Enabled   bool   `json:"enabled"`
	Recipient string `json:"recipient"`
	Warnings  bool   `json:"warnings"`
	Recovery  bool   `json:"recovery"`
}

func (s *Store) NotificationPreferences(ctx context.Context, defaults NotificationPreferences) (NotificationPreferences, error) {
	var p NotificationPreferences
	err := s.db.QueryRowContext(ctx, "SELECT enabled, recipient, warnings, recovery FROM notification_preferences WHERE id=1").Scan(&p.Enabled, &p.Recipient, &p.Warnings, &p.Recovery)
	if errors.Is(err, sql.ErrNoRows) {
		return defaults, nil
	}
	return p, err
}

func (s *Store) SaveNotificationPreferences(ctx context.Context, p NotificationPreferences) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO notification_preferences(id, enabled, recipient, warnings, recovery)
        VALUES(1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
        enabled=excluded.enabled, recipient=excluded.recipient, warnings=excluded.warnings, recovery=excluded.recovery`,
		p.Enabled, p.Recipient, p.Warnings, p.Recovery)
	return err
}

// Compare measurements, not receipt times: a queued report may arrive much later.
func (s *Store) PreviousReport(ctx context.Context, agent string, before time.Time) (model.Report, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx, `SELECT payload_json FROM reports WHERE agent_id=?
        AND julianday(measured_at)<julianday(?) ORDER BY julianday(measured_at) DESC, id DESC LIMIT 1`, agent, before.UTC().Format(time.RFC3339Nano)).Scan(&payload)
	if err != nil {
		return model.Report{}, err
	}
	var report model.Report
	err = json.Unmarshal(payload, &report)
	return report, err
}
