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

	"github.com/example/monitorozo/internal/config"
	"github.com/example/monitorozo/internal/model"
	"github.com/example/monitorozo/migrations"
	_ "modernc.org/sqlite"
)

var ErrReplay = errors.New("report sequence is not newer")

type Store struct {
	db *sql.DB
}

type Alert struct {
	ID         int64
	AgentID    string
	RuleKey    string
	Severity   string
	State      string
	Value      float64
	Threshold  float64
	StartedAt  time.Time
	ResolvedAt *time.Time
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

func (s *Store) ActiveAlerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, agent_id, rule_key, severity,
		state, value, threshold, started_at, resolved_at FROM alerts
		WHERE state='firing' ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var alerts []Alert
	for rows.Next() {
		var item Alert
		var started string
		var resolved sql.NullString
		if err := rows.Scan(&item.ID, &item.AgentID, &item.RuleKey, &item.Severity,
			&item.State, &item.Value, &item.Threshold, &started, &resolved); err != nil {
			return nil, err
		}
		item.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if resolved.Valid {
			value, _ := time.Parse(time.RFC3339Nano, resolved.String)
			item.ResolvedAt = &value
		}
		alerts = append(alerts, item)
	}
	return alerts, rows.Err()
}

func (s *Store) EvaluateCPU(ctx context.Context, report model.Report, threshold float64) (*Alert, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var existing Alert
	var started string
	err = tx.QueryRowContext(ctx, `SELECT id, severity, value, threshold, started_at
		FROM alerts WHERE agent_id=? AND rule_key='cpu_high' AND state='firing'`,
		report.AgentID).Scan(&existing.ID, &existing.Severity, &existing.Value,
		&existing.Threshold, &started)
	hasFiring := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if hasFiring {
		existing.AgentID, existing.RuleKey, existing.State = report.AgentID, "cpu_high", "firing"
		existing.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	}
	if report.CPUPercent >= threshold && !hasFiring {
		result, err := tx.ExecContext(ctx, `INSERT INTO alerts(agent_id, rule_key,
			severity, state, value, threshold, started_at) VALUES(?, 'cpu_high',
			'critical', 'firing', ?, ?, ?)`, report.AgentID, report.CPUPercent,
			threshold, now.Format(time.RFC3339Nano))
		if err != nil {
			return nil, err
		}
		id, _ := result.LastInsertId()
		existing = Alert{ID: id, AgentID: report.AgentID, RuleKey: "cpu_high",
			Severity: "critical", State: "firing", Value: report.CPUPercent,
			Threshold: threshold, StartedAt: now}
		if err := auditTx(ctx, tx, "system", "alert.firing", report.AgentID+"/cpu_high",
			fmt.Sprintf("value=%.2f threshold=%.2f", report.CPUPercent, threshold)); err != nil {
			return nil, err
		}
	} else if report.CPUPercent < threshold && hasFiring {
		_, err := tx.ExecContext(ctx, `UPDATE alerts SET state='resolved',
			resolved_at=?, value=?, notification_state='pending' WHERE id=?`,
			now.Format(time.RFC3339Nano), report.CPUPercent, existing.ID)
		if err != nil {
			return nil, err
		}
		existing.State, existing.Value, existing.ResolvedAt = "resolved", report.CPUPercent, &now
		if err := auditTx(ctx, tx, "system", "alert.resolved", report.AgentID+"/cpu_high",
			fmt.Sprintf("value=%.2f threshold=%.2f", report.CPUPercent, threshold)); err != nil {
			return nil, err
		}
	} else {
		return nil, tx.Commit()
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &existing, nil
}

func (s *Store) MarkAlertNotified(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE alerts SET notification_state='sent' WHERE id=?", id)
	return err
}

func auditTx(ctx context.Context, tx *sql.Tx, actor, action, target, details string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log(occurred_at, actor, action,
		target, details) VALUES(?, ?, ?, ?, ?)`, time.Now().UTC().Format(time.RFC3339Nano),
		actor, action, target, details)
	return err
}
