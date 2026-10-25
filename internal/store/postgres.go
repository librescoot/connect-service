package store

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/librescoot/connect-service/internal/report"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *Postgres) Register(ctx context.Context, installationID string, credentialDigest [32]byte, payload report.Report) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin registration: %w", err)
	}
	defer tx.Rollback()
	if err := lockInstallation(ctx, tx, installationID); err != nil {
		return fmt.Errorf("lock installation: %w", err)
	}

	state, err := readInstallation(ctx, tx, installationID)
	if errors.Is(err, sql.ErrNoRows) {
		return p.createInstallation(ctx, tx, installationID, credentialDigest, payload)
	}
	if err != nil {
		return fmt.Errorf("read installation: %w", err)
	}
	if state.deletedAt.Valid {
		return ErrConflict
	}
	if !state.expiresAt.Valid || !state.expiresAt.Time.After(time.Now()) {
		if err := expireInstallation(ctx, tx, installationID, state.lastReportedAt.Time); err != nil {
			return fmt.Errorf("expire installation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit expiration: %w", err)
		}
		return ErrConflict
	}
	if !sameDigest(state.credentialDigest, credentialDigest[:]) {
		return ErrUnauthorized
	}
	digest := payload.CanonicalDigest()
	if state.initialEventID.String == payload.EventID && sameDigest(state.initialDigest, digest[:]) {
		return tx.Commit()
	}
	return ErrConflict
}

func (p *Postgres) createInstallation(ctx context.Context, tx *sql.Tx, installationID string, credentialDigest [32]byte, payload report.Report) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	now := time.Now().UTC()
	expiresAt := retentionExpiry(now)
	digest := payload.CanonicalDigest()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO installations (
			installation_id, credential_digest, consent_version, facts, initial_event_id, initial_digest,
			first_reported_at, last_reported_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $7, $8, $7)`,
		installationID, credentialDigest[:], payload.ConsentVersion, string(encoded), payload.EventID, digest[:], now, expiresAt)
	if err != nil {
		return fmt.Errorf("insert installation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO report_receipts (installation_id, event_id, digest, received_at)
		VALUES ($1, $2, $3, $4)`, installationID, payload.EventID, digest[:], now); err != nil {
		return fmt.Errorf("insert initial report receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit registration: %w", err)
	}
	return nil
}

func (p *Postgres) UpdateReport(ctx context.Context, installationID string, credentialDigest [32]byte, payload report.Report) error {
	if payload.InstallationID != installationID {
		return ErrUnauthorized
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin report: %w", err)
	}
	defer tx.Rollback()
	if err := lockInstallation(ctx, tx, installationID); err != nil {
		return fmt.Errorf("lock installation: %w", err)
	}
	state, err := readInstallation(ctx, tx, installationID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("read installation: %w", err)
	}
	if state.deletedAt.Valid {
		return ErrUnauthorized
	}
	if !state.expiresAt.Valid || !state.expiresAt.Time.After(time.Now()) {
		if err := expireInstallation(ctx, tx, installationID, state.lastReportedAt.Time); err != nil {
			return fmt.Errorf("expire installation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit expiration: %w", err)
		}
		return ErrUnauthorized
	}
	if !sameDigest(state.credentialDigest, credentialDigest[:]) {
		return ErrUnauthorized
	}

	digest := payload.CanonicalDigest()
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT digest FROM report_receipts WHERE installation_id = $1 AND event_id = $2`, installationID, payload.EventID).Scan(&existing)
	if err == nil {
		if sameDigest(existing, digest[:]) {
			return tx.Commit()
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read report receipt: %w", err)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO report_receipts (installation_id, event_id, digest, received_at)
		VALUES ($1, $2, $3, $4)`, installationID, payload.EventID, digest[:], now); err != nil {
		return fmt.Errorf("insert report receipt: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE installations
		SET facts = $2::jsonb, consent_version = $3, last_reported_at = $4, expires_at = $5
		WHERE installation_id = $1`, installationID, string(encoded), payload.ConsentVersion, now,
		retentionExpiry(now)); err != nil {
		return fmt.Errorf("update installation report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit report: %w", err)
	}
	return nil
}

func (p *Postgres) Delete(ctx context.Context, installationID string, credentialDigest [32]byte) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deletion: %w", err)
	}
	defer tx.Rollback()
	if err := lockInstallation(ctx, tx, installationID); err != nil {
		return fmt.Errorf("lock installation: %w", err)
	}
	state, err := readInstallation(ctx, tx, installationID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("read installation: %w", err)
	}
	if state.deletedAt.Valid {
		return ErrUnauthorized
	}
	if !state.expiresAt.Valid || !state.expiresAt.Time.After(time.Now()) {
		if err := expireInstallation(ctx, tx, installationID, state.lastReportedAt.Time); err != nil {
			return fmt.Errorf("expire installation: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit expiration: %w", err)
		}
		return ErrUnauthorized
	}
	if !sameDigest(state.credentialDigest, credentialDigest[:]) {
		return ErrUnauthorized
	}
	if err := tombstoneInstallation(ctx, tx, installationID, time.Now().UTC()); err != nil {
		return fmt.Errorf("tombstone installation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deletion: %w", err)
	}
	return nil
}

func (p *Postgres) Sweep(ctx context.Context, now time.Time) error {
	for {
		processed, err := p.sweepExpiredBatch(ctx, now)
		if err != nil {
			return err
		}
		if processed == 0 {
			return nil
		}
	}
}

func (p *Postgres) sweepExpiredBatch(ctx context.Context, now time.Time) (int, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin retention sweep: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM report_receipts WHERE received_at < $1`, now.Add(-IdempotencyRetention)); err != nil {
		return 0, fmt.Errorf("prune report receipts: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT installation_id, date_trunc('month', last_reported_at)::date
		FROM installations
		WHERE deleted_at IS NULL AND expires_at <= $1
		ORDER BY expires_at
		FOR UPDATE SKIP LOCKED
		LIMIT 500`, now)
	if err != nil {
		return 0, fmt.Errorf("select expired installations: %w", err)
	}
	type expiredRecord struct {
		id    string
		month time.Time
	}
	expired := make([]expiredRecord, 0)
	for rows.Next() {
		var record expiredRecord
		if err := rows.Scan(&record.id, &record.month); err != nil {
			rows.Close()
			return 0, fmt.Errorf("read expired installation: %w", err)
		}
		expired = append(expired, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate expired installations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired installation rows: %w", err)
	}

	counts := make(map[string]int64)
	for _, record := range expired {
		if err := tombstoneInstallation(ctx, tx, record.id, now); err != nil {
			return 0, fmt.Errorf("expire installation: %w", err)
		}
		counts[record.month.Format("2006-01-02")]++
	}
	for month, count := range counts {
		parsed, err := time.Parse("2006-01-02", month)
		if err != nil {
			return 0, fmt.Errorf("parse aggregate month: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO reporting_retention_aggregates (report_month, expired_installation_count)
			VALUES ($1, $2)
			ON CONFLICT (report_month) DO UPDATE
			SET expired_installation_count = reporting_retention_aggregates.expired_installation_count + EXCLUDED.expired_installation_count`, parsed, count); err != nil {
			return 0, fmt.Errorf("aggregate expired reports: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM report_receipts r
		USING installations i
		WHERE r.installation_id = i.installation_id AND i.deleted_at IS NOT NULL`); err != nil {
		return 0, fmt.Errorf("prune tombstoned receipts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit retention sweep: %w", err)
	}
	return len(expired), nil
}

type installationState struct {
	credentialDigest []byte
	initialEventID   sql.NullString
	initialDigest    []byte
	lastReportedAt   sql.NullTime
	expiresAt        sql.NullTime
	deletedAt        sql.NullTime
}

func readInstallation(ctx context.Context, tx *sql.Tx, installationID string) (installationState, error) {
	var state installationState
	err := tx.QueryRowContext(ctx, `
		SELECT credential_digest, initial_event_id, initial_digest, last_reported_at, expires_at, deleted_at
		FROM installations WHERE installation_id = $1 FOR UPDATE`, installationID).Scan(
		&state.credentialDigest, &state.initialEventID, &state.initialDigest, &state.lastReportedAt, &state.expiresAt, &state.deletedAt)
	return state, err
}

func lockInstallation(ctx context.Context, tx *sql.Tx, installationID string) error {
	var ignored any
	return tx.QueryRowContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, installationID).Scan(&ignored)
}

func retentionExpiry(reportedAt time.Time) time.Time {
	reportedAt = reportedAt.UTC()
	year, month, day := reportedAt.Date()
	monthIndex := int(month) - 1 + InstallationRetentionMonths
	targetYear := year + monthIndex/12
	targetMonth := time.Month(monthIndex%12 + 1)
	lastDay := time.Date(targetYear, targetMonth+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > lastDay {
		day = lastDay
	}
	return time.Date(targetYear, targetMonth, day, reportedAt.Hour(), reportedAt.Minute(), reportedAt.Second(), reportedAt.Nanosecond(), time.UTC)
}

func sameDigest(left, right []byte) bool {
	if len(left) != 32 || len(right) != 32 {
		return false
	}
	return hmac.Equal(left, right)
}

func expireInstallation(ctx context.Context, tx *sql.Tx, installationID string, lastReportedAt time.Time) error {
	if err := tombstoneInstallation(ctx, tx, installationID, time.Now().UTC()); err != nil {
		return err
	}
	month := time.Date(lastReportedAt.Year(), lastReportedAt.Month(), 1, 0, 0, 0, 0, time.UTC)
	_, err := tx.ExecContext(ctx, `
		INSERT INTO reporting_retention_aggregates (report_month, expired_installation_count)
		VALUES ($1, 1)
		ON CONFLICT (report_month) DO UPDATE
		SET expired_installation_count = reporting_retention_aggregates.expired_installation_count + 1`, month)
	return err
}

func tombstoneInstallation(ctx context.Context, tx *sql.Tx, installationID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE installations
		SET credential_digest = NULL, consent_version = NULL, facts = NULL,
			initial_event_id = NULL, initial_digest = NULL, created_at = NULL,
			first_reported_at = NULL, last_reported_at = NULL, expires_at = NULL, deleted_at = $2
		WHERE installation_id = $1 AND deleted_at IS NULL`, installationID, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM report_receipts WHERE installation_id = $1`, installationID)
	return err
}
