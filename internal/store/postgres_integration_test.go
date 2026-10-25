package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/librescoot/connect-service/internal/report"
)

func TestPostgresReportingLifecycle(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CONNECT_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CONNECT_TEST_DATABASE_URL is not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || !strings.HasSuffix(strings.TrimPrefix(parsed.Path, "/"), "_test") {
		t.Fatal("CONNECT_TEST_DATABASE_URL must target a database whose name ends in _test")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open PostgreSQL test database")
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal("connect to PostgreSQL test database")
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("repeat migrations: %v", err)
	}
	repository := NewPostgres(db)

	id := randomTestID(t)
	token := randomTestID(t)
	tokenBytes, _ := base64.RawURLEncoding.DecodeString(token)
	credentialDigest := sha256.Sum256(tokenBytes)
	initial := integrationReport(id, randomTestID(t), "2.3.4")
	if err := repository.Register(ctx, id, credentialDigest, initial); err != nil {
		t.Fatalf("register installation: %v", err)
	}
	if err := repository.Register(ctx, id, credentialDigest, initial); err != nil {
		t.Fatalf("retry initial registration: %v", err)
	}
	parallelCalls(t, 8, func() error { return repository.Register(ctx, id, credentialDigest, initial) })

	var storedDigest []byte
	if err := db.QueryRowContext(ctx, `SELECT credential_digest FROM installations WHERE installation_id = $1`, id).Scan(&storedDigest); err != nil {
		t.Fatalf("read credential digest: %v", err)
	}
	if !sameDigest(storedDigest, credentialDigest[:]) {
		t.Fatal("database did not store the credential digest")
	}

	changedInitial := integrationReport(id, initial.EventID, "2.3.5")
	if err := repository.Register(ctx, id, credentialDigest, changedInitial); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed initial event error = %v, want conflict", err)
	}

	update := integrationReport(id, randomTestID(t), "2.3.5")
	if err := repository.UpdateReport(ctx, id, credentialDigest, update); err != nil {
		t.Fatalf("update report: %v", err)
	}
	if err := repository.UpdateReport(ctx, id, credentialDigest, update); err != nil {
		t.Fatalf("retry report: %v", err)
	}
	parallelCalls(t, 8, func() error { return repository.UpdateReport(ctx, id, credentialDigest, update) })
	changedUpdate := integrationReport(id, update.EventID, "2.3.6")
	if err := repository.UpdateReport(ctx, id, credentialDigest, changedUpdate); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed event error = %v, want conflict", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE report_receipts SET received_at = $3 WHERE installation_id = $1 AND event_id = $2`, id, update.EventID, time.Now().Add(-31*24*time.Hour)); err != nil {
		t.Fatalf("age report receipt: %v", err)
	}
	if err := repository.Sweep(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("sweep old receipt: %v", err)
	}
	var receiptCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM report_receipts WHERE installation_id = $1 AND event_id = $2`, id, update.EventID).Scan(&receiptCount); err != nil {
		t.Fatalf("check old receipt: %v", err)
	}
	if receiptCount != 0 {
		t.Fatal("idempotency receipts older than 30 days must be removed")
	}

	if err := repository.Delete(ctx, id, credentialDigest); err != nil {
		t.Fatalf("delete installation: %v", err)
	}
	if err := repository.UpdateReport(ctx, id, credentialDigest, update); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("report after delete error = %v, want unauthorized", err)
	}
	if err := repository.Register(ctx, id, credentialDigest, initial); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale registration after delete error = %v, want conflict", err)
	}
	assertTombstone(t, ctx, db, id)

	expiredID := randomTestID(t)
	expiredToken := randomTestID(t)
	expiredTokenBytes, _ := base64.RawURLEncoding.DecodeString(expiredToken)
	expiredDigest := sha256.Sum256(expiredTokenBytes)
	expiredReport := integrationReport(expiredID, randomTestID(t), "3.0.0")
	if err := repository.Register(ctx, expiredID, expiredDigest, expiredReport); err != nil {
		t.Fatalf("register retention fixture: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE installations SET expires_at = $2 WHERE installation_id = $1`, expiredID, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("age installation: %v", err)
	}
	if err := repository.Sweep(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("expire installation: %v", err)
	}
	assertTombstone(t, ctx, db, expiredID)
	var aggregateCount int64
	if err := db.QueryRowContext(ctx, `SELECT expired_installation_count FROM reporting_retention_aggregates WHERE report_month = date_trunc('month', CURRENT_DATE)::date`).Scan(&aggregateCount); err != nil {
		t.Fatalf("read retained aggregate: %v", err)
	}
	if aggregateCount < 1 {
		t.Fatal("expiration must preserve aggregate installation counts")
	}
}

func parallelCalls(t *testing.T, count int, call func() error) {
	t.Helper()
	var wait sync.WaitGroup
	errs := make(chan error, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- call()
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("parallel idempotent request failed: %v", err)
		}
	}
}

func assertTombstone(t *testing.T, ctx context.Context, db *sql.DB, id string) {
	t.Helper()
	var deletedAt sql.NullTime
	var createdAt sql.NullTime
	var credential []byte
	var facts []byte
	if err := db.QueryRowContext(ctx, `SELECT deleted_at, created_at, credential_digest, facts FROM installations WHERE installation_id = $1`, id).Scan(&deletedAt, &createdAt, &credential, &facts); err != nil {
		t.Fatalf("read tombstone: %v", err)
	}
	if !deletedAt.Valid || createdAt.Valid || credential != nil || facts != nil {
		t.Fatal("tombstone retained report facts, creation time or a credential digest")
	}
}

func integrationReport(id, eventID, version string) report.Report {
	mdbVariant := report.BoardMDB
	mdbVersion := version
	dbcVariant := report.BoardDBC
	payload := report.Report{
		ProtocolVersion: report.ProtocolVersion,
		ConsentVersion:  report.ConsentVersion,
		InstallationID:  id,
		EventID:         eventID,
		MDB: &report.Board{
			BoardVariant:    &mdbVariant,
			FirmwareVersion: &mdbVersion,
			VersionKnown:    true,
			VersionLive:     true,
		},
		DBC:                  &report.Board{BoardVariant: &dbcVariant},
		SoftwareCapabilities: []string{report.CapabilityReporting},
	}
	if err := payload.ValidateAndCanonicalize(); err != nil {
		panic(err)
	}
	return payload
}

func randomTestID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("generate test identifier")
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
