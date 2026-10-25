package store

import (
	"context"
	"errors"
	"time"

	"github.com/librescoot/connect-service/internal/report"
)

const (
	InstallationRetentionMonths = 24
	IdempotencyRetention        = 30 * 24 * time.Hour
)

var (
	ErrConflict     = errors.New("conflict")
	ErrUnauthorized = errors.New("unauthorized")
)

type Repository interface {
	Register(ctx context.Context, installationID string, credentialDigest [32]byte, payload report.Report) error
	UpdateReport(ctx context.Context, installationID string, credentialDigest [32]byte, payload report.Report) error
	Delete(ctx context.Context, installationID string, credentialDigest [32]byte) error
	Ping(ctx context.Context) error
	Sweep(ctx context.Context, now time.Time) error
}
