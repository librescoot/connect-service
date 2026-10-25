package config

import (
	"testing"
	"time"
)

func setDefaults(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"CONNECT_LISTEN_ADDR",
		"CONNECT_DATABASE_URL",
		"CONNECT_READ_HEADER_TIMEOUT_SECONDS",
		"CONNECT_READ_TIMEOUT_SECONDS",
		"CONNECT_WRITE_TIMEOUT_SECONDS",
		"CONNECT_IDLE_TIMEOUT_SECONDS",
		"CONNECT_MAX_BODY_BYTES",
		"CONNECT_DATABASE_MAX_OPEN_CONNS",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("CONNECT_DATABASE_URL", "postgres://connect:local@127.0.0.1/connect_test?sslmode=disable")
}

func TestLoadDefaultsAndValidatesDatabaseURL(t *testing.T) {
	setDefaults(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:8080" || cfg.MaxBodyBytes != 16*1024 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.ReadTimeout != 10*time.Second || cfg.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected timeout defaults: %+v", cfg)
	}
}

func TestLoadRejectsInsecureRemoteDatabaseURL(t *testing.T) {
	for _, sslMode := range []string{"require", "verify-ca"} {
		t.Run(sslMode, func(t *testing.T) {
			setDefaults(t)
			t.Setenv("CONNECT_DATABASE_URL", "postgres://connect:local@database.internal/connect?sslmode="+sslMode)
			if _, err := Load(); err == nil {
				t.Fatal("remote PostgreSQL must verify the server certificate and hostname")
			}
		})
	}
}

func TestLoadRejectsUnboundedSettings(t *testing.T) {
	setDefaults(t)
	t.Setenv("CONNECT_MAX_BODY_BYTES", "999999")
	if _, err := Load(); err == nil {
		t.Fatal("oversized body limit must be rejected")
	}
}

func TestLoadRejectsAmbiguousDatabaseTLSMode(t *testing.T) {
	setDefaults(t)
	t.Setenv("CONNECT_DATABASE_URL", "postgres://connect:local@db.example.invalid/connect?sslmode=verify-full&sslmode=disable")
	if _, err := Load(); err == nil {
		t.Fatal("duplicate sslmode values must be rejected")
	}
}

func TestLoadRejectsMalformedListenHost(t *testing.T) {
	setDefaults(t)
	t.Setenv("CONNECT_LISTEN_ADDR", "bad/host:8080")
	if _, err := Load(); err == nil {
		t.Fatal("malformed listener host must be rejected")
	}
}
