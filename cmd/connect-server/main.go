package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/librescoot/connect-service/internal/config"
	"github.com/librescoot/connect-service/internal/server"
	"github.com/librescoot/connect-service/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Print("connect server stopped")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		log.Print("configuration invalid")
		return err
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Print("database initialization failed")
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(cfg.DatabaseMaxOpenConns)
	db.SetMaxIdleConns(cfg.DatabaseMaxOpenConns)
	db.SetConnMaxLifetime(30 * time.Minute)

	startupCtx, startupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startupCancel()
	if err := db.PingContext(startupCtx); err != nil {
		log.Print("database unavailable")
		return err
	}
	if err := store.Migrate(startupCtx, db); err != nil {
		log.Print("database migration failed")
		return err
	}
	repository := store.NewPostgres(db)
	if err := repository.Sweep(startupCtx, time.Now().UTC()); err != nil {
		log.Print("retention sweep failed")
		return err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		log.Print("HTTP listener unavailable")
		return err
	}
	httpServer := &http.Server{
		Handler:           server.NewHandler(repository, cfg.MaxBodyBytes, cfg.WriteTimeout),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    16 * 1024,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpServer.Serve(listener)
	}()
	go runRetentionSweep(ctx, repository)

	log.Print("connect server listening")
	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print("HTTP server failed")
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

func runRetentionSweep(ctx context.Context, repository store.Repository) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := repository.Sweep(sweepCtx, time.Now().UTC())
			cancel()
			if err != nil {
				log.Print("retention sweep failed")
			}
		}
	}
}
