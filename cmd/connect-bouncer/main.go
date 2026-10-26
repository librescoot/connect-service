package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

var version = "development"

func main() {
	configPath := flag.String("config", "/etc/connect-service/pairing.json", "private configuration file")
	state := flag.String("state", "/var/lib/connect-service/pairing.json", "private transient state file")
	listen := flag.String("listen", "127.0.0.1:8081", "loopback listener behind trusted ingress")
	development := flag.Bool("development", false, "allow loopback HTTP for isolated tests")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("loopback listener required")
	}
	var config struct {
		Origin    string                `json:"origin"`
		Providers []enrollment.Provider `json:"providers"`
	}
	if err := enrollment.ReadCredential(*configPath, &config); err != nil {
		log.Fatal("cannot read private configuration")
	}
	handler, err := enrollment.NewServer(*state, config.Origin, version, config.Providers, *development)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		server.Shutdown(shutdown)
	}()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if handler.Sweep() != nil {
					log.Print("pairing state expiry write failed")
				}
			}
		}
	}()
	log.Printf("connect bouncer %s", version)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
