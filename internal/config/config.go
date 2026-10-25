package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddress        string
	DatabaseURL          string
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	MaxBodyBytes         int64
	DatabaseMaxOpenConns int
}

func Load() (Config, error) {
	listen := envOrDefault("CONNECT_LISTEN_ADDR", "127.0.0.1:8080")
	if err := validateListenAddress(listen); err != nil {
		return Config{}, fmt.Errorf("CONNECT_LISTEN_ADDR: %w", err)
	}
	databaseURL := strings.TrimSpace(os.Getenv("CONNECT_DATABASE_URL"))
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, fmt.Errorf("CONNECT_DATABASE_URL: %w", err)
	}

	readHeaderTimeout, err := durationSeconds("CONNECT_READ_HEADER_TIMEOUT_SECONDS", 5, 2, 30)
	if err != nil {
		return Config{}, err
	}
	readTimeout, err := durationSeconds("CONNECT_READ_TIMEOUT_SECONDS", 10, 1, 60)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := durationSeconds("CONNECT_WRITE_TIMEOUT_SECONDS", 10, 1, 60)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := durationSeconds("CONNECT_IDLE_TIMEOUT_SECONDS", 60, 10, 300)
	if err != nil {
		return Config{}, err
	}
	maxBodyBytes, err := int64Value("CONNECT_MAX_BODY_BYTES", 16*1024, 1024, 64*1024)
	if err != nil {
		return Config{}, err
	}
	databaseMaxOpenConns, err := intValue("CONNECT_DATABASE_MAX_OPEN_CONNS", 10, 1, 50)
	if err != nil {
		return Config{}, err
	}

	return Config{
		ListenAddress:        listen,
		DatabaseURL:          databaseURL,
		ReadHeaderTimeout:    readHeaderTimeout,
		ReadTimeout:          readTimeout,
		WriteTimeout:         writeTimeout,
		IdleTimeout:          idleTimeout,
		MaxBodyBytes:         maxBodyBytes,
		DatabaseMaxOpenConns: databaseMaxOpenConns,
	}, nil
}

func validateListenAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("must be a host:port address")
	}
	if host != "" && net.ParseIP(host) == nil && !validHostname(host) {
		return errors.New("invalid host")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validHostname(host string) bool {
	if len(host) > 253 || strings.TrimSpace(host) != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validateDatabaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Hostname() == "" {
		return errors.New("must be a PostgreSQL URL with a host")
	}
	if parsed.User == nil || parsed.User.Username() == "" || parsed.Path == "" || parsed.Path == "/" {
		return errors.New("must include a database name and username")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query["sslmode"]) > 1 {
		return errors.New("invalid PostgreSQL URL query")
	}
	sslMode := ""
	if modes := query["sslmode"]; len(modes) == 1 {
		sslMode = modes[0]
	}
	host := parsed.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if isLocal {
		if sslMode != "" && sslMode != "disable" && sslMode != "verify-full" {
			return errors.New("invalid sslmode for local PostgreSQL")
		}
		return nil
	}
	if sslMode != "verify-full" {
		return errors.New("remote PostgreSQL requires sslmode=verify-full")
	}
	return nil
}

func durationSeconds(key string, defaultValue, minimum, maximum int) (time.Duration, error) {
	value, err := intValue(key, defaultValue, minimum, maximum)
	if err != nil {
		return 0, err
	}
	return time.Duration(value) * time.Second, nil
}

func intValue(key string, defaultValue, minimum, maximum int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func int64Value(key string, defaultValue, minimum, maximum int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
