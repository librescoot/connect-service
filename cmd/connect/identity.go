package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
	"github.com/redis/go-redis/v9"
)

func readIdentity(ctx context.Context, development bool, path string) enrollment.Identity {
	if development && path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			var identity enrollment.Identity
			if json.Unmarshal(data, &identity) == nil && identity.Valid() {
				return identity
			}
		}
		return enrollment.Identity{}
	}
	return readRedisIdentity(ctx, "127.0.0.1:6379")
}

func readRedisIdentity(ctx context.Context, address string) enrollment.Identity {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{Addr: address, MaxRetries: -1})
	defer client.Close()
	var identity enrollment.Identity
	identity.IMEI, _ = client.HGet(ctx, "internet", "sim-imei").Result()
	identity.ICCID, _ = client.HGet(ctx, "internet", "sim-iccid").Result()
	identity.MDBSerial, _ = client.HGet(ctx, "version:mdb", "serial_number_real").Result()
	identity.IMEI = strings.TrimSpace(identity.IMEI)
	identity.ICCID = strings.TrimSpace(identity.ICCID)
	identity.MDBSerial = strings.ToLower(strings.TrimSpace(identity.MDBSerial))
	// Treat unavailable or malformed fields independently.
	if !(enrollment.Identity{IMEI: identity.IMEI}).Valid() {
		identity.IMEI = ""
	}
	if !(enrollment.Identity{ICCID: identity.ICCID}).Valid() {
		identity.ICCID = ""
	}
	if !(enrollment.Identity{MDBSerial: identity.MDBSerial}).Valid() {
		identity.MDBSerial = ""
	}
	return identity
}
