package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/librescoot/connect-service/internal/enrollment"
)

func TestReadRedisIdentity(t *testing.T) {
	redis := miniredis.RunT(t)
	redis.HSet("internet", "sim-imei", "123456789012345")
	redis.HSet("internet", "sim-iccid", "8949000000000000001")
	redis.HSet("version:mdb", "serial_number_real", "1234567890ABCDEF")
	got := readRedisIdentity(context.Background(), redis.Addr())
	want := (enrollment.Identity{IMEI: "123456789012345", ICCID: "8949000000000000001", MDBSerial: "1234567890abcdef"})
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	redis.HSet("internet", "sim-iccid", "invalid")
	got = readRedisIdentity(context.Background(), redis.Addr())
	if got.ICCID != "" || got.IMEI != want.IMEI || got.MDBSerial != want.MDBSerial {
		t.Fatalf("malformed field affected others: %+v", got)
	}
}

func TestRegistrationSendsIdentity(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	server := httptest.NewUnstartedServer(nil)
	handler, err := enrollment.NewServer(filepath.Join(root, "server.json"), "http://"+server.Listener.Addr().String(), "test", []enrollment.Provider{{ID: "sunshine", Name: "Sunshine", Origin: "https://sunshine.example", Profiles: []string{enrollment.ProfileRadioGaga}, Credential: enrollment.Token()}}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	client := filepath.Join(root, "client")
	if err := os.WriteFile(client, []byte("#!/bin/sh\nprintf '{\"profiles\":[\"radio-gaga/1\"]}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(root, "identity.json")
	identity := enrollment.Identity{IMEI: "123456789012345", ICCID: "8949000000000000001", MDBSerial: "1234567890abcdef"}
	data, _ := json.Marshal(identity)
	if err := os.WriteFile(identityPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCLIChild", "--", "-endpoint", server.URL, "-state-dir", filepath.Join(root, "client-state"), "-client", client, "-development", "-identity-file", identityPath, "register")
	cmd.Env = append(os.Environ(), "CONNECT_CLI_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("register: %v %s", err, out)
	}
	var state struct {
		Sessions map[string]enrollment.Session `json:"sessions"`
	}
	if err := enrollment.Read(filepath.Join(root, "server.json"), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Sessions) != 1 {
		t.Fatal("registration missing")
	}
	for _, session := range state.Sessions {
		if session.Identity == nil || *session.Identity != identity {
			t.Fatalf("identity not submitted: %+v", session.Identity)
		}
	}
}
