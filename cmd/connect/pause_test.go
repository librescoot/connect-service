package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

func TestCooperativePauseDoesNotInterruptConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	o, state := machineFixture(t)
	o.origin = server.URL
	o.development = true
	state.Origin = o.origin
	state.Development = true
	marker := filepath.Join(o.directory, "applying")
	client := filepath.Join(o.directory, "client")
	script := "#!/bin/sh\ntouch '" + marker + "'\nsleep 0.5\nprintf '{\"state\":\"connected\",\"profile\":\"radio-gaga/1\"}\\n'\n"
	if err := os.WriteFile(client, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	o.client = client
	state.Client = client
	state.Offer = &enrollment.Offer{State: "approved", Profile: enrollment.ProfileRadioGaga, ProviderOrigin: "https://cloud.example.org", ClaimToken: enrollment.Token()}
	if err := enrollment.Write(filepath.Join(o.directory, "pairing.json"), state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCLIChild", "--", "-endpoint", server.URL, "-state-dir", o.directory, "-client", client, "-development", "-cooperative-wait", "wait")
	command.Env = append(os.Environ(), "CONNECT_CLI_CHILD=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("client ended before applying: %v", err)
		case <-ctx.Done():
			t.Fatal("client did not enter application")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := enrollment.Write(filepath.Join(o.directory, "pause.json"), true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("configuration interrupted: %v", err)
	}
	current, err := readPairing(o)
	if err != nil || !current.Complete {
		t.Fatal("completed application lost to pause request")
	}
}

func TestCooperativePauseBeforeApplicationDoesNotInvokeClient(t *testing.T) {
	o, state := machineFixture(t)
	if err := enrollment.Write(filepath.Join(o.directory, "pause.json"), true); err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	// An explicit pause is honored before any network or client operation.
	state.Registration.ID = ""
	if err := enrollment.Write(filepath.Join(o.directory, "pairing.json"), state); err != nil {
		t.Fatal(err)
	}
	if err := pairingWorker(context.Background(), o, "/usr/bin/connect", run); err != nil || calls != 0 {
		t.Fatal("paused worker invoked client")
	}
}
