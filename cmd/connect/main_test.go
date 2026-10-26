package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

func TestCLIChild(t *testing.T) {
	if os.Getenv("CONNECT_CLI_CHILD") != "1" {
		return
	}
	index := 0
	for i, arg := range os.Args {
		if arg == "--" {
			index = i + 1
			break
		}
	}
	os.Args = append([]string{os.Args[0]}, os.Args[index:]...)
	flag.CommandLine = flag.NewFlagSet("connect", flag.ContinueOnError)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}
func TestClientCompletionSurvivesLostBouncerAcknowledgement(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/complete") {
			t.Error("unexpected polling after client completion")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	os.Chmod(root, 0700)
	stateDir := filepath.Join(root, "state")
	enrollment.PrivateDir(stateDir)
	marker := filepath.Join(root, "client-calls")
	client := filepath.Join(root, "client")
	script := "#!/bin/sh\numask 077\nprintf 'called\\n' >> '" + marker + "'\nprintf '{\"state\":\"connected\",\"profile\":\"radio-gaga/1\"}\\n'\n"
	if err := os.WriteFile(client, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	state := journal{Origin: server.URL, Client: client, Development: true, Profiles: []string{enrollment.ProfileRadioGaga}, Registration: enrollment.Registration{ID: enrollment.Token(), Token: enrollment.Token(), ExpiresAt: time.Now().Add(time.Hour).Unix()}, Offer: &enrollment.Offer{State: "approved", Profile: enrollment.ProfileRadioGaga, ProviderOrigin: "https://cloud.example.org", ClaimToken: enrollment.Token()}}
	path := filepath.Join(stateDir, "pairing.json")
	if err := enrollment.Write(path, state); err != nil {
		t.Fatal(err)
	}
	invoke := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCLIChild", "--", "-endpoint", server.URL, "-state-dir", stateDir, "-client", client, "-development", "wait")
		command.Env = append(os.Environ(), "CONNECT_CLI_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("CLI failed: %s", output)
		}
	}
	invoke()
	state = journal{}
	if err := enrollment.Read(path, &state); err != nil {
		t.Fatal(err)
	}
	if !state.Complete || state.Acknowledged || state.Offer != nil {
		t.Fatal("client completion was not durable before acknowledgement")
	}
	invoke()
	state = journal{}
	if err := enrollment.Read(path, &state); err != nil {
		t.Fatal(err)
	}
	if !state.Acknowledged || calls.Load() != 2 {
		t.Fatal("acknowledgement was not recovered")
	}
	data, _ := os.ReadFile(marker)
	if string(data) != "called\n" {
		t.Fatal("client was reapplied on acknowledgement retry")
	}
}
