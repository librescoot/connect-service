package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

func machineFixture(t *testing.T) (machineOptions, journal) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	o := machineOptions{origin: "https://connect.librescoot.org", directory: root, client: "/usr/bin/radio-gaga", timeout: 15 * time.Minute}
	state := journal{Origin: o.origin, Client: o.client, Registration: enrollment.Registration{ID: "private-id", Token: "private-polling-secret", ExpiresAt: time.Now().Add(time.Hour).Unix()}, Claim: &enrollment.Claim{Code: "01234-56789", URL: o.origin + "/pair#private-qr-secret", ExpiresAt: time.Now().Add(time.Minute).Unix()}}
	if err := enrollment.Write(filepath.Join(root, "pairing.json"), state); err != nil {
		t.Fatal(err)
	}
	return o, state
}

func TestMachineViewNeverSerializesPrivateJournal(t *testing.T) {
	o, state := machineFixture(t)
	view := viewPairing(state, true, false, time.Now().Unix())
	data, _ := json.Marshal(view)
	for _, secret := range []string{"private-id", "private-polling-secret", "private-qr-secret", "claim_token", "provider_origin"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("private journal material escaped")
		}
	}
	if view.Code != "01234-56789" || view.URL != o.origin+"/pair" || !view.Running {
		t.Fatalf("unexpected public view: %s", data)
	}
	state.Claim.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if v := viewPairing(state, true, false, time.Now().Unix()); v.Code != "" || v.URL != "" {
		t.Fatal("expired code exposed")
	}
	state.Offer = &enrollment.Offer{ClaimToken: "private-provider-secret"}
	if v := viewPairing(state, true, false, time.Now().Unix()); v.State != "applying" || v.Code != "" {
		t.Fatal("incorrect application state")
	}
	state.Complete = true
	if v := viewPairing(state, false, true, time.Now().Unix()); v.State != "connected" || v.Error != "" {
		t.Fatal("completed state replaced by worker error")
	}
}

func TestMachineStatusDoesNotBlockOnWorkerLock(t *testing.T) {
	o, _ := machineFixture(t)
	lock, err := enrollment.Lock(filepath.Join(o.directory, "control.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	run := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ActiveState=active\nResult=success\n"), nil
	}
	view, err := machineAction(context.Background(), o, "status", "/usr/bin/connect", run)
	if err != nil || !view.Running || view.Code == "" {
		t.Fatalf("status blocked or unavailable: %v", err)
	}
}

func TestMachineStartUsesOneExplicitBoundedUnit(t *testing.T) {
	o, _ := machineFixture(t)
	var commands [][]string
	run := func(_ context.Context, binary string, args ...string) ([]byte, error) {
		commands = append(commands, append([]string{binary}, args...))
		return []byte("ActiveState=inactive\nResult=success\n"), nil
	}
	view, err := machineAction(context.Background(), o, "start", "/usr/bin/connect", run)
	if err != nil || !view.Running {
		t.Fatalf("start failed: %v", err)
	}
	command := strings.Join(commands[len(commands)-1], " ")
	for _, required := range []string{"systemd-run", "--unit=" + pairingUnit, "RuntimeMaxSec=20min", "StandardOutput=null", "StandardError=null", "-- /usr/bin/connect", "-background-worker"} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing %q", required)
		}
	}
	if strings.Contains(command, "private-") || strings.Contains(command, "sh -c") {
		t.Fatal("private data or shell in worker argv")
	}
	commands = nil
	active := func(_ context.Context, binary string, args ...string) ([]byte, error) {
		commands = append(commands, []string{binary})
		return []byte("ActiveState=active\nResult=success\n"), nil
	}
	if _, err := machineAction(context.Background(), o, "start", "/usr/bin/connect", active); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 {
		t.Fatal("active worker launched twice")
	}
}

func TestMachineTrustTargetAndErrorsFailClosed(t *testing.T) {
	o, _ := machineFixture(t)
	run := func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("private-error-token")
	}
	for _, action := range []string{"shell", "start;touch /tmp/unsafe"} {
		if _, err := machineAction(context.Background(), o, action, "/usr/bin/connect", run); err == nil {
			t.Fatal("arbitrary action accepted")
		}
	}
	_, err := machineAction(context.Background(), o, "start", "/usr/bin/connect", run)
	if err == nil || strings.Contains(err.Error(), "private-error-token") {
		t.Fatal("runner error leaked or start succeeded")
	}
	o.origin = "https://attacker.invalid"
	if _, err := machineAction(context.Background(), o, "status", "/usr/bin/connect", run); err == nil {
		t.Fatal("trust target change accepted")
	}
}

func TestMachineStopRequestsPauseWithoutKillingConfiguration(t *testing.T) {
	o, _ := machineFixture(t)
	active := true
	run := func(_ context.Context, binary string, args ...string) ([]byte, error) {
		if binary == "systemctl" && args[0] == "stop" {
			t.Fatal("configuration could be interrupted")
		}
		if active {
			return []byte("ActiveState=active\nResult=success\n"), nil
		}
		return []byte("ActiveState=inactive\nResult=success\n"), nil
	}
	view, err := machineAction(context.Background(), o, "stop", "/usr/bin/connect", run)
	if err != nil || !view.Running || view.State != "stopping" || !pauseRequested(o.directory) {
		t.Fatalf("pause request failed: %v", err)
	}
	state, err := readPairing(o)
	if err != nil || state.Registration.ID == "" || state.Claim == nil {
		t.Fatal("stop destroyed pairing journal")
	}
	active = false
	view, err = machineStatus(context.Background(), o, run)
	if err != nil || view.State != "paused" || view.Code != "" {
		t.Fatal("pause state incorrect")
	}
	if _, err = machineAction(context.Background(), o, "start", "/usr/bin/connect", run); err != nil || pauseRequested(o.directory) {
		t.Fatal("explicit restart did not clear pause")
	}
}

func TestMachineWorkerPreservesDeliveredOfferAfterBouncerExpiry(t *testing.T) {
	o, state := machineFixture(t)
	state.Registration.ExpiresAt = 1
	state.Offer = &enrollment.Offer{ClaimToken: "private-claim"}
	if err := enrollment.Write(filepath.Join(o.directory, "pairing.json"), state); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	run := func(_ context.Context, binary string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{binary}, args...))
		return nil, nil
	}
	if err := pairingWorker(context.Background(), o, "/usr/bin/connect", run); err != nil {
		t.Fatal(err)
	}
	current, err := readPairing(o)
	if err != nil || current.Offer == nil || current.Offer.ClaimToken != "private-claim" {
		t.Fatal("issued offer discarded")
	}
	if len(calls) != 1 || !strings.HasSuffix(strings.Join(calls[0], " "), "-cooperative-wait wait") {
		t.Fatal("did not resume exact issued claim")
	}
}

func TestMachineWorkerKeepsCompletedJournalAndResetsOnlyExpiredSession(t *testing.T) {
	o, state := machineFixture(t)
	state.Complete = true
	enrollment.Write(filepath.Join(o.directory, "pairing.json"), state)
	calls := 0
	run := func(context.Context, string, ...string) ([]byte, error) { calls++; return nil, nil }
	if err := pairingWorker(context.Background(), o, "/usr/bin/connect", run); err != nil || calls != 0 {
		t.Fatal("completed connection reapplied")
	}
	state.Complete = false
	state.Registration.ExpiresAt = 1
	enrollment.Write(filepath.Join(o.directory, "pairing.json"), state)
	if err := pairingWorker(context.Background(), o, "/usr/bin/connect", run); err != nil {
		t.Fatal(err)
	}
	current, err := readPairing(o)
	if err != nil || current.Registration.ID != "" || current.Origin != o.origin || calls != 3 {
		t.Fatal("expired session not reset safely")
	}
}
