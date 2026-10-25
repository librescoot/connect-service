package poc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestNoContactBeforeExplicitRegister(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	root := t.TempDir()
	os.Chmod(root, 0700)
	device, err := OpenDevice(filepath.Join(root, "scooter"), server.URL, "http://127.0.0.1:4301")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if device.Status() != "not_registered" {
		t.Fatal("unexpected initial state")
	}
	if _, err := device.Code(context.Background()); err == nil {
		t.Fatal("code succeeded before registration")
	}
	if _, err := device.Step(context.Background()); err == nil {
		t.Fatal("wait succeeded before registration")
	}
	if calls.Load() != 0 {
		t.Fatal("unrequested request")
	}
	if err := device.Register(context.Background()); err == nil {
		t.Fatal("expected unavailable service")
	}
	if calls.Load() != 1 {
		t.Fatal("explicit registration did not contact bouncer")
	}
}
func TestEndpointChangeAndSymlinkRejected(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "device.json")
	state := DeviceState{Bouncer: "http://127.0.0.1:4300", Provider: "http://127.0.0.1:4301"}
	if err := WritePrivate(path, state); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDevice(root, "http://127.0.0.1:4302", state.Provider); err == nil {
		t.Fatal("forwarded credentials to new endpoint")
	}
	target := filepath.Join(root, "other.json")
	if err := os.Symlink(path, target); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(target, state); err == nil {
		t.Fatal("wrote through symlink")
	}
	if err := ReadPrivate(target, &state); err == nil {
		t.Fatal("read through symlink")
	}
}
