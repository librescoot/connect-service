package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateDirectoryAcrossFirmwareLayouts(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	if actual := stateDirectoryForDataPath(data); actual != "/var/lib/connect-service" {
		t.Fatal("stock layout selected a /data journal")
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Fatal("stock lookup created /data")
	}
	if err := os.Mkdir(data, 0755); err != nil {
		t.Fatal(err)
	}
	if actual := stateDirectoryForDataPath(data); actual != filepath.Join(data, "connect-service") {
		t.Fatal("Librescoot persistent directory not selected")
	}
}

func TestInstalledClientKeepsExplicitTrustTarget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "radio-gaga")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	if actual, err := installedClient("radio-gaga"); err != nil || actual != path {
		t.Fatal("installed PATH client not selected")
	}
	if _, err := installedClient(filepath.Join(root, "missing")); err == nil {
		t.Fatal("explicit missing client silently replaced")
	}
}
