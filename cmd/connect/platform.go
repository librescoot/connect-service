package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

func stateDirectoryForDataPath(data string) string {
	if info, err := os.Stat(data); err == nil && info.IsDir() {
		return filepath.Join(data, "connect-service")
	}
	return "/var/lib/connect-service"
}

func installedClient(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil || name != "radio-gaga" {
		return path, err
	}
	for _, candidate := range []string{"/opt/rescoot-radio-gaga/radio-gaga", "/usr/bin/radio-gaga", "/sbin/radio-gaga"} {
		if path, found := exec.LookPath(candidate); found == nil {
			return path, nil
		}
	}
	return "", err
}
