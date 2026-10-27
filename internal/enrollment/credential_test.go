package enrollment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdCredentialPermissionsDoNotRelaxStatePermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "credential.json")
	if err := os.WriteFile(path, []byte(`{"origin":"https://connect.example"}`), 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Origin string `json:"origin"`
	}
	if err := ReadCredential(path, &config); err != nil {
		t.Fatal(err)
	}
	if err := Read(path, &config); err == nil {
		t.Fatal("group-readable state accepted")
	}
	for _, mode := range []os.FileMode{0644, 0660, 0441} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := ReadCredential(path, &config); err == nil {
			t.Fatalf("unsafe credential mode %o accepted", mode)
		}
	}
}
