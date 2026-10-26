package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const ProfileRadioGaga = "radio-gaga/1"

type Provider struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Origin     string   `json:"origin"`
	Profiles   []string `json:"profiles"`
	Credential string   `json:"credential"`
}
type Registration struct {
	ID        string `json:"session_id"`
	Token     string `json:"polling_token"`
	ExpiresAt int64  `json:"expires_at"`
}
type Claim struct {
	Code      string `json:"code"`
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expires_at"`
}
type Offer struct {
	State          string `json:"state"`
	SessionID      string `json:"session_id,omitempty"`
	ProviderID     string `json:"provider_id,omitempty"`
	ProviderOrigin string `json:"provider_origin,omitempty"`
	Profile        string `json:"profile,omitempty"`
	ClaimToken     string `json:"claim_token,omitempty"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
}

func Token() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Digest(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func ValidToken(s string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32
}
func Origin(raw string, development bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("invalid origin")
	}
	if u.Scheme != "https" && !(development && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return "", errors.New("HTTPS origin required")
	}
	return u.Scheme + "://" + u.Host, nil
}
func Client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func Decode(r io.Reader, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("oversized JSON")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func Bearer(r *http.Request) string {
	p := strings.Split(r.Header.Get("Authorization"), " ")
	if len(p) != 2 || p[0] != "Bearer" {
		return ""
	}
	return p[1]
}
func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	s, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !s.IsDir() || s.Mode().Perm()&0077 != 0 {
		return errors.New("private state directory required")
	}
	return nil
}
func Read(path string, v any) error {
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 {
		return errors.New("private regular state file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if s.Size() > 4<<20 {
		return errors.New("oversized state")
	}
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func Write(path string, v any) error {
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if s, err := os.Lstat(path); err == nil && (!s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0) {
		return errors.New("unsafe state file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func Lock(path string) (*os.File, error) {
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("state already in use")
	}
	return f, nil
}
