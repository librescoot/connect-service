package poc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func request(t *testing.T, client *http.Client, method, endpoint, token, body string, status int) []byte {
	t.Helper()
	r, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, endpoint, response.StatusCode, status, data)
	}
	return data
}
func startBouncer(t *testing.T, path, provider, credential string) (*httptest.Server, *Bouncer) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	handler, err := NewBouncer(path, "http://"+server.Listener.Addr().String(), provider, credential)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	return server, handler
}
func form(t *testing.T, client *http.Client, endpoint string, values url.Values, status int) []byte {
	t.Helper()
	response, err := client.PostForm(endpoint, values)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != status {
		t.Fatalf("form: %d: %s", response.StatusCode, body)
	}
	return body
}
func csrf(t *testing.T, body []byte) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatal("missing CSRF token")
	}
	return string(m[1])
}
func TestThreeComponentExchangeAndResume(t *testing.T) {
	ctx := context.Background()
	claim, credential := RandomToken(), RandomToken()
	var sessionID string
	probes := 0
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SessionID string `json:"session_id"`
		}
		if Decode(r.Body, &body) != nil || body.SessionID != sessionID {
			w.WriteHeader(409)
			return
		}
		switch r.URL.Path {
		case "/connect_poc/exchange":
			if bearer(r) != claim {
				w.WriteHeader(401)
				return
			}
			jsonResponse(w, 200, Configuration{Profile: "sunshine-poc/v1", SessionID: sessionID, Credential: credential})
		case "/connect_poc/connection":
			if bearer(r) != credential {
				w.WriteHeader(401)
				return
			}
			probes++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer cloud.Close()
	root := t.TempDir()
	os.Chmod(root, 0700)
	bouncerPath := filepath.Join(root, "bouncer", "state.json")
	providerToken := RandomToken()
	server, b := startBouncer(t, bouncerPath, cloud.URL, providerToken)
	deviceDir := filepath.Join(root, "scooter")
	d, err := OpenDevice(deviceDir, server.URL, cloud.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDevice(deviceDir, server.URL, cloud.URL); err == nil {
		t.Fatal("concurrent device accepted")
	}
	if err := d.Register(ctx); err != nil {
		t.Fatal(err)
	}
	sessionID = d.state.Registration.ID
	if err := d.Register(ctx); err != nil {
		t.Fatal(err)
	}
	claimInfo, err := d.Code(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.Code(ctx)
	if err != nil || second != claimInfo {
		t.Fatal("code was not stable")
	}
	done, err := d.Step(ctx)
	if err != nil || done {
		t.Fatal("connected before web approval")
	}
	jar, _ := cookiejar.New(nil)
	browser := HTTPClient()
	browser.Jar = jar
	body := request(t, browser, "GET", server.URL+"/pair", "", "", 200)
	token := csrf(t, body)
	form(t, browser, server.URL+"/pair", url.Values{"action": {"exchange"}, "csrf": {"wrong"}, "code": {claimInfo.Code}}, 403)
	body = form(t, browser, server.URL+"/pair", url.Values{"action": {"exchange"}, "csrf": {token}, "code": {strings.ToLower(claimInfo.Code)}}, 200)
	if !bytes.Contains(body, []byte("Continue to Sunshine")) {
		t.Fatal("missing provider chooser")
	}
	form(t, browser, server.URL+"/pair", url.Values{"action": {"provider"}, "csrf": {token}}, 303)
	s := b.state.Sessions[sessionID]
	handoff := s.HandoffID
	request(t, HTTPClient(), "GET", server.URL+"/poc/v1/provider/"+handoff, "wrong", "", 401)
	request(t, HTTPClient(), "GET", server.URL+"/poc/v1/provider/"+handoff, providerToken, "", 200)
	payload := `{"claim_token":"` + claim + `"}`
	for i := 0; i < 2; i++ {
		request(t, HTTPClient(), "POST", server.URL+"/poc/v1/provider/"+handoff, providerToken, payload, 204)
	}
	request(t, HTTPClient(), "POST", server.URL+"/poc/v1/provider/"+handoff, providerToken, `{"claim_token":"`+RandomToken()+`"}`, 409)
	// Restart both sides after delivery; no rotated token and no second logical enrollment.
	d.Close()
	restored, err := NewBouncer(bouncerPath, server.URL, cloud.URL, providerToken)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.state = restored.state
	b.mu.Unlock()
	d, err = OpenDevice(deviceDir, server.URL, cloud.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	done, err = d.Step(ctx)
	if err != nil || !done {
		t.Fatalf("resume: done=%v err=%v", done, err)
	}
	if d.Status() != "connected" {
		t.Fatal(d.Status())
	}
	done, err = d.Step(ctx)
	if err != nil || !done || probes != 1 {
		t.Fatalf("replayed apply: %v %v %d", done, err, probes)
	}
	var config Configuration
	if err := ReadPrivate(filepath.Join(deviceDir, "cloud.json"), &config); err != nil {
		t.Fatal(err)
	}
	if config.Credential != credential {
		t.Fatal("wrong applied credential")
	}
	persisted, _ := os.ReadFile(bouncerPath)
	if bytes.Contains(persisted, []byte(claim)) || bytes.Contains(persisted, []byte(credential)) {
		t.Fatal("completed bouncer retained secret")
	}
	request(t, HTTPClient(), "GET", server.URL+"/poc/v1/device/"+sessionID+"/offer", RandomToken(), "", 401)
}
func TestExpiryAndPrivateState(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "bouncer.json")
	server, b := startBouncer(t, path, "http://127.0.0.1:4301", RandomToken())
	data := request(t, HTTPClient(), "POST", server.URL+"/poc/v1/registrations", "", "", 201)
	var registration Registration
	json.Unmarshal(data, &registration)
	request(t, HTTPClient(), "POST", server.URL+"/poc/v1/device/"+registration.ID+"/code", registration.Token, "", 200)
	b.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	request(t, HTTPClient(), "GET", server.URL+"/poc/v1/device/"+registration.ID+"/offer", registration.Token, "", 401)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBouncer(path, server.URL, "http://127.0.0.1:4301", RandomToken()); err == nil {
		t.Fatal("world readable state accepted")
	}
}
func TestLoopbackOnly(t *testing.T) {
	for _, raw := range []string{"http://example.com:4300", "https://127.0.0.1:4300", "http://localhost:4300", "http://192.168.7.1:4300", "http://127.0.0.1:4300/path", "http://user:pass@127.0.0.1:4300", "http://127.0.0.1:4300?token=abc"} {
		if _, err := LoopbackOrigin(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:4300", "http://[::1]:4300"} {
		if _, err := LoopbackOrigin(raw); err != nil {
			t.Fatal(err)
		}
	}
}
func TestWriteFailureDoesNotExposeRegistration(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	server, b := startBouncer(t, filepath.Join(root, "state.json"), "http://127.0.0.1:4301", RandomToken())
	b.path = filepath.Join(root, "missing-file", "state.json")
	os.WriteFile(filepath.Join(root, "missing-file"), []byte("not a directory"), 0600)
	request(t, HTTPClient(), "POST", server.URL+"/poc/v1/registrations", "", "", 500)
	if len(b.state.Sessions) != 0 {
		t.Fatal("failed mutation survived")
	}
}
