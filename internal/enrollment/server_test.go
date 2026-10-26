package enrollment

import (
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

func call(t *testing.T, client *http.Client, method, endpoint, token, body string, status int) []byte {
	t.Helper()
	r, _ := http.NewRequest(method, endpoint, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != status {
		t.Fatalf("%s %s: HTTP %d want %d (%s)", method, endpoint, response.StatusCode, status, data)
	}
	return data
}
func setupServer(t *testing.T) (*httptest.Server, *Server, string) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	server := httptest.NewUnstartedServer(nil)
	credential := Token()
	handler, err := NewServer(filepath.Join(root, "state.json"), "http://"+server.Listener.Addr().String(), "test", []Provider{{ID: "sunshine", Name: "Sunshine", Origin: "http://127.0.0.1:4301", Profiles: []string{ProfileRadioGaga}, Credential: credential}}, true)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(func() { server.Close(); handler.Close() })
	return server, handler, credential
}
func postForm(t *testing.T, client *http.Client, endpoint string, values url.Values, status int) []byte {
	t.Helper()
	r, err := client.PostForm(endpoint, values)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if r.StatusCode != status {
		t.Fatalf("form status %d: %s", r.StatusCode, body)
	}
	return body
}
func TestProfileNegotiationAndPrivateClaim(t *testing.T) {
	server, handler, providerCredential := setupServer(t)
	var registration Registration
	json.Unmarshal(call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":["radio-gaga/1","uplink/1"]}`, 201), &registration)
	var claim Claim
	json.Unmarshal(call(t, Client(), "POST", server.URL+"/api/v1/enrollments/"+registration.ID+"/code", registration.Token, "{}", 200), &claim)
	jar, _ := cookiejar.New(nil)
	browser := Client()
	browser.Jar = jar
	page := call(t, browser, "GET", server.URL+"/pair", "", "", 200)
	matches := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(page)
	if len(matches) != 2 {
		t.Fatal("missing CSRF")
	}
	csrf := string(matches[1])
	postForm(t, browser, server.URL+"/pair", url.Values{"action": {"exchange"}, "code": {claim.Code}, "csrf": {"wrong"}}, 403)
	page = postForm(t, browser, server.URL+"/pair", url.Values{"action": {"exchange"}, "code": {strings.ToLower(claim.Code)}, "csrf": {csrf}}, 200)
	if !strings.Contains(string(page), "Continue to Sunshine") {
		t.Fatal("compatible provider missing")
	}
	postForm(t, browser, server.URL+"/pair", url.Values{"action": {"provider"}, "provider": {"sunshine"}, "csrf": {csrf}}, 303)
	handler.mu.Lock()
	handoff := handler.state.Sessions[registration.ID].HandoffID
	handler.mu.Unlock()
	providerURL := server.URL + "/api/v1/provider/sunshine/" + handoff
	call(t, Client(), "GET", providerURL, "wrong", "", 401)
	var context struct {
		SessionID string `json:"session_id"`
		Profile   string `json:"profile"`
		Expires   int64  `json:"expires_at"`
	}
	json.Unmarshal(call(t, Client(), "GET", providerURL, providerCredential, "", 200), &context)
	if context.SessionID != registration.ID || context.Profile != ProfileRadioGaga {
		t.Fatal("wrong binding/profile")
	}
	token := Token()
	payload := `{"claim_token":"` + token + `"}`
	call(t, Client(), "POST", providerURL, providerCredential, payload, 204)
	call(t, Client(), "POST", providerURL, providerCredential, payload, 204)
	call(t, Client(), "POST", providerURL, providerCredential, `{"claim_token":"`+Token()+`"}`, 409)
	offerURL := server.URL + "/api/v1/enrollments/" + registration.ID + "/claim"
	call(t, Client(), "GET", offerURL, token, "", 401)
	var offer Offer
	json.Unmarshal(call(t, Client(), "GET", offerURL, registration.Token, "", 200), &offer)
	if offer.ClaimToken != token || offer.Profile != ProfileRadioGaga || offer.ProviderOrigin != "http://127.0.0.1:4301" {
		t.Fatal("wrong offer")
	}
	call(t, Client(), "POST", server.URL+"/api/v1/enrollments/"+registration.ID+"/complete", registration.Token, "{}", 204)
	state, _ := os.ReadFile(handler.path)
	if strings.Contains(string(state), token) || strings.Contains(string(state), registration.Token) {
		t.Fatal("retained completed claim or polling plaintext")
	}
}
func TestUnsupportedProfilesRateAndExpiry(t *testing.T) {
	server, handler, _ := setupServer(t)
	call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":["unknown/1"]}`, 422)
	var registration Registration
	json.Unmarshal(call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":["radio-gaga/1"]}`, 201), &registration)
	for i := 0; i < 8; i++ {
		call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":[]}`, 400)
	}
	call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":["radio-gaga/1"]}`, 429)
	handler.mu.Lock()
	handler.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	handler.mu.Unlock()
	if err := handler.Sweep(); err != nil {
		t.Fatal(err)
	}
	var state serverState
	if err := Read(handler.path, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Sessions) != 0 {
		t.Fatal("expired sessions retained")
	}
	call(t, Client(), "GET", server.URL+"/api/v1/enrollments/"+registration.ID+"/claim", registration.Token, "", 401)
}
func TestProductionOriginsAndLargePrivateState(t *testing.T) {
	for _, origin := range []string{"http://example.org", "https://u:p@example.org", "https://example.org/path", "https://example.org?token=x"} {
		if _, err := Origin(origin, false); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	root := t.TempDir()
	os.Chmod(root, 0700)
	path := filepath.Join(root, "state.json")
	state := serverState{Sessions: map[string]*Session{}}
	for i := 0; i < 512; i++ {
		id := Token()
		state.Sessions[id] = &Session{ID: id, State: "registered", PollDigest: Digest(Token()), Profiles: []string{ProfileRadioGaga}, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	}
	if err := Write(path, state); err != nil {
		t.Fatal(err)
	}
	handler, err := NewServer(path, "https://connect.example.org", "test", []Provider{{ID: "cloud", Name: "Cloud", Origin: "https://cloud.example.org", Profiles: []string{ProfileRadioGaga}, Credential: Token()}}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	if _, err := NewServer(path, "https://connect.example.org", "test", handler.providers, false); err == nil {
		t.Fatal("second writer accepted")
	}
	if len(handler.state.Sessions) != 512 {
		t.Fatal("large state lost")
	}
}
