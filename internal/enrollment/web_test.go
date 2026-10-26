package enrollment

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPairingAssetsAndPolicy(t *testing.T) {
	server, handler, _ := setupServer(t)
	for _, asset := range []struct {
		path, contentType, contains string
	}{
		{"/pair", "text/html", `href="/pair.css"`},
		{"/pair.css", "text/css", "prefers-color-scheme: dark"},
		{"/pair.js", "text/javascript", "history.replaceState"},
	} {
		response, err := server.Client().Get(server.URL + asset.path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || !strings.HasPrefix(response.Header.Get("Content-Type"), asset.contentType) {
			t.Fatalf("wrong asset response for %s", asset.path)
		}
		policy := response.Header.Get("Content-Security-Policy")
		if !strings.Contains(policy, "style-src 'self'") || strings.Contains(policy, "unsafe-inline") || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("unsafe asset policy for %s", asset.path)
		}
		if !strings.Contains(string(body), asset.contains) {
			t.Fatalf("missing asset content for %s", asset.path)
		}
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.state.Sessions) != 0 {
		t.Fatal("presentation requests created an enrollment")
	}
}

func TestPairingPresentationStatesAndEscaping(t *testing.T) {
	_, handler, _ := setupServer(t)
	handler.providers[0].Name = "Cloud <script>alert(1)</script>"
	for _, state := range []string{"browser_open", "selected", "approved"} {
		response := httptest.NewRecorder()
		handler.render(response, "test-csrf", &Session{State: state, Profiles: []string{ProfileRadioGaga}}, "")
		body := response.Body.String()
		if !strings.Contains(body, "Cloud &lt;script&gt;") || strings.Contains(body, "Cloud <script>") {
			t.Fatal("provider name was not escaped")
		}
		if !strings.Contains(body, `name="csrf" value="test-csrf"`) || !strings.Contains(body, `name="provider" value="sunshine"`) {
			t.Fatal("provider form bindings missing")
		}
		if state == "approved" && !strings.Contains(body, "Finish on your scooter") {
			t.Fatal("approved status missing")
		}
	}
	response := httptest.NewRecorder()
	handler.render(response, "test-csrf", nil, "Invalid or expired code.")
	body := response.Body.String()
	for _, want := range []string{`role="alert"`, `for="pairing-code"`, `id="pairing-code"`, `name="qr"`, `aria-current="step"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing accessible form element %s", want)
		}
	}
}
