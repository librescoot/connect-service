package enrollment

import (
	"crypto/sha256"
	"fmt"
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
		{"/pair.css", "text/css", "var(--font-mono)"},
		{"/assets/style.css", "text/css", "Librescoot - \"Precision Workshop\" design system"},
		{"/assets/fonts/fonts.css", "text/css", "Hanken Grotesk"},
		{"/assets/fonts/abel-latin.woff2", "font/woff2", ""},
		{"/assets/images/librescoot-logo-v3-full.png", "image/png", ""},
		{"/assets/theme-toggle.js", "text/javascript", "localStorage.getItem('theme')"},
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
		if !strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "font-src 'self'") || !strings.Contains(policy, "img-src 'self'") || strings.Contains(policy, "unsafe-inline") || response.Header.Get("Cache-Control") != "no-store" {
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

func TestSharedWebsiteAssetsAreUnmodified(t *testing.T) {
	for name, want := range map[string]string{
		"style.css":                          "0a8face47a4737b08b107eb2b7f6920a9085849fa30247ea30d0bd9adda350ab",
		"fonts/fonts.css":                    "b643da3704c7ba85b829069a914041eabcbde957e159a4a7203800d4b48235c5",
		"images/librescoot-logo-v3-full.png": "c5c542cd3ceb055afe75dde1a07e6c63e29ee267b60b87a742e83d2a2adb40a3",
		"theme-toggle.js":                    "b1a41a7e3fed48276c090551d45bfc8963ad0a90f63c25f0e5ae85177116c304",
	} {
		data, err := pairAssets.ReadFile("web/assets/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != want {
			t.Fatalf("shared website asset %s differs from its pinned source", name)
		}
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
	for _, want := range []string{`role="alert"`, `for="pairing-code"`, `id="pairing-code"`, `name="qr"`, `class="btn btn-primary"`, `class="nav nav-docs"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing accessible form element %s", want)
		}
	}
}
