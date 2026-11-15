package enrollment

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestPreclaimRestrictsProviderAndKeepsIdentityPrivate(t *testing.T) {
	server, handler, sunshineCredential := setupServer(t)
	handler.mu.Lock()
	handler.providers[0].PreclaimEnabled = true
	otherCredential := Token()
	handler.providers = append(handler.providers, Provider{ID: "other", Name: "Other", Origin: "https://other.example", Profiles: []string{ProfileRadioGaga}, Credential: otherCredential, PreclaimEnabled: true})
	handler.mu.Unlock()
	iccid := "8949000000000000001"
	body := `{"iccid":"` + iccid + `"}`
	preclaim := server.URL + "/api/v1/provider/sunshine/preclaims"
	call(t, Client(), http.MethodPost, preclaim, "wrong", body, 401)
	call(t, Client(), http.MethodPost, preclaim, sunshineCredential, body, 204)
	call(t, Client(), http.MethodPost, preclaim, sunshineCredential, body, 204)
	call(t, Client(), http.MethodPost, server.URL+"/api/v1/provider/other/preclaims", otherCredential, body, 409)
	call(t, Client(), http.MethodDelete, server.URL+"/api/v1/provider/other/preclaims", otherCredential, body, 409)

	var registration Registration
	json.Unmarshal(call(t, Client(), "POST", server.URL+"/api/v1/enrollments", "", `{"profiles":["radio-gaga/1"]}`, 201), &registration)
	identity := `{"imei":"123456789012345","iccid":"` + iccid + `","mdb_serial":"1234567890abcdef"}`
	identityURL := server.URL + "/api/v1/enrollments/" + registration.ID + "/identity"
	call(t, Client(), "POST", identityURL, "wrong", identity, 401)
	call(t, Client(), "POST", identityURL, registration.Token, `{"iccid":"invalid"}`, 400)
	call(t, Client(), "POST", identityURL, registration.Token, identity, 204)
	var claim Claim
	json.Unmarshal(call(t, Client(), "POST", server.URL+"/api/v1/enrollments/"+registration.ID+"/code", registration.Token, `{}`, 200), &claim)
	call(t, Client(), "POST", identityURL, registration.Token, identity, 409)
	jar, _ := cookiejar.New(nil)
	browser := Client()
	browser.Jar = jar
	page := call(t, browser, "GET", server.URL+"/pair", "", "", 200)
	cookies := jar.Cookies(mustURL(server.URL + "/pair"))
	if len(cookies) == 0 {
		t.Fatal("missing browser cookie")
	}
	csrf := cookies[0].Value
	page = postForm(t, browser, server.URL+"/pair", url.Values{"action": {"exchange"}, "code": {claim.Code}, "csrf": {csrf}}, 200)
	if strings.Contains(string(page), iccid) || strings.Contains(string(page), "Continue to Other") || !strings.Contains(string(page), "Continue to Sunshine") {
		t.Fatal("incorrect provider selection or identity leaked")
	}
	postForm(t, browser, server.URL+"/pair", url.Values{"action": {"provider"}, "provider": {"other"}, "csrf": {csrf}}, 403)
	postForm(t, browser, server.URL+"/pair", url.Values{"action": {"provider"}, "provider": {"sunshine"}, "csrf": {csrf}}, 303)
	handler.mu.Lock()
	handoff := handler.state.Sessions[registration.ID].HandoffID
	handler.mu.Unlock()
	context := call(t, Client(), "GET", server.URL+"/api/v1/provider/sunshine/"+handoff, sunshineCredential, "", 200)
	if !strings.Contains(string(context), iccid) || !strings.Contains(string(context), "1234567890abcdef") {
		t.Fatal("identity not delivered to selected provider")
	}
	call(t, Client(), "GET", server.URL+"/api/v1/provider/other/"+handoff, otherCredential, "", 404)
	call(t, Client(), "POST", server.URL+"/api/v1/provider/sunshine/"+handoff, sunshineCredential, `{"claim_token":"`+Token()+`"}`, 204)
	call(t, Client(), "POST", server.URL+"/api/v1/enrollments/"+registration.ID+"/complete", registration.Token, `{}`, 204)
	handler.mu.Lock()
	if handler.state.Sessions[registration.ID].Identity != nil {
		t.Error("completed identity retained")
	}
	handler.mu.Unlock()
	var registry map[string]string
	if err := Read(handler.path+".preclaims", &registry); err != nil || registry[iccid] != "sunshine" {
		t.Fatal("preclaim not durable", err)
	}
	handler.Close()
	restarted, err := NewServer(handler.path, handler.origin, "test", handler.providers, true)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.preclaims[iccid] != "sunshine" {
		t.Fatal("preclaim not loaded on restart")
	}
	restarted.Close()
	// The test server continues with its in-memory state; reopen its process lock.
	handler.lock, err = Lock(handler.path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	call(t, Client(), "DELETE", preclaim, sunshineCredential, body, 204)
	registry = nil
	if err := Read(handler.path+".preclaims", &registry); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry[iccid]; ok {
		t.Fatal("preclaim not removed")
	}
}

func mustURL(raw string) *url.URL { u, _ := url.Parse(raw); return u }
