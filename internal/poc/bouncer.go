package poc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type session struct {
	ID                string `json:"id"`
	TokenDigest       string `json:"token_digest"`
	ExpiresAt         int64  `json:"expires_at"`
	State             string `json:"state"`
	CodeDigest        string `json:"code_digest,omitempty"`
	QRDigest          string `json:"qr_digest,omitempty"`
	ClaimExpiresAt    int64  `json:"claim_expires_at,omitempty"`
	BrowserDigest     string `json:"browser_digest,omitempty"`
	CeremonyExpiresAt int64  `json:"ceremony_expires_at,omitempty"`
	HandoffID         string `json:"handoff_id,omitempty"`
	ClaimToken        string `json:"claim_token,omitempty"`
}
type diskState struct {
	Sessions map[string]*session `json:"sessions"`
}
type Bouncer struct {
	mu            sync.Mutex
	path          string
	origin        string
	provider      string
	providerToken string
	state         diskState
	now           func() time.Time
}

func NewBouncer(path, origin, provider, providerToken string) (*Bouncer, error) {
	var err error
	if origin, err = LoopbackOrigin(origin); err != nil {
		return nil, err
	}
	if provider, err = LoopbackOrigin(provider); err != nil {
		return nil, err
	}
	if !validToken(providerToken) {
		return nil, errors.New("provider credential must encode 32 random bytes")
	}
	b := &Bouncer{path: path, origin: origin, provider: provider, providerToken: providerToken, now: time.Now, state: diskState{Sessions: map[string]*session{}}}
	if err := ReadPrivate(path, &b.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if b.state.Sessions == nil {
		return nil, errors.New("invalid bouncer state")
	}
	return b, nil
}
func (b *Bouncer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; form-action 'self' "+b.provider+"; frame-ancestors 'none'; base-uri 'none'")
	expected, _ := url.Parse(b.origin)
	if r.Host != expected.Host {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query strings are not accepted", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	if r.URL.Path == "/pair.js" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(pairScript))
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Persist every successful mutation before returning a credential or redirect.
	previous, _ := json.Marshal(b.state)
	restore := func() {
		b.state = diskState{}
		_ = json.Unmarshal(previous, &b.state)
	}
	persisted := false
	save := func() bool {
		if err := WritePrivate(b.path, b.state); err != nil {
			restore()
			http.Error(w, "state unavailable", 500)
			return false
		}
		persisted = true
		return true
	}
	defer func() {
		if !persisted {
			restore()
		}
	}()
	now := b.now().Unix()
	for id, s := range b.state.Sessions {
		if s.ExpiresAt <= now {
			delete(b.state.Sessions, id)
		}
	}
	if r.URL.Path == "/poc/v1/registrations" && r.Method == http.MethodPost {
		if len(b.state.Sessions) >= 100 {
			http.Error(w, "capacity reached", 429)
			return
		}
		id, token := RandomToken(), RandomToken()
		s := &session{ID: id, TokenDigest: digest(token), ExpiresAt: now + 7*86400, State: "registered"}
		b.state.Sessions[id] = s
		if save() {
			jsonResponse(w, 201, Registration{ID: id, Token: token, ExpiresAt: s.ExpiresAt})
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/poc/v1/device/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/poc/v1/device/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		s := b.state.Sessions[parts[0]]
		if s == nil || !validToken(bearer(r)) || !equal(s.TokenDigest, digest(bearer(r))) {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case parts[1] == "code" && r.Method == http.MethodPost:
			if s.State != "registered" && s.State != "claim_active" {
				http.Error(w, "pairing already started", 409)
				return
			}
			random := RandomToken()
			raw := []byte(random)
			const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
			// Base64 characters are uniform; their low five bits are not. Use decoded random bytes.
			bytes, _ := base64.RawURLEncoding.DecodeString(random)
			for i := 0; i < 10; i++ {
				raw[i] = alphabet[bytes[i]&31]
			}
			code := string(raw[:10])
			qr := RandomToken()
			s.State = "claim_active"
			s.CodeDigest = digest(code)
			s.QRDigest = digest(qr)
			s.ClaimExpiresAt = min(now+900, s.ExpiresAt)
			if save() {
				jsonResponse(w, 200, Claim{Code: code[:5] + "-" + code[5:], URL: b.origin + "/pair#" + qr, ExpiresAt: s.ClaimExpiresAt})
			}
			return
		case parts[1] == "offer" && r.Method == http.MethodGet:
			if s.State == "approved" && now >= s.CeremonyExpiresAt {
				http.Error(w, "expired", 410)
				return
			}
			offer := Offer{State: s.State}
			if s.State == "approved" {
				offer.Provider = b.provider
				offer.SessionID = s.ID
				offer.ClaimToken = s.ClaimToken
				offer.ExpiresAt = s.CeremonyExpiresAt
			}
			jsonResponse(w, 200, offer)
			return
		case parts[1] == "complete" && r.Method == http.MethodPost:
			if s.State != "approved" && s.State != "complete" {
				http.Error(w, "not approved", 409)
				return
			}
			s.State = "complete"
			s.ClaimToken = ""
			if save() {
				w.WriteHeader(204)
			}
			return
		}
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/poc/v1/provider/") {
		if !equal(b.providerToken, bearer(r)) {
			http.Error(w, "unauthorized", 401)
			return
		}
		handoff := strings.TrimPrefix(r.URL.Path, "/poc/v1/provider/")
		var s *session
		for _, candidate := range b.state.Sessions {
			if candidate.HandoffID == handoff && validToken(handoff) {
				s = candidate
				break
			}
		}
		if s == nil {
			http.NotFound(w, r)
			return
		}
		if now >= s.CeremonyExpiresAt {
			http.Error(w, "expired", 410)
			return
		}
		if r.Method == http.MethodGet {
			jsonResponse(w, 200, map[string]any{"session_id": s.ID, "expires_at": s.CeremonyExpiresAt})
			return
		}
		if r.Method == http.MethodPost {
			var claim struct {
				ClaimToken string `json:"claim_token"`
			}
			if Decode(r.Body, &claim) != nil || !validToken(claim.ClaimToken) {
				http.Error(w, "invalid claim", 400)
				return
			}
			if s.State == "approved" && equal(s.ClaimToken, claim.ClaimToken) {
				w.WriteHeader(204)
				return
			}
			if s.State != "selected" {
				http.Error(w, "conflict", 409)
				return
			}
			s.ClaimToken = claim.ClaimToken
			s.State = "approved"
			if save() {
				w.WriteHeader(204)
			}
			return
		}
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/pair" {
		http.NotFound(w, r)
		return
	}
	browser := browserToken(w, r)
	if r.Method == http.MethodGet {
		b.render(w, browser, "", false)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if err := r.ParseForm(); err != nil || !equal(r.Form.Get("csrf"), browser) {
		http.Error(w, "invalid form", 403)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != b.origin {
		http.Error(w, "invalid origin", 403)
		return
	}
	var current *session
	for _, s := range b.state.Sessions {
		if s.BrowserDigest == digest(browser) && s.CeremonyExpiresAt > now {
			current = s
			break
		}
	}
	switch r.Form.Get("action") {
	case "exchange":
		code := normalizeCode(r.Form.Get("code"))
		qr := r.Form.Get("qr")
		if code != "" && qr != "" {
			http.Error(w, "use one capability", 400)
			return
		}
		if current == nil {
			for _, s := range b.state.Sessions {
				if s.State != "claim_active" || s.ClaimExpiresAt <= now {
					continue
				}
				if (code != "" && equal(s.CodeDigest, digest(code))) || (validToken(qr) && equal(s.QRDigest, digest(qr))) {
					current = s
					break
				}
			}
			if current == nil {
				b.render(w, browser, "Invalid or expired code.", false)
				return
			}
			current.State = "browser_open"
			current.BrowserDigest = digest(browser)
			current.CeremonyExpiresAt = min(now+3600, current.ExpiresAt)
			current.CodeDigest = ""
			current.QRDigest = ""
		}
		if save() {
			b.render(w, browser, "", true)
		}
		return
	case "provider":
		if current == nil {
			http.Error(w, "expired", 410)
			return
		}
		if current.State == "browser_open" {
			current.HandoffID = RandomToken()
			current.State = "selected"
		}
		if current.State != "selected" && current.State != "approved" {
			http.Error(w, "conflict", 409)
			return
		}
		if save() {
			http.Redirect(w, r, b.provider+"/connect_poc?handoff_id="+current.HandoffID, 303)
		}
		return
	}
	http.Error(w, "invalid action", 400)
}
func browserToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("connect_poc_browser"); err == nil && validToken(c.Value) {
		return c.Value
	}
	token := RandomToken()
	http.SetCookie(w, &http.Cookie{Name: "connect_poc_browser", Value: token, Path: "/pair", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	return token
}
func normalizeCode(code string) string {
	if len(code) == 11 && code[5] == '-' {
		code = code[:5] + code[6:]
	}
	code = strings.ToUpper(code)
	if len(code) != 10 {
		return ""
	}
	for _, c := range code {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			return ""
		}
	}
	return code
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var page = template.Must(template.New("pair").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Connect proof of concept</title><script src="/pair.js" defer></script><h1>Connect a provider</h1><p>Local proof of concept. No real scooter is changed.</p><p>{{.Error}}</p>{{if .Selected}}<p>Choose a provider. Login and confirmation happen at the provider.</p><form method="post" action="/pair"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="provider"><button>Continue to Sunshine</button></form>{{else}}<form method="post" action="/pair"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="action" value="exchange"><label>Pairing code <input name="code" autocomplete="off"></label><p>Or paste the QR capability (the part after # in the pairing URL): <input name="qr" autocomplete="off"></p><button>Find scooter</button></form>{{end}}</html>`))

const pairScript = `const capability = location.hash.slice(1);
if (location.hash) history.replaceState(null, '', '/pair');
if (/^[A-Za-z0-9_-]{43}$/.test(capability)) {
  const input = document.querySelector('input[name="qr"]');
  if (input) input.value = capability;
}`

func (b *Bouncer) render(w http.ResponseWriter, csrf, message string, selected bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, struct {
		CSRF, Error string
		Selected    bool
	}{csrf, message, selected})
}
