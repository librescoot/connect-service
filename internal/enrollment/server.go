package enrollment

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type Session struct {
	ID                string   `json:"id"`
	PollDigest        string   `json:"poll_digest"`
	Profiles          []string `json:"profiles"`
	ExpiresAt         int64    `json:"expires_at"`
	State             string   `json:"state"`
	CodeDigest        string   `json:"code_digest,omitempty"`
	QRDigest          string   `json:"qr_digest,omitempty"`
	ClaimExpiresAt    int64    `json:"claim_expires_at,omitempty"`
	BrowserDigest     string   `json:"browser_digest,omitempty"`
	CeremonyExpiresAt int64    `json:"ceremony_expires_at,omitempty"`
	HandoffID         string   `json:"handoff_id,omitempty"`
	ProviderID        string   `json:"provider_id,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	ClaimToken        string   `json:"claim_token,omitempty"`
}
type serverState struct {
	Sessions map[string]*Session `json:"sessions"`
}
type rate struct {
	Count int
	Start int64
}
type Server struct {
	mu          sync.Mutex
	origin      string
	providers   []Provider
	path        string
	version     string
	development bool
	lock        *os.File
	state       serverState
	rates       map[string]rate
	now         func() time.Time
}

func NewServer(path, origin, version string, providers []Provider, development bool) (*Server, error) {
	var err error
	origin, err = Origin(origin, development)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for i := range providers {
		p := &providers[i]
		p.Origin, err = Origin(p.Origin, development)
		if err != nil || p.ID == "" || ids[p.ID] || !ValidToken(p.Credential) || len(p.Profiles) == 0 {
			return nil, errors.New("invalid provider registry")
		}
		ids[p.ID] = true
	}
	if len(providers) == 0 {
		return nil, errors.New("no providers configured")
	}
	lock, err := Lock(path + ".lock")
	if err != nil {
		return nil, err
	}
	s := &Server{origin: origin, providers: providers, path: path, version: version, development: development, lock: lock, state: serverState{Sessions: map[string]*Session{}}, rates: map[string]rate{}, now: time.Now}
	if err := Read(path, &s.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		lock.Close()
		return nil, err
	}
	if s.state.Sessions == nil || len(s.state.Sessions) > 512 {
		lock.Close()
		return nil, errors.New("invalid state")
	}
	return s, nil
}
func (s *Server) Close() { s.lock.Close() }
func (s *Server) Sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	expired := map[string]*Session{}
	for id, v := range s.state.Sessions {
		if v.ExpiresAt <= now || (v.CeremonyExpiresAt > 0 && v.CeremonyExpiresAt <= now) {
			expired[id] = v
			delete(s.state.Sessions, id)
		}
	}
	if len(expired) == 0 {
		return nil
	}
	if err := Write(s.path, s.state); err != nil {
		for id, v := range expired {
			s.state.Sessions[id] = v
		}
		return err
	}
	return nil
}
func (s *Server) provider(id string) *Provider {
	for i := range s.providers {
		if s.providers[i].ID == id {
			return &s.providers[i]
		}
	}
	return nil
}
func (s *Server) allow(r *http.Request, now int64) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if value := r.Header.Get("X-Real-IP"); net.ParseIP(value) != nil {
			host = value
		}
	}
	key := Digest(host)
	for k, v := range s.rates {
		if now-v.Start >= 60 {
			delete(s.rates, k)
		}
	}
	limit := 60
	if r.Method == http.MethodPost && r.URL.Path == "/pair" {
		limit = 10
	}
	if r.URL.Path == "/api/v1/enrollments" {
		limit = 10
	}
	key += ":" + r.URL.Path
	v := s.rates[key]
	if v.Start == 0 {
		if len(s.rates) >= 10000 {
			return false
		}
		v.Start = now
	}
	if v.Count >= limit {
		return false
	}
	v.Count++
	s.rates[key] = v
	return true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	u, _ := url.Parse(s.origin)
	if r.Host != u.Host || r.URL.RawQuery != "" {
		http.Error(w, "invalid request", 400)
		return
	}
	destinations := []string{}
	for _, provider := range s.providers {
		destinations = append(destinations, provider.Origin)
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self' "+strings.Join(destinations, " ")+"; frame-ancestors 'none'; base-uri 'none'")
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	defer r.Body.Close()
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		jsonReply(w, 200, map[string]string{"version": s.version})
		return
	}
	if r.URL.Path == "/pair.css" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(pairCSS))
		return
	}
	if r.URL.Path == "/pair.js" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(pairJS))
		return
	}
	if r.URL.Path == "/" && r.Method == http.MethodGet {
		http.Redirect(w, r, "/pair", 302)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	if !s.allow(r, now) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", 429)
		return
	}
	previous, _ := json.Marshal(s.state)
	restore := func() { s.state = serverState{}; _ = json.Unmarshal(previous, &s.state) }
	saved := false
	save := func() bool {
		if err := Write(s.path, s.state); err != nil {
			restore()
			http.Error(w, "unavailable", 503)
			return false
		}
		saved = true
		return true
	}
	defer func() {
		if !saved {
			restore()
		}
	}()
	for id, v := range s.state.Sessions {
		if v.ExpiresAt <= now || (v.CeremonyExpiresAt > 0 && v.CeremonyExpiresAt <= now) {
			delete(s.state.Sessions, id)
		}
	}
	if r.URL.Path == "/api/v1/enrollments" && r.Method == http.MethodPost {
		var body struct {
			Profiles []string `json:"profiles"`
		}
		if Decode(r.Body, &body) != nil || len(body.Profiles) == 0 || len(body.Profiles) > 8 {
			http.Error(w, "invalid profiles", 400)
			return
		}
		for _, p := range body.Profiles {
			if len(p) == 0 || len(p) > 64 || strings.ContainsAny(p, " \t\n\r") {
				http.Error(w, "invalid profile", 400)
				return
			}
		}
		supported := false
		for _, p := range s.providers {
			for _, profile := range body.Profiles {
				if slices.Contains(p.Profiles, profile) {
					supported = true
				}
			}
		}
		if !supported {
			http.Error(w, "unsupported profile", 422)
			return
		}
		if len(s.state.Sessions) >= 512 {
			http.Error(w, "capacity reached", 429)
			return
		}
		id, token := Token(), Token()
		v := &Session{ID: id, PollDigest: Digest(token), Profiles: body.Profiles, State: "registered", ExpiresAt: now + 7*86400}
		s.state.Sessions[id] = v
		if save() {
			jsonReply(w, 201, Registration{ID: id, Token: token, ExpiresAt: v.ExpiresAt})
		}
		return
	}
	const devicePrefix = "/api/v1/enrollments/"
	if strings.HasPrefix(r.URL.Path, devicePrefix) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, devicePrefix), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		v := s.state.Sessions[parts[0]]
		if v == nil || !ValidToken(Bearer(r)) || !Equal(v.PollDigest, Digest(Bearer(r))) {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case parts[1] == "code" && r.Method == http.MethodPost:
			if v.State != "registered" && v.State != "claim_active" {
				http.Error(w, "already selected", 409)
				return
			}
			random, _ := base64.RawURLEncoding.DecodeString(Token())
			code := make([]byte, 10)
			const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
			for i := range code {
				code[i] = alphabet[random[i]&31]
			}
			qr := Token()
			v.State = "claim_active"
			v.CodeDigest = Digest(string(code))
			v.QRDigest = Digest(qr)
			v.ClaimExpiresAt = min(now+900, v.ExpiresAt)
			if save() {
				jsonReply(w, 200, Claim{Code: string(code[:5]) + "-" + string(code[5:]), URL: s.origin + "/pair#" + qr, ExpiresAt: v.ClaimExpiresAt})
			}
			return
		case parts[1] == "claim" && r.Method == http.MethodGet:
			out := Offer{State: v.State}
			if v.State == "approved" {
				p := s.provider(v.ProviderID)
				if p == nil {
					http.Error(w, "provider unavailable", 503)
					return
				}
				out = Offer{State: v.State, SessionID: v.ID, ProviderID: v.ProviderID, ProviderOrigin: p.Origin, Profile: v.Profile, ClaimToken: v.ClaimToken, ExpiresAt: v.CeremonyExpiresAt}
			}
			jsonReply(w, 200, out)
			return
		case parts[1] == "complete" && r.Method == http.MethodPost:
			if v.State != "approved" && v.State != "complete" {
				http.Error(w, "not approved", 409)
				return
			}
			v.State = "complete"
			v.ClaimToken = ""
			if save() {
				w.WriteHeader(204)
			}
			return
		}
		http.NotFound(w, r)
		return
	}
	const providerPrefix = "/api/v1/provider/"
	if strings.HasPrefix(r.URL.Path, providerPrefix) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, providerPrefix), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		p := s.provider(parts[0])
		if p == nil || !Equal(p.Credential, Bearer(r)) {
			http.Error(w, "unauthorized", 401)
			return
		}
		var v *Session
		for _, candidate := range s.state.Sessions {
			if candidate.HandoffID == parts[1] && candidate.ProviderID == p.ID && ValidToken(parts[1]) {
				v = candidate
				break
			}
		}
		if v == nil {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			jsonReply(w, 200, map[string]any{"session_id": v.ID, "profile": v.Profile, "expires_at": v.CeremonyExpiresAt})
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				ClaimToken string `json:"claim_token"`
			}
			if Decode(r.Body, &body) != nil || !ValidToken(body.ClaimToken) {
				http.Error(w, "invalid claim", 400)
				return
			}
			if v.State == "approved" && Equal(v.ClaimToken, body.ClaimToken) {
				w.WriteHeader(204)
				return
			}
			if v.State != "selected" {
				http.Error(w, "conflict", 409)
				return
			}
			v.State = "approved"
			v.ClaimToken = body.ClaimToken
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
	cookie := ""
	if c, err := r.Cookie("connect_browser"); err == nil && ValidToken(c.Value) {
		cookie = c.Value
	} else {
		cookie = Token()
		http.SetCookie(w, &http.Cookie{Name: "connect_browser", Value: cookie, Path: "/pair", Secure: !s.development, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600})
	}
	var current *Session
	for _, v := range s.state.Sessions {
		if v.BrowserDigest == Digest(cookie) && v.CeremonyExpiresAt > now && v.State != "complete" {
			current = v
			break
		}
	}
	if r.Method == http.MethodGet {
		s.render(w, cookie, current, "")
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if r.ParseForm() != nil || !Equal(r.Form.Get("csrf"), cookie) {
		http.Error(w, "invalid form", 403)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != s.origin {
		http.Error(w, "invalid origin", 403)
		return
	}
	switch r.Form.Get("action") {
	case "exchange":
		if current == nil {
			code := NormalizeCode(r.Form.Get("code"))
			qr := r.Form.Get("qr")
			if code != "" && qr != "" {
				http.Error(w, "choose one code", 400)
				return
			}
			for _, v := range s.state.Sessions {
				if v.State == "claim_active" && v.ClaimExpiresAt > now && ((code != "" && Equal(v.CodeDigest, Digest(code))) || (ValidToken(qr) && Equal(v.QRDigest, Digest(qr)))) {
					current = v
					break
				}
			}
			if current == nil {
				s.render(w, cookie, nil, "Invalid or expired code.")
				return
			}
			current.State = "browser_open"
			current.BrowserDigest = Digest(cookie)
			current.CodeDigest = ""
			current.QRDigest = ""
			current.CeremonyExpiresAt = min(now+3600, current.ExpiresAt)
		}
		if save() {
			s.render(w, cookie, current, "")
		}
		return
	case "provider":
		if current == nil {
			http.Error(w, "expired", 410)
			return
		}
		p := s.provider(r.Form.Get("provider"))
		if p == nil {
			http.Error(w, "unknown provider", 400)
			return
		}
		profile := ""
		for _, candidate := range current.Profiles {
			if slices.Contains(p.Profiles, candidate) {
				profile = candidate
				break
			}
		}
		if profile == "" {
			http.Error(w, "unsupported profile", 422)
			return
		}
		if current.State == "browser_open" {
			current.HandoffID = Token()
			current.ProviderID = p.ID
			current.Profile = profile
			current.State = "selected"
		}
		if current.ProviderID != p.ID || (current.State != "selected" && current.State != "approved") {
			http.Error(w, "conflict", 409)
			return
		}
		if save() {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; form-action 'self' "+p.Origin+"; frame-ancestors 'none'; base-uri 'none'")
			http.Redirect(w, r, p.Origin+"/connect#"+current.HandoffID, 303)
		}
		return
	}
	http.Error(w, "invalid action", 400)
}
func NormalizeCode(code string) string {
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
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) render(w http.ResponseWriter, csrf string, v *Session, message string) {
	providers := []Provider{}
	if v != nil {
		for _, p := range s.providers {
			for _, profile := range v.Profiles {
				if slices.Contains(p.Profiles, profile) {
					providers = append(providers, Provider{ID: p.ID, Name: p.Name})
					break
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pairPage.Execute(w, struct {
		CSRF, Message string
		Session       *Session
		Providers     []Provider
	}{csrf, message, v, providers})
}
