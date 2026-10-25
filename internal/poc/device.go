package poc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type DeviceState struct {
	Bouncer       string         `json:"bouncer"`
	Provider      string         `json:"provider"`
	Registration  Registration   `json:"registration"`
	Claim         *Claim         `json:"claim,omitempty"`
	Offer         *Offer         `json:"offer,omitempty"`
	Configuration *Configuration `json:"configuration,omitempty"`
	Complete      bool           `json:"complete"`
}
type Device struct {
	path   string
	state  DeviceState
	client *http.Client
	lock   *os.File
}

func OpenDevice(dir, bouncer, provider string) (*Device, error) {
	bouncer, err := LoopbackOrigin(bouncer)
	if err != nil {
		return nil, err
	}
	provider, err = LoopbackOrigin(provider)
	if err != nil {
		return nil, err
	}
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	// One process owns the journal and any pending exchange at a time.
	lockPath := filepath.Join(dir, "lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another CLI owns this state directory")
	}
	d := &Device{path: filepath.Join(dir, "device.json"), client: HTTPClient(), lock: lock, state: DeviceState{Bouncer: bouncer, Provider: provider}}
	if err := ReadPrivate(d.path, &d.state); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.Close()
		return nil, err
	}
	if d.state.Bouncer != bouncer || d.state.Provider != provider {
		d.Close()
		return nil, errors.New("endpoint changed; use a new state directory")
	}
	return d, nil
}
func (d *Device) Close()      { _ = d.lock.Close() }
func (d *Device) save() error { return WritePrivate(d.path, d.state) }
func (d *Device) Register(ctx context.Context) error {
	if d.state.Registration.ID != "" {
		return nil
	}
	var registration Registration
	if err := d.request(ctx, http.MethodPost, d.state.Bouncer+"/poc/v1/registrations", "", nil, &registration); err != nil {
		return err
	}
	if !validToken(registration.ID) || !validToken(registration.Token) || registration.ExpiresAt <= time.Now().Unix() {
		return errors.New("invalid registration response")
	}
	d.state.Registration = registration
	return d.save()
}
func (d *Device) Code(ctx context.Context) (Claim, error) {
	if d.state.Registration.ID == "" {
		return Claim{}, errors.New("run register first")
	}
	if d.state.Complete {
		return Claim{}, errors.New("already connected")
	}
	if c := d.state.Claim; c != nil && c.ExpiresAt > time.Now().Unix() {
		return *c, nil
	}
	var claim Claim
	if err := d.request(ctx, http.MethodPost, d.deviceURL("code"), d.state.Registration.Token, nil, &claim); err != nil {
		return claim, err
	}
	if normalizeCode(claim.Code) == "" || claim.ExpiresAt <= time.Now().Unix() {
		return Claim{}, errors.New("invalid code response")
	}
	d.state.Claim = &claim
	return claim, d.save()
}
func (d *Device) deviceURL(action string) string {
	return d.state.Bouncer + "/poc/v1/device/" + d.state.Registration.ID + "/" + action
}
func (d *Device) Status() string {
	if d.state.Complete {
		return "connected"
	}
	if d.state.Configuration != nil {
		return "configuration_saved"
	}
	if d.state.Offer != nil {
		return "claim_received"
	}
	if d.state.Claim != nil {
		return "waiting_for_user"
	}
	if d.state.Registration.ID != "" {
		return "registered"
	}
	return "not_registered"
}

// Step resumes the same exchange after interruption. It never prints a cloud credential.
func (d *Device) Step(ctx context.Context) (bool, error) {
	if d.state.Registration.ID == "" {
		return false, errors.New("run register first")
	}
	if d.state.Complete {
		return true, nil
	}
	if d.state.Offer == nil {
		var offer Offer
		if err := d.request(ctx, http.MethodGet, d.deviceURL("offer"), d.state.Registration.Token, nil, &offer); err != nil {
			return false, err
		}
		if offer.State != "approved" {
			return false, nil
		}
		if offer.Provider != d.state.Provider || offer.SessionID != d.state.Registration.ID || !validToken(offer.ClaimToken) || offer.ExpiresAt <= time.Now().Unix() {
			return false, errors.New("invalid provider claim")
		}
		d.state.Offer = &offer
		if err := d.save(); err != nil {
			return false, err
		}
	}
	if d.state.Configuration == nil {
		var config Configuration
		if err := d.request(ctx, http.MethodPost, d.state.Provider+"/connect_poc/exchange", d.state.Offer.ClaimToken, map[string]string{"session_id": d.state.Registration.ID}, &config); err != nil {
			return false, err
		}
		if config.Profile != "sunshine-poc/v1" || config.SessionID != d.state.Registration.ID || !validToken(config.Credential) {
			return false, errors.New("invalid cloud configuration")
		}
		d.state.Configuration = &config
		if err := d.save(); err != nil {
			return false, err
		}
	}
	config := d.state.Configuration
	if err := d.request(ctx, http.MethodPost, d.state.Provider+"/connect_poc/connection", config.Credential, map[string]string{"session_id": config.SessionID}, nil); err != nil {
		return false, err
	}
	if err := WritePrivate(filepath.Join(filepath.Dir(d.path), "cloud.json"), config); err != nil {
		return false, err
	}
	if err := d.request(ctx, http.MethodPost, d.deviceURL("complete"), d.state.Registration.Token, nil, nil); err != nil {
		return false, err
	}
	d.state.Complete = true
	d.state.Claim = nil
	d.state.Offer = nil
	return true, d.save()
}
func (d *Device) request(ctx context.Context, method, endpoint, token string, body, out any) error {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := d.client.Do(req)
	if err != nil {
		return errors.New("local service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("local service returned HTTP %d", response.StatusCode)
	}
	if out != nil {
		return Decode(response.Body, out)
	}
	return nil
}
