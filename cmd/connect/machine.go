package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

const pairingUnit = "librescoot-connect-pairing.service"

func pauseRequested(directory string) bool {
	var paused bool
	err := enrollment.Read(filepath.Join(directory, "pause.json"), &paused)
	return err == nil && paused || err != nil && !os.IsNotExist(err)
}

func clearPause(directory string) error {
	path := filepath.Join(directory, "pause.json")
	var paused bool
	if err := enrollment.Read(path, &paused); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.New("pairing control unavailable")
	}
	return os.Remove(path)
}

// pairingView is the entire machine API. Private journal fields never cross it.
type pairingView struct {
	State     string `json:"state"`
	Running   bool   `json:"running"`
	Code      string `json:"code,omitempty"`
	URL       string `json:"url,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type machineOptions struct {
	origin, directory, client, config, identity string
	development                                 bool
	timeout                                     time.Duration
}

func (o machineOptions) args() []string {
	args := []string{"-endpoint", o.origin, "-state-dir", o.directory, "-client", o.client, "-timeout", o.timeout.String()}
	if o.config != "" {
		args = append(args, "-client-config", o.config)
	}
	if o.development {
		args = append(args, "-development")
	}
	if o.identity != "" {
		args = append(args, "-identity-file", o.identity)
	}
	return args
}

type machineRun func(context.Context, string, ...string) ([]byte, error)

func machineCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	// Only systemctl's bounded, non-secret unit properties are captured.
	if binary == "systemctl" && len(args) > 0 && args[0] == "show" {
		return command.Output()
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return nil, command.Run()
}

func readPairing(o machineOptions) (journal, error) {
	state := journal{Origin: o.origin, Client: o.client, ClientConfig: o.config, Development: o.development}
	if err := enrollment.Read(filepath.Join(o.directory, "pairing.json"), &state); err != nil && !os.IsNotExist(err) {
		return journal{}, errors.New("pairing state unavailable")
	}
	if state.Origin != o.origin || state.Client != o.client || state.ClientConfig != o.config || state.Development != o.development {
		return journal{}, errors.New("pairing trust target changed")
	}
	return state, nil
}

func viewPairing(state journal, active, failed bool, now int64) pairingView {
	view := pairingView{State: "not_registered", Running: active}
	if state.Registration.ID != "" {
		view.State = "registered"
	}
	if active {
		view.State = "starting"
	}
	if state.Claim != nil {
		view.State = "waiting_for_web_setup"
		if state.Claim.ExpiresAt > now && enrollment.NormalizeCode(state.Claim.Code) != "" {
			view.Code = state.Claim.Code
			view.URL = state.Origin + "/pair"
			view.ExpiresAt = state.Claim.ExpiresAt
		}
	}
	if state.Offer != nil {
		view.State = "applying"
		view.Code = ""
		view.URL = ""
		view.ExpiresAt = 0
	}
	if failed {
		view.State = "error"
		view.Error = "Pairing stopped before completion. Check connectivity and keep the scooter stationary, then retry."
	}
	if state.Complete {
		return pairingView{State: "connected", Running: active}
	}
	return view
}

func machineStatus(ctx context.Context, o machineOptions, run machineRun) (pairingView, error) {
	state, err := readPairing(o)
	if err != nil {
		return pairingView{}, err
	}
	output, _ := run(ctx, "systemctl", "show", pairingUnit, "--property=ActiveState", "--property=Result")
	active, failed := false, false
	for _, line := range strings.Split(string(output), "\n") {
		key, value, _ := strings.Cut(line, "=")
		if key == "ActiveState" {
			active = value == "active" || value == "activating" || value == "deactivating"
		}
		if key == "Result" {
			failed = value != "" && value != "success"
		}
	}
	view := viewPairing(state, active, failed, time.Now().Unix())
	if !state.Complete && pauseRequested(o.directory) {
		view = pairingView{State: "paused", Running: active}
		if active {
			view.State = "stopping"
		}
	}
	return view, nil
}

func machineAction(ctx context.Context, o machineOptions, action, executable string, run machineRun) (pairingView, error) {
	if action != "start" && action != "status" && action != "stop" {
		return pairingView{}, errors.New("JSON actions: start, status, stop")
	}
	if err := enrollment.PrivateDir(o.directory); err != nil {
		return pairingView{}, errors.New("pairing state unavailable")
	}
	if action == "status" {
		return machineStatus(ctx, o, run)
	}
	// This lock coordinates web/BLE requests, separately from the worker's CLI lock.
	lock, err := enrollment.Lock(filepath.Join(o.directory, "interface.lock"))
	if err != nil {
		return pairingView{}, errors.New("another pairing action is in progress")
	}
	defer lock.Close()
	view, err := machineStatus(ctx, o, run)
	if err != nil {
		return view, err
	}
	if action == "stop" {
		if view.State == "connected" {
			return view, nil
		}
		// The worker pauses between steps, never by killing a config transaction.
		if err = enrollment.Write(filepath.Join(o.directory, "pause.json"), true); err != nil {
			return view, errors.New("could not pause pairing")
		}
		return machineStatus(ctx, o, run)
	}
	if view.Running || view.State == "connected" {
		return view, nil
	}
	if err = clearPause(o.directory); err != nil {
		return view, err
	}
	_, _ = run(ctx, "systemctl", "reset-failed", pairingUnit)
	args := []string{"--quiet", "--unit=" + pairingUnit, "--service-type=exec", "--property=RuntimeMaxSec=20min", "--property=TimeoutStopSec=10s", "--property=UMask=0077", "--property=StandardOutput=null", "--property=StandardError=null", "--", executable}
	args = append(args, o.args()...)
	args = append(args, "-background-worker")
	if _, err = run(ctx, "systemd-run", args...); err != nil {
		return view, errors.New("could not start pairing worker")
	}
	view.Running = true
	view.State = "starting"
	view.Error = ""
	return view, nil
}

func pairingWorker(ctx context.Context, o machineOptions, executable string, run machineRun) error {
	state, err := readPairing(o)
	if err != nil {
		return err
	}
	if state.Complete {
		return nil
	}
	// An issued provider claim may already have been applied. Preserve it for
	// a safe retry even if the bouncer acknowledgement window has expired.
	if state.Offer != nil {
		if pauseRequested(o.directory) {
			return nil
		}
		if _, err = run(ctx, executable, append(o.args(), "-cooperative-wait", "wait")...); err != nil {
			return errors.New("pairing did not complete")
		}
		return nil
	}
	if state.Registration.ID != "" {
		expired := state.Registration.ExpiresAt <= time.Now().Unix()
		if !expired {
			var offer enrollment.Offer
			err = request(ctx, http.MethodGet, o.origin+"/api/v1/enrollments/"+state.Registration.ID+"/claim", state.Registration.Token, nil, &offer)
			expired = errors.Is(err, connectHTTPError(http.StatusUnauthorized))
			if err != nil && !expired {
				return errors.New("connect service unavailable")
			}
		}
		if expired {
			lock, err := enrollment.Lock(filepath.Join(o.directory, "control.lock"))
			if err != nil {
				return errors.New("pairing state in use")
			}
			// Only the expired bouncer session is replaced, never device configuration.
			current, err := readPairing(o)
			if err == nil && !current.Complete {
				err = enrollment.Write(filepath.Join(o.directory, "pairing.json"), journal{Origin: o.origin, Client: o.client, ClientConfig: o.config, Development: o.development})
			}
			lock.Close()
			if err != nil {
				return errors.New("pairing state unavailable")
			}
			if current.Complete {
				return nil
			}
		}
	}
	if pauseRequested(o.directory) {
		return nil
	}
	if _, err = run(ctx, executable, append(o.args(), "register")...); err != nil {
		return errors.New("pairing registration failed")
	}
	if pauseRequested(o.directory) {
		return nil
	}
	// A browser-selected session may refuse a fresh code; polling resumes it.
	_, _ = run(ctx, executable, append(o.args(), "code")...)
	if pauseRequested(o.directory) {
		return nil
	}
	if _, err = run(ctx, executable, append(o.args(), "-cooperative-wait", "wait")...); err != nil {
		return errors.New("pairing did not complete")
	}
	return nil
}

func machineJSON(ctx context.Context, o machineOptions, action string) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("installed connect client unavailable")
	}
	view, err := machineAction(ctx, o, action, executable, machineCommand)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(view)
}
