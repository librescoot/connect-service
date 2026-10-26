package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"time"

	"github.com/librescoot/connect-service/internal/enrollment"
)

var version = "development"

type journal struct {
	Origin       string                  `json:"origin"`
	Client       string                  `json:"client"`
	ClientConfig string                  `json:"client_config"`
	Development  bool                    `json:"development"`
	Profiles     []string                `json:"profiles"`
	Registration enrollment.Registration `json:"registration"`
	Claim        *enrollment.Claim       `json:"claim,omitempty"`
	Offer        *enrollment.Offer       `json:"offer,omitempty"`
	Complete     bool                    `json:"complete"`
	Acknowledged bool                    `json:"acknowledged"`
}

func request(ctx context.Context, method, endpoint, token string, body, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := enrollment.Client().Do(req)
	if err != nil {
		return errors.New("connect service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("connect service returned HTTP %d", response.StatusCode)
	}
	if result != nil {
		return enrollment.Decode(response.Body, result)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	originArg := flag.String("endpoint", "https://connect.librescoot.org", "trusted rendezvous origin")
	directory := flag.String("state-dir", "/data/connect-service", "private pairing journal directory")
	binary := flag.String("client", "radio-gaga", "installed client executable")
	clientConfig := flag.String("client-config", "", "local client config path; empty uses its managed default")
	development := flag.Bool("development", false, "allow isolated loopback HTTP testing")
	identityFile := flag.String("identity-file", "", "synthetic identity file for isolated client tests")
	timeout := flag.Duration("timeout", 15*time.Minute, "maximum wait for web approval and safe application")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if flag.NArg() != 1 {
		return errors.New("usage: connect [options] register|code|wait|status")
	}
	origin, err := enrollment.Origin(*originArg, *development)
	if err != nil {
		return err
	}
	client, err := exec.LookPath(*binary)
	if err != nil {
		return errors.New("installed cloud client not found")
	}
	client, err = filepath.Abs(client)
	if err != nil {
		return err
	}
	if err := enrollment.PrivateDir(*directory); err != nil {
		return err
	}
	lock, err := enrollment.Lock(filepath.Join(*directory, "control.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	path := filepath.Join(*directory, "pairing.json")
	state := journal{Origin: origin, Client: client, ClientConfig: *clientConfig, Development: *development}
	if err := enrollment.Read(path, &state); err != nil && !os.IsNotExist(err) {
		return err
	}
	if state.Origin != origin || state.Client != client || state.ClientConfig != *clientConfig || state.Development != *development {
		return errors.New("trust target changed; use a separate state directory")
	}
	save := func() error { return enrollment.Write(path, state) }
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, *timeout)
	defer deadline()
	deviceURL := func(action string) string {
		return origin + "/api/v1/enrollments/" + state.Registration.ID + "/" + action
	}
	switch flag.Arg(0) {
	case "register":
		if state.Registration.ID != "" {
			fmt.Println("Already registered.")
			return nil
		}
		cmd := exec.CommandContext(ctx, client, "-connect-capabilities")
		out, err := cmd.Output()
		if err != nil {
			return errors.New("client does not support enrollment")
		}
		var capabilities struct {
			Profiles []string `json:"profiles"`
		}
		if enrollment.Decode(bytes.NewReader(out), &capabilities) != nil || len(capabilities.Profiles) == 0 {
			return errors.New("invalid client capabilities")
		}
		state.Profiles = capabilities.Profiles
		if err := request(ctx, http.MethodPost, origin+"/api/v1/enrollments", "", capabilities, &state.Registration); err != nil {
			return err
		}
		if !enrollment.ValidToken(state.Registration.ID) || !enrollment.ValidToken(state.Registration.Token) || state.Registration.ExpiresAt <= time.Now().Unix() {
			return errors.New("invalid registration")
		}
		if err := save(); err != nil {
			return err
		}
		fmt.Println("Registered. Polling credential saved privately; run code to start web pairing.")
		return nil
	case "status":
		status := "not_registered"
		if state.Registration.ID != "" {
			status = "registered"
		}
		if state.Claim != nil {
			status = "waiting_for_web_setup"
		}
		if state.Offer != nil {
			status = "applying"
		}
		if state.Complete {
			status = "connected"
		}
		fmt.Println(status)
		return nil
	case "code":
		if state.Registration.ID == "" {
			return errors.New("run register first")
		}
		if state.Complete {
			return errors.New("already connected")
		}
		if state.Claim == nil || state.Claim.ExpiresAt <= time.Now().Unix() {
			var claim enrollment.Claim
			if err := request(ctx, http.MethodPost, deviceURL("code"), state.Registration.Token, nil, &claim); err != nil {
				return err
			}
			if enrollment.NormalizeCode(claim.Code) == "" || claim.ExpiresAt <= time.Now().Unix() {
				return errors.New("invalid claim window")
			}
			state.Claim = &claim
			if err := save(); err != nil {
				return err
			}
		}
		fmt.Printf("Visit %s/pair\nCode: %s\nPairing URL: %s\nExpires: %s\n", origin, state.Claim.Code, state.Claim.URL, time.Unix(state.Claim.ExpiresAt, 0).UTC().Format(time.RFC3339))
		return nil
	case "wait":
		if state.Registration.ID == "" {
			return errors.New("run register first")
		}
		if state.Complete {
			if !state.Acknowledged {
				if request(ctx, http.MethodPost, deviceURL("complete"), state.Registration.Token, nil, nil) == nil {
					state.Acknowledged = true
					if err := save(); err != nil {
						return err
					}
				}
			}
			fmt.Println("Already connected.")
			return nil
		}
		for {
			if state.Offer == nil {
				var offer enrollment.Offer
				if err := request(ctx, http.MethodGet, deviceURL("claim"), state.Registration.Token, nil, &offer); err != nil {
					return err
				}
				if offer.State == "approved" {
					provider, err := enrollment.Origin(offer.ProviderOrigin, *development)
					if err != nil || provider != offer.ProviderOrigin || offer.SessionID != state.Registration.ID || !slices.Contains(state.Profiles, offer.Profile) || !enrollment.ValidToken(offer.ClaimToken) || offer.ExpiresAt <= time.Now().Unix() {
						return errors.New("invalid provider claim")
					}
					state.Offer = &offer
					if err := save(); err != nil {
						return err
					}
				}
			}
			if state.Offer != nil {
				body := struct {
					SessionID      string `json:"session_id"`
					Profile        string `json:"profile"`
					ProviderOrigin string `json:"provider_origin"`
					ClaimToken     string `json:"claim_token"`
				}{state.Offer.SessionID, state.Offer.Profile, state.Offer.ProviderOrigin, state.Offer.ClaimToken}
				input, _ := json.Marshal(body)
				args := []string{"-connect-enroll"}
				if *clientConfig != "" {
					args = append(args, "-config", *clientConfig)
				}
				if *development {
					args = append(args, "-connect-development")
					if *identityFile != "" {
						args = append(args, "-connect-identity-file", *identityFile)
					}
				}
				cmd := exec.CommandContext(ctx, client, args...)
				cmd.Stdin = bytes.NewReader(input)
				cmd.Stderr = io.Discard
				out, applyErr := cmd.Output()
				var result struct {
					State   string `json:"state"`
					Profile string `json:"profile"`
				}
				if applyErr == nil && enrollment.Decode(bytes.NewReader(out), &result) == nil && result.State == "connected" && result.Profile == state.Offer.Profile {
					state.Complete = true
					state.Offer = nil
					state.Claim = nil
					if err := save(); err != nil {
						return err
					}
					if err := request(ctx, http.MethodPost, deviceURL("complete"), state.Registration.Token, nil, nil); err == nil {
						state.Acknowledged = true
						if err := save(); err != nil {
							return err
						}
					} else {
						fmt.Fprintln(os.Stderr, "Connected; rendezvous acknowledgement is pending.")
					}
					fmt.Println("Connected. The client applied and verified its own configuration.")
					return nil
				}
				fmt.Fprintln(os.Stderr, "Client enrollment is incomplete; retrying the same claim.")
			}
			select {
			case <-ctx.Done():
				return errors.New("wait ended; rerun wait to resume")
			case <-time.After(10 * time.Second):
			}
		}
	default:
		return errors.New("expected register, code, wait or status")
	}
}
