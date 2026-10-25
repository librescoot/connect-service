package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/librescoot/connect-service/internal/poc"
)

func main() {
	state := flag.String("state-dir", "", "private disposable scooter state directory")
	bouncer := flag.String("bouncer", "http://127.0.0.1:4300", "local connect origin")
	provider := flag.String("sunshine", "http://127.0.0.1:4301", "pinned local Sunshine origin")
	timeout := flag.Duration("timeout", 10*time.Minute, "maximum wait for web approval")
	flag.Parse()
	if *state == "" || flag.NArg() != 1 {
		log.Fatal("usage: connect-poc-device -state-dir DIR [options] register|code|wait|status")
	}
	d, err := poc.OpenDevice(*state, *bouncer, *provider)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, deadline := context.WithTimeout(ctx, *timeout)
	defer deadline()
	switch flag.Arg(0) {
	case "register":
		if err := d.Register(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Registered with connect. Credential saved privately. Run code when ready to pair.")
	case "code":
		claim, err := d.Code(ctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Visit %s/pair\nCode: %s\nPairing URL: %s\nExpires: %s\n", *bouncer, claim.Code, claim.URL, time.Unix(claim.ExpiresAt, 0).UTC().Format(time.RFC3339))
	case "wait":
		for {
			done, err := d.Step(ctx)
			if err != nil {
				log.Fatal(err)
			}
			if done {
				fmt.Println("Connected to local Sunshine. Disposable configuration saved in cloud.json.")
				return
			}
			select {
			case <-ctx.Done():
				log.Fatal("wait ended; rerun wait to resume")
			case <-time.After(time.Second):
			}
		}
	case "status":
		fmt.Println(d.Status())
	default:
		log.Fatal("expected register, code, wait or status")
	}
}
