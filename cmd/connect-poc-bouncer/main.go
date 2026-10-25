package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/librescoot/connect-service/internal/poc"
)

func main() {
	origin := flag.String("origin", "http://127.0.0.1:4300", "numeric loopback HTTP origin")
	provider := flag.String("sunshine", "http://127.0.0.1:4301", "local Sunshine origin")
	state := flag.String("state", "", "private bouncer state file")
	flag.Parse()
	if *state == "" {
		log.Fatal("-state is required")
	}
	handler, err := poc.NewBouncer(*state, *origin, *provider, os.Getenv("CONNECT_POC_PROVIDER_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	u, _ := url.Parse(*origin)
	server := &http.Server{Addr: u.Host, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fmt.Printf("Local pairing bouncer: %s/pair\n", *origin)
	log.Fatal(server.ListenAndServe())
}
