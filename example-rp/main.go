// Command example-rp is a disposable OpenID Connect Relying Party used to
// exercise and inspect an OP's flows by hand: authorization_code (with and
// without PKCE-driven consent for offline_access), password (ROPC),
// client_credentials, refresh_token, dynamic client registration, and both
// front-channel and back-channel RP-initiated logout. Everything lives in
// memory; restarting the process resets all state.
package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("addr", ":9090", "address to listen on")
	publicURL := flag.String("public-url", "", "externally reachable base URL for this app, used to build redirect/logout URIs (default: http://localhost<addr>)")
	issuer := flag.String("issuer", "", "OP issuer URL, e.g. http://localhost:8080 (required)")
	flag.Parse()

	if *issuer == "" {
		fmt.Println("example-rp: -issuer is required, e.g.:")
		fmt.Println("  example-rp -issuer http://localhost:8080")
		os.Exit(1)
	}

	base := *publicURL
	if base == "" {
		base = "http://localhost" + *addr
	}

	cfg := defaultConfig(base, *issuer)
	store := newStore()

	tmpl, err := template.New("").ParseFiles("templates/layout.html")
	if err != nil {
		log.Fatalf("parsing templates: %v", err)
	}

	app := newApp(cfg, store, tmpl)

	fmt.Printf("example-rp listening on %s against issuer %s\n", *addr, cfg.Issuer)
	fmt.Printf("open http://localhost%s/\n", *addr)
	if err := http.ListenAndServe(*addr, app.routes()); err != nil {
		log.Fatal(err)
	}
}
