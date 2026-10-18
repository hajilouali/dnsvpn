// Command server runs the DNS-VPN authoritative tunnel endpoint plus the web admin
// panel. It needs UDP/53 reachable from recursive resolvers and a delegated zone.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"

	"dnsvpn/server/admin"
	"dnsvpn/server/engine"
	"dnsvpn/server/store"
)

func main() {
	var (
		zone      = flag.String("zone", "", "tunnel zone, e.g. t.example.com (required)")
		psk       = flag.String("psk", "", "pre-shared key shared with clients (required)")
		dnsAddr   = flag.String("dns", ":53", "UDP address for the authoritative DNS listener")
		httpAddr  = flag.String("http", "127.0.0.1:8080", "address for the web admin panel")
		dbPath    = flag.String("db", "dnsvpn.db", "path to the SQLite user database")
		adminUser = flag.String("admin-user", "admin", "admin panel username")
		adminPass = flag.String("admin-pass", "", "admin panel password (random if empty)")
	)
	flag.Parse()
	if *zone == "" || *psk == "" {
		log.Fatal("both -zone and -psk are required")
	}
	if *adminPass == "" {
		var b [12]byte
		rand.Read(b[:])
		*adminPass = hex.EncodeToString(b[:])
		log.Printf("generated admin password: %s", *adminPass)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	panel, err := admin.New(st, *adminUser, *adminPass)
	if err != nil {
		log.Fatalf("admin: %v", err)
	}
	go func() {
		log.Printf("admin panel on http://%s (user %q)", *httpAddr, *adminUser)
		if err := http.ListenAndServe(*httpAddr, panel.Handler()); err != nil {
			log.Fatalf("admin http: %v", err)
		}
	}()

	srv, err := engine.New(engine.Config{
		Zone:       *zone,
		PSK:        *psk,
		Authorizer: st,
		Accountant: st,
		Logger:     log.New(os.Stderr, "", log.LstdFlags),
	})
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	defer srv.Close()

	if err := srv.ServeDNS(*dnsAddr); err != nil {
		log.Fatalf("dns listener: %v", err)
	}
}
