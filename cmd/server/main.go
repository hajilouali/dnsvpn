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
	"path/filepath"

	"dnsvpn/server/admin"
	"dnsvpn/server/engine"
	"dnsvpn/server/store"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var (
		zone      = flag.String("zone", "", "tunnel zone, e.g. t.example.com (required)")
		psk       = flag.String("psk", "", "pre-shared key shared with clients (required)")
		dnsAddr   = flag.String("dns", ":53", "UDP address for the authoritative DNS listener")
		httpAddr  = flag.String("http", "127.0.0.1:8080", "address for the web admin panel")
		dbPath    = flag.String("db", "dnsvpn.db", "path to the SQLite user database")
		adminUser = flag.String("admin-user", "admin", "admin panel username")
		adminPass = flag.String("admin-pass", "", "admin panel bootstrap password (random if empty; change it later in the panel)")
		candidates = flag.String("candidates", "", "default resolver candidates baked into clients' config links (comma-separated, CIDRs allowed)")
		panelDomain = flag.String("panel-domain", "", "serve the panel publicly over HTTPS on this domain with an auto Let's Encrypt cert (needs :80 and :443 open)")
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

	panel, err := admin.New(st, *adminUser, *adminPass, *zone, *psk, *candidates)
	if err != nil {
		log.Fatalf("admin: %v", err)
	}
	handler := panel.Handler()
	// Always serve the panel on the local HTTP address, so an SSH tunnel keeps working
	// regardless of the public HTTPS setup.
	go func() {
		log.Printf("admin panel on http://%s (user %q)", *httpAddr, *adminUser)
		if err := http.ListenAndServe(*httpAddr, handler); err != nil {
			log.Fatalf("admin http: %v", err)
		}
	}()
	// Additionally serve public HTTPS with an automatic Let's Encrypt certificate when a
	// panel domain is set. TLS-ALPN-01 runs on :443; :80 serves the HTTP-01 challenge and
	// redirects to HTTPS. The cert is cached on disk and autocert renews it automatically
	// (well before the ~90-day expiry) for as long as the service runs.
	if *panelDomain != "" {
		certDir := filepath.Join(filepath.Dir(*dbPath), "certs")
		os.MkdirAll(certDir, 0700)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*panelDomain),
			Cache:      autocert.DirCache(certDir),
		}
		go func() {
			log.Printf("admin panel also on https://%s", *panelDomain)
			s := &http.Server{Addr: ":443", Handler: handler, TLSConfig: m.TLSConfig()}
			if err := s.ListenAndServeTLS("", ""); err != nil {
				log.Fatalf("admin https: %v", err)
			}
		}()
		go func() {
			if err := http.ListenAndServe(":80", m.HTTPHandler(redirectHTTPS())); err != nil {
				log.Fatalf("admin http-challenge: %v", err)
			}
		}()
	}

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

// redirectHTTPS sends any plain-HTTP request that isn't an ACME challenge to https://.
func redirectHTTPS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}
