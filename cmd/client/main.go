// Command client runs the DNS-VPN client: it brings up the tunnel over a pool of
// recursive resolvers and exposes a local SOCKS5 proxy for applications.
//
// Settings come from flags, or from a JSON file via -config (flags override the file),
// so a user can be handed just client.exe + a config.json holding their zone/psk/token.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"dnsvpn/client/core"
	"dnsvpn/client/socks"
	"dnsvpn/internal/configlink"
	"dnsvpn/internal/dispatcher"
)

// Sensible default pool of public recursive resolvers (anycast, port 53).
var defaultResolvers = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
}

func parseMode(s string) dispatcher.Mode {
	switch strings.ToLower(s) {
	case "latency", "lowest-latency":
		return dispatcher.LowestLatency
	case "random":
		return dispatcher.Random
	default:
		return dispatcher.RoundRobin
	}
}

// fileConfig mirrors the JSON config file. Empty/zero fields fall back to flag values.
type fileConfig struct {
	Zone         string `json:"zone"`
	PSK          string `json:"psk"`
	Token        string `json:"token"`
	Resolvers    string `json:"resolvers"`
	Candidates   string `json:"candidates"` // extra probe candidates, may include CIDRs
	Socks        string `json:"socks"`
	Mode         string `json:"mode"`
	Workers      int    `json:"workers"`
	MaxInflight  int    `json:"max_inflight"`
	Scan         *bool  `json:"scan"`
	MaxResolvers int    `json:"max_resolvers"`
	Rescan       string `json:"rescan"`        // duration string, e.g. "60s"
	QueryTimeout string `json:"query_timeout"` // duration string, e.g. "1500ms"
}

func main() {
	var (
		configPath = flag.String("config", "", "path to a JSON config file (flags override its values)")
		link       = flag.String("link", "", "a dnsvpn:// config link from the admin panel (sets zone/psk/token/candidates)")
		zone       = flag.String("zone", "", "tunnel zone, e.g. t.example.com (required)")
		psk        = flag.String("psk", "", "pre-shared key shared with the server (required)")
		token      = flag.String("token", "", "user auth token (from the admin panel)")
		resolvers  = flag.String("resolvers", strings.Join(defaultResolvers, ","), "comma-separated resolver host[:port] list")
		candidates = flag.String("candidates", "", "extra probe candidates to scan, comma-separated; may include CIDRs e.g. 2.188.21.0/24")
		socksAddr  = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
		mode       = flag.String("mode", "latency", "resolver selection: roundrobin|latency|random")
		workers    = flag.Int("workers", 48, "in-flight query window (parallelism)")
		maxInflight = flag.Int("max-inflight", 6, "per-resolver concurrent-query cap (spreads load across the pool)")
		scan       = flag.Bool("scan", true, "auto-discover & validate resolvers (system + defaults + -resolvers), keep the fastest")
		maxRes     = flag.Int("max-resolvers", 8, "with -scan, how many fastest resolvers to keep active")
		rescan     = flag.Duration("rescan", 60*time.Second, "with -scan, how often to re-probe resolvers")
		qTimeout   = flag.Duration("query-timeout", 2*time.Second, "per-query timeout; a slow/dead resolver is abandoned after this")
	)
	flag.Parse()

	// A config file supplies values for any flag the user did NOT set explicitly.
	if *configPath != "" {
		fc, err := loadFileConfig(*configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		set := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
		applyFileConfig(fc, set, zone, psk, token, resolvers, candidates, socksAddr, mode, workers, maxInflight, scan, maxRes, rescan, qTimeout)
	}

	// A dnsvpn:// link fills zone/psk/token/candidates for any flag not set explicitly.
	if *link != "" {
		lc, err := configlink.Decode(*link)
		if err != nil {
			log.Fatalf("link: %v", err)
		}
		set := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if !set["zone"] {
			*zone = lc.Zone
		}
		if !set["psk"] {
			*psk = lc.PSK
		}
		if !set["token"] && lc.Token != "" {
			*token = lc.Token
		}
		if !set["candidates"] && lc.Candidates != "" {
			*candidates = lc.Candidates
		}
	}

	if *zone == "" || *psk == "" {
		log.Fatal("both zone and psk are required (via -config, -link, or flags)")
	}

	splitList := func(s string) []string {
		var out []string
		for _, r := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	list := splitList(*resolvers)
	cands := splitList(*candidates)

	c := core.New(core.Config{
		Zone:           *zone,
		PSK:            *psk,
		Token:          *token,
		Resolvers:      list,
		Candidates:     cands,
		Mode:           parseMode(*mode),
		Workers:        *workers,
		MaxInflight:    *maxInflight,
		Scan:           *scan,
		MaxResolvers:   *maxRes,
		RescanInterval: *rescan,
		QueryTimeout:   *qTimeout,
	})
	defer c.Close()

	log.Printf("client: zone=%s seed-resolvers=%d mode=%s workers=%d scan=%v socks=%s",
		*zone, len(list), *mode, *workers, *scan, *socksAddr)
	s := &socks.Server{Client: c}
	if err := s.ListenAndServe(*socksAddr); err != nil {
		log.Fatalf("socks: %v", err)
	}
}

func loadFileConfig(path string) (fileConfig, error) {
	var fc fileConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return fc, err
	}
	err = json.Unmarshal(b, &fc)
	return fc, err
}

// applyFileConfig fills each flag the user did not set from the file (when the file
// provides a value), so explicit flags always win.
func applyFileConfig(fc fileConfig, set map[string]bool,
	zone, psk, token, resolvers, candidates, socksAddr, mode *string, workers, maxInflight *int,
	scan *bool, maxRes *int, rescan, qTimeout *time.Duration) {

	setStr := func(name string, dst *string, v string) {
		if !set[name] && v != "" {
			*dst = v
		}
	}
	setInt := func(name string, dst *int, v int) {
		if !set[name] && v != 0 {
			*dst = v
		}
	}
	setDur := func(name string, dst *time.Duration, v string) {
		if !set[name] && v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	setStr("zone", zone, fc.Zone)
	setStr("psk", psk, fc.PSK)
	setStr("token", token, fc.Token)
	setStr("resolvers", resolvers, fc.Resolvers)
	setStr("candidates", candidates, fc.Candidates)
	setStr("socks", socksAddr, fc.Socks)
	setStr("mode", mode, fc.Mode)
	setInt("workers", workers, fc.Workers)
	setInt("max-inflight", maxInflight, fc.MaxInflight)
	setInt("max-resolvers", maxRes, fc.MaxResolvers)
	setDur("rescan", rescan, fc.Rescan)
	setDur("query-timeout", qTimeout, fc.QueryTimeout)
	if !set["scan"] && fc.Scan != nil {
		*scan = *fc.Scan
	}
}
