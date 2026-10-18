// Package scanner discovers and validates recursive DNS resolvers for the tunnel
// client. It sends each candidate an authenticated probe (see proto.BuildProbe) and
// keeps only those that return the genuine PSK-derived reply within the timeout —
// proving the resolver both reaches our authoritative server and is not hijacking the
// zone. Results are ranked by round-trip time so the client can point its dispatcher
// at the fastest working resolvers, and re-scan periodically as the network shifts.
package scanner

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"dnsvpn/internal/dnswire"
	"dnsvpn/internal/proto"

	"golang.org/x/net/dns/dnsmessage"
)

var errBadReply = errors.New("scanner: resolver returned an inauthentic reply")

// Result is one resolver's probe outcome.
type Result struct {
	Addr string
	RTT  time.Duration
	OK   bool
	Err  error
}

// Config tunes a scan.
type Config struct {
	Zone        string
	PSK         string
	QType       dnsmessage.Type // 0 => TXT
	Timeout     time.Duration   // per-probe timeout. 0 => 2s
	Attempts    int             // probes per resolver, best RTT kept. 0 => 2
	Concurrency int             // max parallel probes. 0 => 64
}

func (c *Config) defaults() {
	if c.QType == 0 {
		c.QType = dnsmessage.TypeTXT
	}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Second
	}
	if c.Attempts == 0 {
		c.Attempts = 2
	}
	if c.Concurrency == 0 {
		c.Concurrency = 64
	}
}

// probeOnce sends one authenticated probe to addr and verifies the reply, returning
// the measured RTT on success.
func probeOnce(ctx context.Context, addr string, cfg Config) (time.Duration, error) {
	challenge := proto.NewProbeChallenge()
	name, err := dnswire.PackName(cfg.Zone, proto.BuildProbe(challenge))
	if err != nil {
		return 0, err
	}
	q, err := dnswire.BuildQuery(uint16(time.Now().UnixNano()), name, cfg.QType)
	if err != nil {
		return 0, err
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(cfg.Timeout))

	start := time.Now()
	if _, err := conn.Write(q); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	rtt := time.Since(start)
	reply, err := dnswire.ParseTXTResponse(buf[:n])
	if err != nil {
		return 0, err
	}
	if !proto.VerifyProbeReply(cfg.PSK, challenge, reply) {
		return 0, errBadReply
	}
	return rtt, nil
}

// probeResolver probes addr up to Attempts times and keeps the best RTT.
func probeResolver(ctx context.Context, addr string, cfg Config) Result {
	addr = normAddr(addr)
	res := Result{Addr: addr}
	best := time.Duration(1<<63 - 1)
	for i := 0; i < cfg.Attempts; i++ {
		rtt, err := probeOnce(ctx, addr, cfg)
		if err != nil {
			res.Err = err
			continue
		}
		res.OK = true
		if rtt < best {
			best = rtt
		}
	}
	if res.OK {
		res.RTT = best
		res.Err = nil
	}
	return res
}

// maxExpand caps how many addresses CIDR expansion may produce, so a careless /8
// can't explode the candidate set.
const maxExpand = 8192

// ExpandCIDRs turns any CIDR entries (e.g. "2.188.21.0/24") into their individual host
// addresses, passing plain host[:port] entries through unchanged. Iranian ISP resolver
// ranges often host many distinct recursive resolvers; probing the whole range and
// keeping only the ones that authentically reach the server is how the client builds a
// large pool and spreads load past any single resolver's rate limit.
func ExpandCIDRs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			out = append(out, c)
			continue
		}
		ip, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			out = append(out, c) // not a CIDR after all; let the prober error on it
			continue
		}
		for addr := ip.Mask(ipnet.Mask); ipnet.Contains(addr) && len(out) < maxExpand; addr = nextIP(addr) {
			out = append(out, addr.String())
		}
	}
	if len(out) > maxExpand {
		out = out[:maxExpand]
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil {
		return ip
	}
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// Scan probes all candidates concurrently and returns results sorted best-first
// (working resolvers by ascending RTT, then the failures). CIDR entries are expanded.
func Scan(ctx context.Context, cfg Config, candidates []string) []Result {
	cfg.defaults()
	candidates = dedupe(ExpandCIDRs(candidates))

	results := make([]Result, len(candidates))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, c := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probeResolver(ctx, c, cfg)
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool {
		if results[a].OK != results[b].OK {
			return results[a].OK
		}
		return results[a].RTT < results[b].RTT
	})
	return results
}

// Best returns the addresses of up to n working resolvers, fastest first.
func Best(results []Result, n int) []string {
	var out []string
	for _, r := range results {
		if !r.OK {
			break
		}
		out = append(out, r.Addr)
		if n > 0 && len(out) >= n {
			break
		}
	}
	return out
}

func normAddr(a string) string {
	if _, _, err := net.SplitHostPort(a); err != nil {
		return net.JoinHostPort(a, "53")
	}
	return a
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, a := range in {
		a = normAddr(a)
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// DefaultCandidates is a starting pool of recursive resolvers: major global anycast
// services plus resolvers commonly reachable from Iranian networks. The client should
// prepend SystemResolvers() (the ISP's own resolvers) since those are the most likely
// to keep working during a shutdown, and let the scan sort out what actually works.
var DefaultCandidates = []string{
	// Iranian / regionally reachable
	"178.22.122.100", "185.51.200.2", // Shecan
	"185.55.226.26", "185.55.225.25", // Begzar
	"10.202.10.202", "10.202.10.102", // 403.online
	"10.202.10.10", // Radar/Electro
	"217.218.155.155", "217.218.127.127", // TCI / مخابرات
	"5.200.200.200", // Pishgaman
	// Global anycast
	"8.8.8.8", "8.8.4.4", // Google
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"9.9.9.9", "149.112.112.112", // Quad9
	"77.88.8.8", "77.88.8.1", // Yandex
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"4.2.2.1", "4.2.2.2", // Level3
}
