// Package core is the client-side tunnel: it builds the multi-resolver dispatcher,
// brings up the KCP/smux session over DNS, and hands out streams to arbitrary
// destinations (used by the SOCKS front end). Sessions are redialled on failure.
package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"dnsvpn/internal/dnsnet"
	"dnsvpn/internal/dispatcher"
	"dnsvpn/internal/proto"
	"dnsvpn/internal/scanner"
	"dnsvpn/internal/tunnel"

	"github.com/xtaci/smux"
)

// Config configures the client.
type Config struct {
	Zone      string
	PSK       string
	Token     string
	Resolvers []string // explicit resolvers; also seed candidates when scanning
	Mode         dispatcher.Mode
	Workers      int              // in-flight query window
	MaxInflight  int              // per-resolver concurrent-query cap (spreads load). 0 => 6
	QueryTimeout time.Duration    // per-query timeout; a slow/dead resolver is abandoned after this. 0 => 2s
	Exchanger    dnsnet.Exchanger // override (tests/loopback); nil => build a resolver pool

	// Scanning: when Scan is set, the client probes a candidate pool (system resolvers
	// + Resolvers + Candidates + built-in defaults), keeps the fastest MaxResolvers
	// that authentically reach the server, and re-scans every RescanInterval.
	Scan           bool
	Candidates     []string
	MaxResolvers   int           // active resolvers kept from a scan. 0 => 8
	RescanInterval time.Duration // 0 => 60s
	ScanTimeout    time.Duration // per-probe timeout. 0 => 2s

	Logger *log.Logger
}

// Client maintains one live tunnel session, redialling as needed.
type Client struct {
	cfg    Config
	logger *log.Logger

	mu     sync.Mutex
	dnsCli *dnsnet.Client
	mux    *smux.Session

	pool     *dispatcher.Pool
	scanOnce sync.Once
}

// New creates a client. The session is established lazily on first OpenStream.
func New(cfg Config) *Client {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.MaxResolvers == 0 {
		cfg.MaxResolvers = 8
	}
	if cfg.RescanInterval == 0 {
		cfg.RescanInterval = 60 * time.Second
	}
	if cfg.ScanTimeout == 0 {
		cfg.ScanTimeout = 2 * time.Second
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 2 * time.Second
	}
	return &Client{cfg: cfg, logger: cfg.Logger}
}

func (c *Client) buildExchanger() (dnsnet.Exchanger, error) {
	if c.cfg.Exchanger != nil {
		return c.cfg.Exchanger, nil
	}
	pool, err := dispatcher.New(dispatcher.Config{
		Zone:        c.cfg.Zone,
		Resolvers:   c.cfg.Resolvers,
		Mode:        c.cfg.Mode,
		Timeout:     c.cfg.QueryTimeout,
		MaxInflight: c.cfg.MaxInflight,
	})
	if err != nil {
		return nil, err
	}
	c.pool = pool
	if c.cfg.Scan {
		// Scan in the background: the pool already has the seed resolvers, so the
		// first request goes out immediately while the scan refines the set and
		// re-scans periodically.
		c.scanOnce.Do(func() {
			go func() {
				c.scanAndApply()
				c.rescanLoop()
			}()
		})
	}
	return pool, nil
}

// candidateList assembles the full probe set, system resolvers first (most likely to
// survive a shutdown), then explicit resolvers, extra candidates, and built-in defaults.
func (c *Client) candidateList() []string {
	var cands []string
	cands = append(cands, scanner.SystemResolvers()...)
	cands = append(cands, c.cfg.Resolvers...)
	cands = append(cands, c.cfg.Candidates...)
	cands = append(cands, scanner.DefaultCandidates...)
	return cands
}

// scanAndApply probes the candidate list and points the pool at the fastest working
// resolvers. If nothing passes, the pool is left unchanged (keeps its current set).
func (c *Client) scanAndApply() {
	// Background scan: give it generous wall-clock time so large CIDR ranges finish,
	// one probe per candidate (enough to validate + time it), high concurrency.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	results := scanner.Scan(ctx, scanner.Config{
		Zone:        c.cfg.Zone,
		PSK:         c.cfg.PSK,
		Timeout:     c.cfg.ScanTimeout,
		Attempts:    1,
		Concurrency: 256,
	}, c.candidateList())
	best := scanner.Best(results, c.cfg.MaxResolvers)
	if len(best) == 0 {
		c.logger.Printf("scanner: no resolver passed the probe; keeping current set")
		return
	}
	c.pool.SetResolvers(best)
	c.logger.Printf("scanner: using %d/%d resolvers: %v", len(best), len(results), best)
}

func (c *Client) rescanLoop() {
	t := time.NewTicker(c.cfg.RescanInterval)
	defer t.Stop()
	for range t.C {
		c.scanAndApply()
	}
}

// session returns a live smux session, dialling or redialling if needed.
func (c *Client) session() (*smux.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mux != nil && !c.mux.IsClosed() {
		return c.mux, nil
	}
	// tear down a dead session
	if c.mux != nil {
		c.mux.Close()
	}
	if c.dnsCli != nil {
		c.dnsCli.Close()
	}

	ex, err := c.buildExchanger()
	if err != nil {
		return nil, err
	}
	id, err := proto.NewClientID()
	if err != nil {
		return nil, err
	}
	c.dnsCli = dnsnet.NewClient(id, ex, dnsnet.ClientConfig{
		Workers:     c.cfg.Workers,
		MaxDatagram: tunnel.Mtu(c.cfg.Zone),
	})
	mux, err := tunnel.Dial(c.dnsCli.PacketConn(), proto.ServerAddr{}, c.cfg.PSK, c.cfg.Zone)
	if err != nil {
		c.dnsCli.Close()
		c.dnsCli = nil
		return nil, err
	}
	c.mux = mux
	c.logger.Printf("core: session up (zone=%s, %s)", c.cfg.Zone, id)
	return mux, nil
}

// OpenStream opens a tunnel stream to dest ("host:port", or "echo") and sends the
// auth/destination preface. The returned stream is ready for application bytes.
func (c *Client) OpenStream(dest string) (*smux.Stream, error) {
	mux, err := c.session()
	if err != nil {
		return nil, err
	}
	stream, err := mux.OpenStream()
	if err != nil {
		// one redial attempt on a stale session
		c.mu.Lock()
		if c.mux == mux {
			c.mux = nil
		}
		c.mu.Unlock()
		if mux, err = c.session(); err != nil {
			return nil, err
		}
		if stream, err = mux.OpenStream(); err != nil {
			return nil, err
		}
	}
	if _, err := (proto.StreamPreface{Token: c.cfg.Token, Dest: dest}).WriteTo(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("core: preface: %w", err)
	}
	return stream, nil
}

// Close tears the client down.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mux != nil {
		c.mux.Close()
	}
	if c.dnsCli != nil {
		c.dnsCli.Close()
	}
	return nil
}
