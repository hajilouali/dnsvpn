// Package dispatcher sends tunnel queries across a pool of recursive DNS resolvers,
// keeping per-resolver health/latency so the busy worker window favours fast, healthy
// paths and routes around rate-limited or dead ones. This fan-out across many
// resolvers is the main lever for throughput beyond a single-path tunnel.
package dispatcher

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dnsvpn/internal/dnswire"
	"golang.org/x/net/dns/dnsmessage"
)

// Mode selects how a resolver is chosen for each query.
type Mode int

const (
	RoundRobin    Mode = iota // even spread
	LowestLatency             // prefer the lowest EWMA RTT healthy resolver
	Random                    // uniform random healthy resolver
)

type resolver struct {
	addr      string
	rttNanos  int64 // EWMA, atomic
	inflight  int64 // atomic
	failUntil int64 // unix-nano; resolver disabled until then (atomic)
}

func (r *resolver) healthy(now int64) bool { return atomic.LoadInt64(&r.failUntil) <= now }

// Pool is an Exchanger over many resolvers. Its resolver set can be replaced at
// runtime (SetResolvers) so the client's scanner can keep it pointed at whichever
// resolvers currently reach the server fastest.
type Pool struct {
	zone        string
	qtype       dnsmessage.Type
	timeout     time.Duration
	penalty     time.Duration
	mode        Mode
	maxInflight int64 // per-resolver concurrent-query cap (0 => unlimited)
	rr          uint64
	rnd         *rand.Rand
	rndMu       sync.Mutex

	mu        sync.RWMutex
	resolvers []*resolver
	byAddr    map[string]*resolver
}

// Config configures a Pool.
type Config struct {
	Zone      string        // tunnel zone, no trailing dot
	Resolvers []string      // host:port list (":53" appended if no port)
	QType     dnsmessage.Type // 0 => TXT
	Mode      Mode
	Timeout   time.Duration // per-query timeout. 0 => 4s
	Penalty   time.Duration // how long a failed resolver is benched. 0 => 5s
	// MaxInflight caps concurrent queries sent to any single resolver, so load
	// spreads across the whole pool instead of piling onto the fastest few and
	// tripping their rate limits. 0 => 6.
	MaxInflight int
}

// New builds a Pool.
func New(cfg Config) (*Pool, error) {
	if len(cfg.Resolvers) == 0 {
		return nil, errors.New("dispatcher: no resolvers")
	}
	if cfg.QType == 0 {
		cfg.QType = dnsmessage.TypeTXT
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 4 * time.Second
	}
	if cfg.Penalty == 0 {
		cfg.Penalty = 5 * time.Second
	}
	if cfg.MaxInflight == 0 {
		cfg.MaxInflight = 6
	}
	p := &Pool{
		zone:        cfg.Zone,
		qtype:       cfg.QType,
		timeout:     cfg.Timeout,
		penalty:     cfg.Penalty,
		mode:        cfg.Mode,
		maxInflight: int64(cfg.MaxInflight),
		rnd:         rand.New(rand.NewSource(time.Now().UnixNano())),
		byAddr:      make(map[string]*resolver),
	}
	p.SetResolvers(cfg.Resolvers)
	return p, nil
}

// normAddr appends :53 when no port is given.
func normAddr(a string) string {
	if _, _, err := net.SplitHostPort(a); err != nil {
		return net.JoinHostPort(a, "53")
	}
	return a
}

// SetResolvers replaces the active resolver set. Resolvers already present keep their
// measured RTT/health; new ones start fresh; dropped ones are discarded. Safe for
// concurrent use alongside Exchange.
func (p *Pool) SetResolvers(addrs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next := make([]*resolver, 0, len(addrs))
	nextByAddr := make(map[string]*resolver, len(addrs))
	for _, a := range addrs {
		a = normAddr(a)
		if nextByAddr[a] != nil {
			continue // dedupe
		}
		r := p.byAddr[a]
		if r == nil {
			r = &resolver{addr: a, rttNanos: int64(50 * time.Millisecond)}
		}
		next = append(next, r)
		nextByAddr[a] = r
	}
	p.resolvers = next
	p.byAddr = nextByAddr
}

// Resolvers returns the current resolver addresses.
func (p *Pool) Resolvers() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.resolvers))
	for i, r := range p.resolvers {
		out[i] = r.addr
	}
	return out
}

func (p *Pool) pick() *resolver {
	now := time.Now().UnixNano()
	p.mu.RLock()
	all := p.resolvers
	healthy := make([]*resolver, 0, len(all))
	for _, r := range all {
		if r.healthy(now) {
			healthy = append(healthy, r)
		}
	}
	if len(healthy) == 0 { // everyone benched: try them all anyway
		healthy = append(healthy, all...)
	}
	p.mu.RUnlock()
	if len(healthy) == 0 {
		return nil
	}
	// Prefer resolvers below their per-resolver inflight cap so sustained load
	// spreads across the whole pool rather than saturating the fastest few (which
	// then rate-limit us). Only if every healthy resolver is at its cap do we fall
	// back to the full set and let the scorer pick the least-loaded.
	if p.maxInflight > 0 {
		avail := make([]*resolver, 0, len(healthy))
		for _, r := range healthy {
			if atomic.LoadInt64(&r.inflight) < p.maxInflight {
				avail = append(avail, r)
			}
		}
		if len(avail) > 0 {
			healthy = avail
		}
	}
	switch p.mode {
	case Random:
		p.rndMu.Lock()
		r := healthy[p.rnd.Intn(len(healthy))]
		p.rndMu.Unlock()
		return r
	case LowestLatency:
		best := healthy[0]
		bestScore := atomic.LoadInt64(&best.rttNanos) * (1 + atomic.LoadInt64(&best.inflight))
		for _, r := range healthy[1:] {
			s := atomic.LoadInt64(&r.rttNanos) * (1 + atomic.LoadInt64(&r.inflight))
			if s < bestScore {
				best, bestScore = r, s
			}
		}
		return best
	default: // RoundRobin
		i := atomic.AddUint64(&p.rr, 1)
		return healthy[int(i)%len(healthy)]
	}
}

func (r *resolver) observe(rtt time.Duration) {
	old := atomic.LoadInt64(&r.rttNanos)
	// EWMA, alpha = 1/4
	next := old - old/4 + int64(rtt)/4
	atomic.StoreInt64(&r.rttNanos, next)
}

// Exchange implements dnsnet.Exchanger.
func (p *Pool) Exchange(ctx context.Context, namePayload []byte) ([]byte, error) {
	r := p.pick()
	if r == nil {
		return nil, errors.New("dispatcher: no resolvers available")
	}
	name, err := dnswire.PackName(p.zone, namePayload)
	if err != nil {
		return nil, err
	}
	id := uint16(time.Now().UnixNano())
	qwire, err := dnswire.BuildQuery(id, name, p.qtype)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&r.inflight, 1)
	defer atomic.AddInt64(&r.inflight, -1)
	start := time.Now()

	d := net.Dialer{Timeout: p.timeout}
	conn, err := d.DialContext(ctx, "udp", r.addr)
	if err != nil {
		p.bench(r)
		return nil, err
	}
	defer conn.Close()

	dl := start.Add(p.timeout)
	if t, ok := ctx.Deadline(); ok && t.Before(dl) {
		dl = t
	}
	conn.SetDeadline(dl)

	if _, err := conn.Write(qwire); err != nil {
		p.bench(r)
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		p.bench(r)
		return nil, err
	}
	r.observe(time.Since(start))
	return dnswire.ParseTXTResponse(buf[:n])
}

func (p *Pool) bench(r *resolver) {
	atomic.StoreInt64(&r.failUntil, time.Now().Add(p.penalty).UnixNano())
}

// Close implements dnsnet.Exchanger (nothing persistent to release).
func (p *Pool) Close() error { return nil }

// Stats is a point-in-time view of one resolver, for the admin panel / logs.
type Stats struct {
	Addr     string
	RTTMillis int64
	Inflight int64
	Healthy  bool
}

// Snapshot returns current per-resolver stats.
func (p *Pool) Snapshot() []Stats {
	now := time.Now().UnixNano()
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Stats, 0, len(p.resolvers))
	for _, r := range p.resolvers {
		out = append(out, Stats{
			Addr:      r.addr,
			RTTMillis: atomic.LoadInt64(&r.rttNanos) / int64(time.Millisecond),
			Inflight:  atomic.LoadInt64(&r.inflight),
			Healthy:   r.healthy(now),
		})
	}
	return out
}
