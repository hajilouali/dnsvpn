// Package engine is the tunnel server: an authoritative DNS endpoint that demuxes
// client queries into KCP/smux sessions and bridges their streams to the open
// internet (the exit). It is transport-agnostic about how queries arrive — the same
// HandleNamePayload drives both the real UDP/53 listener and the in-memory loopback
// exchanger used by local tests.
package engine

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"dnsvpn/internal/dnsnet"
	"dnsvpn/internal/dnswire"
	"dnsvpn/internal/proto"
	"dnsvpn/internal/tunnel"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Authorizer validates a user token and reports whether the stream may proceed.
// A later SQLite-backed store implements this; nil means allow-all (test only).
type Authorizer interface {
	// Authorize is called once per stream with the preface token. Returning a nil
	// error admits the stream. The returned release func is called when the stream
	// closes (for concurrency accounting); it may be nil.
	Authorize(token string) (release func(), err error)
}

// Accountant receives post-close byte counts per user token for quota/stats.
type Accountant interface {
	Account(token string, up, down int64)
}

// Config configures a Server.
type Config struct {
	Zone       string // tunnel zone, no trailing dot
	PSK        string // pre-shared key for the KCP AES layer (also obfuscation)
	AnswerWait time.Duration // how long a query waits for a downstream datagram. 0 => 20ms
	MaxDownBytes int         // TXT payload budget packed per answer. 0 => 700
	Authorizer Authorizer    // nil => allow all
	Accountant Accountant    // nil => no accounting
	DialTimeout time.Duration // exit dial timeout. 0 => 10s
	Logger     *log.Logger
}

// Server holds the shared packet conn and the KCP listener.
type Server struct {
	cfg      Config
	pc       *dnsnet.QueuePacketConn
	kcpln    *kcp.Listener
	logger   *log.Logger
	maxFrame int // one KCP datagram + its 2-byte length prefix

	mu       sync.Mutex
	sessions map[string]time.Time // clientID -> last seen, for idle reaping later
}

// New creates the server and starts its accept loop.
func New(cfg Config) (*Server, error) {
	if cfg.AnswerWait == 0 {
		cfg.AnswerWait = 20 * time.Millisecond
	}
	if cfg.MaxDownBytes == 0 {
		// Cap on TXT payload per answer. ~1180 keeps the whole message under the
		// 1232-byte EDNS buffer for short (poll) QNAMEs; data QNAMEs are sized down
		// adaptively in answerBudget.
		cfg.MaxDownBytes = 1180
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	s := &Server{
		cfg:      cfg,
		pc:       dnsnet.NewQueuePacketConn(proto.ServerAddr{}, 8192, 1500),
		logger:   cfg.Logger,
		maxFrame: tunnel.Mtu(cfg.Zone) + 2,
		sessions: make(map[string]time.Time),
	}
	ln, err := tunnel.Listen(s.pc, cfg.PSK)
	if err != nil {
		return nil, err
	}
	s.kcpln = ln
	go s.acceptLoop()
	return s, nil
}

// HandleNamePayload processes one upstream query payload with the default answer
// budget (used by the in-memory Loopback; the real UDP path uses handleWithBudget so
// it can size each answer to the query's name length). Safe for concurrent use.
func (s *Server) HandleNamePayload(namePayload []byte) []byte {
	return s.handleWithBudget(namePayload, s.cfg.MaxDownBytes)
}

// handleWithBudget drains up to maxDown bytes of queued downstream datagrams for the
// client, framed into one answer. maxDown is sized per query by the caller: a short
// poll QNAME leaves far more room for a large EDNS answer than a data-carrying QNAME.
func (s *Server) handleWithBudget(namePayload []byte, maxDown int) []byte {
	// Resolver probes are answered directly with an authenticated canary and never
	// reach KCP; this is how clients discover and validate resolvers.
	if ch, ok := proto.ParseProbe(namePayload); ok {
		return proto.ProbeReply(s.cfg.PSK, ch)
	}
	cid, _, datagram, err := proto.UnpackWire(namePayload)
	if err != nil {
		return nil
	}
	if len(datagram) > 0 {
		s.pc.QueueIncoming(datagram, cid)
	}
	if maxDown < s.maxFrame {
		maxDown = s.maxFrame // always allow at least one datagram
	}
	// The first waits a short beat so an answer can carry fresh data rather than
	// coming back empty; the rest are drained non-blocking until the budget is used.
	out := s.pc.OutboundQueue(cid)
	var batch [][]byte
	select {
	case d := <-out:
		batch = append(batch, d)
	case <-time.After(s.cfg.AnswerWait):
		return nil
	}
	used := 2 + len(batch[0])
	for used+s.maxFrame <= maxDown {
		select {
		case d := <-out:
			batch = append(batch, d)
			used += 2 + len(d)
		default:
			return dnswire.PackDatagrams(batch)
		}
	}
	return dnswire.PackDatagrams(batch)
}

// answerBudget returns how many TXT payload bytes a response to qname may carry while
// the whole DNS message stays within the client's advertised EDNS buffer. dnsmessage
// does not compress names, so the QNAME is repeated in both the question and the answer
// RR; a short poll name therefore leaves much more room than a long data name.
func (s *Server) answerBudget(qname string) int {
	qwire := len(strings.TrimSuffix(qname, ".")) + 2 // ~label-length bytes + root
	// header(12) + question(name+4) + answer RR(name+10) + OPT(11) + TXT framing(~8) + margin(16)
	overhead := 12 + (qwire + 4) + (qwire + 10) + 11 + 8 + 16
	budget := dnswire.EDNSUDPSize - overhead
	if budget > s.cfg.MaxDownBytes {
		budget = s.cfg.MaxDownBytes
	}
	return budget
}

// ServeDNS binds UDP addr (e.g. ":53") and serves until the conn errors.
func (s *Server) ServeDNS(addr string) error {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	return s.ServeUDPConn(conn)
}

// ServeUDPConn serves the authoritative DNS loop over an already-bound UDP conn.
// Useful when the caller needs the chosen port (e.g. binding to :0 in tests).
func (s *Server) ServeUDPConn(conn *net.UDPConn) error {
	s.logger.Printf("engine: authoritative DNS on %s zone=%s", conn.LocalAddr(), s.cfg.Zone)
	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.serveQuery(conn, src, pkt)
	}
}

func (s *Server) serveQuery(conn *net.UDPConn, src *net.UDPAddr, pkt []byte) {
	q, err := dnswire.ParseQuery(pkt)
	if err != nil {
		return
	}
	payload, err := dnswire.UnpackName(s.cfg.Zone, q.Name)
	if err != nil {
		return // not for our zone / unparseable
	}
	down := s.handleWithBudget(payload, s.answerBudget(q.Name))
	resp, err := dnswire.BuildTXTResponse(q, down)
	if err != nil {
		return
	}
	conn.WriteToUDP(resp, src)
}

func (s *Server) acceptLoop() {
	for {
		sess, err := s.kcpln.AcceptKCP()
		if err != nil {
			s.logger.Printf("engine: accept: %v", err)
			return
		}
		go s.handleSession(sess)
	}
}

func (s *Server) handleSession(ksess *kcp.UDPSession) {
	mux, err := tunnel.ServerSession(ksess, s.cfg.Zone)
	if err != nil {
		ksess.Close()
		return
	}
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
}

func (s *Server) handleStream(stream *smux.Stream) {
	defer stream.Close()
	stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	pre, err := proto.ReadPreface(stream)
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Time{})

	var release func()
	if s.cfg.Authorizer != nil {
		release, err = s.cfg.Authorizer.Authorize(pre.Token)
		if err != nil {
			s.logger.Printf("engine: auth denied: %v", err)
			return
		}
	}
	if release != nil {
		defer release()
	}

	up, down := s.bridge(stream, pre.Dest)
	if s.cfg.Accountant != nil {
		s.cfg.Accountant.Account(pre.Token, up, down)
	}
}

// bridge connects the stream to its destination and pipes bytes both ways, returning
// the byte counts. Dest "echo" loops the stream back on itself (for tests).
func (s *Server) bridge(stream *smux.Stream, dest string) (up, down int64) {
	if dest == "echo" {
		n, _ := io.Copy(stream, stream)
		return n, n
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	defer cancel()
	d := net.Dialer{}
	remote, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		s.logger.Printf("engine: dial %s: %v", dest, err)
		return 0, 0
	}
	defer remote.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n, _ := io.Copy(remote, stream); up = n; closeWrite(remote) }()
	go func() { defer wg.Done(); n, _ := io.Copy(stream, remote); down = n; stream.Close() }()
	wg.Wait()
	return up, down
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// Close shuts the server down.
func (s *Server) Close() error {
	if s.kcpln != nil {
		s.kcpln.Close()
	}
	return s.pc.Close()
}

// Loopback is an in-memory dnsnet.Exchanger that feeds queries straight into the
// server, with no sockets — used by local end-to-end tests.
type Loopback struct{ S *Server }

func (l Loopback) Exchange(_ context.Context, namePayload []byte) ([]byte, error) {
	return l.S.HandleNamePayload(namePayload), nil
}
func (l Loopback) Close() error { return nil }
