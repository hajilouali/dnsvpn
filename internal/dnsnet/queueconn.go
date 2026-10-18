// Package dnsnet carries KCP datagrams over DNS.
//
// QueuePacketConn adapts the request/response, connectionless world of DNS to the
// net.PacketConn that KCP expects. KCP reads/writes datagrams against it; the DNS
// machinery (client workers, server handler) moves those datagrams in and out via
// QueueIncoming and per-address outbound queues. This is the "Turbo Tunnel" seam:
// an unreliable datagram pipe below, reliable ordered streams above.
package dnsnet

import (
	"errors"
	"net"
	"sync"
	"time"
)

// taggedPacket is one datagram plus the peer address it is to/from.
type taggedPacket struct {
	data []byte
	addr net.Addr
}

// QueuePacketConn implements net.PacketConn over in-memory queues.
//
//   - WriteTo(p, addr) enqueues p on addr's outbound queue; the DNS layer drains that
//     queue (client: to fill query payloads; server: to fill answer RDATA).
//   - QueueIncoming(p, addr) delivers a datagram that arrived over DNS so that the
//     next ReadFrom returns it to KCP.
type QueuePacketConn struct {
	local   net.Addr
	maxLen  int
	incoming chan taggedPacket

	mu       sync.Mutex
	outbound map[string]chan []byte
	closed   chan struct{}
	closeOnce sync.Once
}

// NewQueuePacketConn creates a conn whose local address is local. qcap bounds each
// queue; maxLen is the largest datagram accepted (silently dropped if larger, as a
// real lossy link would).
func NewQueuePacketConn(local net.Addr, qcap, maxLen int) *QueuePacketConn {
	return &QueuePacketConn{
		local:    local,
		maxLen:   maxLen,
		incoming: make(chan taggedPacket, qcap),
		outbound: make(map[string]chan []byte),
		closed:   make(chan struct{}),
	}
}

func (c *QueuePacketConn) queueFor(addr net.Addr) chan []byte {
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	q, ok := c.outbound[key]
	if !ok {
		q = make(chan []byte, 2048)
		c.outbound[key] = q
	}
	return q
}

// OutboundQueue returns the drain channel of datagrams KCP wants sent to addr.
func (c *QueuePacketConn) OutboundQueue(addr net.Addr) <-chan []byte {
	return c.queueFor(addr)
}

// QueueIncoming hands a datagram received over DNS to KCP. A copy is made.
func (c *QueuePacketConn) QueueIncoming(p []byte, addr net.Addr) {
	if len(p) == 0 || len(p) > c.maxLen {
		return
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case c.incoming <- taggedPacket{cp, addr}:
	case <-c.closed:
	default: // full: drop, like a congested link
	}
}

// ReadFrom returns the next datagram received over DNS.
func (c *QueuePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.incoming:
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo enqueues p to be carried to addr by the DNS layer. A copy is made.
func (c *QueuePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > c.maxLen {
		return 0, errors.New("dnsnet: datagram exceeds max length")
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	q := c.queueFor(addr)
	select {
	case q <- cp:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(p), nil // drop on overflow; KCP will retransmit
	}
}

func (c *QueuePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *QueuePacketConn) LocalAddr() net.Addr                { return c.local }
func (c *QueuePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *QueuePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *QueuePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Done reports the conn's close channel.
func (c *QueuePacketConn) Done() <-chan struct{} { return c.closed }
