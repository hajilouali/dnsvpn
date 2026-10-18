// Package tunnel wires KCP (reliable ARQ) + smux (stream multiplexing) over a
// net.PacketConn, with identical tuning on both ends. KCP gives ordered, reliable,
// congestion-controlled delivery over the lossy DNS datagram pipe; smux carries many
// application streams over one KCP session.
package tunnel

import (
	"crypto/sha256"
	"time"

	"dnsvpn/internal/dnswire"
	"dnsvpn/internal/proto"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"net"
)

// Mtu returns the largest KCP datagram that still fits in one upstream query QNAME
// for the given zone (upstream is the tighter direction). KCP segments must not
// exceed this or the query cannot be formed and the segment is lost permanently.
func Mtu(zone string) int {
	m := dnswire.MaxUpstreamPayload(zone) - proto.HeaderLen
	if m < 64 {
		m = 64
	}
	return m
}

func blockFromKey(psk string) kcp.BlockCrypt {
	sum := sha256.Sum256([]byte("dnsvpn-kcp-v1:" + psk))
	b, _ := kcp.NewAESBlockCrypt(sum[:]) // 32-byte key => AES-256
	return b
}

func tune(sess *kcp.UDPSession, mtu int) {
	sess.SetMtu(mtu)
	// Aggressive, low-latency ARQ: nodelay on, 10ms flush, fast resend after 2 dup
	// acks, congestion control off (we pace via the resolver window instead).
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(1024, 1024) // deep windows; the resolver fan-out fills them
	sess.SetACKNoDelay(true)
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
}

func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 30 * time.Second
	c.MaxReceiveBuffer = 8 << 20
	c.MaxStreamBuffer = 2 << 20
	return c
}

// Dial brings up a client smux session over pc toward raddr.
func Dial(pc net.PacketConn, raddr net.Addr, psk, zone string) (*smux.Session, error) {
	sess, err := kcp.NewConn2(raddr, blockFromKey(psk), 0, 0, pc)
	if err != nil {
		return nil, err
	}
	tune(sess, Mtu(zone))
	return smux.Client(sess, smuxConfig())
}

// Listen returns a KCP listener over pc. Accept sessions with AcceptKCP, then wrap
// each with ServerSession.
func Listen(pc net.PacketConn, psk string) (*kcp.Listener, error) {
	return kcp.ServeConn(blockFromKey(psk), 0, 0, pc)
}

// ServerSession tunes an accepted KCP session and wraps it as a smux server.
func ServerSession(sess *kcp.UDPSession, zone string) (*smux.Session, error) {
	tune(sess, Mtu(zone))
	return smux.Server(sess, smuxConfig())
}
