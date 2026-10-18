// Package proto defines the tunnel's framing that rides inside DNS names.
//
// Every upstream query's QNAME carries, before any resolver sees it, the bytes:
//
//	clientID(8) || nonce(4, big-endian) || datagram(0..N)
//
// base32-encoded into labels (see package dnswire). clientID lets the server demux
// many clients arriving via many resolvers onto distinct sessions; nonce makes each
// QNAME unique so recursive resolvers never serve a cached answer (critical for the
// empty "poll" queries the client uses to pull downstream data). The datagram is an
// opaque KCP segment — proto does not interpret it.
package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ClientIDLen = 8
	NonceLen    = 4
	HeaderLen   = ClientIDLen + NonceLen
)

// ClientID identifies a tunnel session end to end.
type ClientID [ClientIDLen]byte

// NewClientID returns a cryptographically random client id.
func NewClientID() (ClientID, error) {
	var id ClientID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return id, nil
}

func (c ClientID) String() string { return fmt.Sprintf("cid-%x", c[:]) }

// Network implements net.Addr; ClientID doubles as the per-client address used by the
// QueuePacketConn so KCP can tell sessions apart.
func (c ClientID) Network() string { return "dnsvpn" }

// PackWire builds the name payload: clientID || nonce || datagram.
func PackWire(id ClientID, nonce uint32, datagram []byte) []byte {
	out := make([]byte, HeaderLen+len(datagram))
	copy(out[:ClientIDLen], id[:])
	binary.BigEndian.PutUint32(out[ClientIDLen:HeaderLen], nonce)
	copy(out[HeaderLen:], datagram)
	return out
}

var errShort = errors.New("proto: wire payload shorter than header")

// UnpackWire splits a name payload back into its parts. The returned datagram slice
// aliases the input.
func UnpackWire(b []byte) (id ClientID, nonce uint32, datagram []byte, err error) {
	if len(b) < HeaderLen {
		return id, 0, nil, errShort
	}
	copy(id[:], b[:ClientIDLen])
	nonce = binary.BigEndian.Uint32(b[ClientIDLen:HeaderLen])
	datagram = b[HeaderLen:]
	return id, nonce, datagram, nil
}

// ServerAddr is the single fixed net.Addr a client uses to refer to the tunnel server
// through its QueuePacketConn (KCP needs some stable remote address).
type ServerAddr struct{}

func (ServerAddr) Network() string { return "dnsvpn" }
func (ServerAddr) String() string  { return "dnsvpn-server" }

var _ net.Addr = ClientID{}
var _ net.Addr = ServerAddr{}
