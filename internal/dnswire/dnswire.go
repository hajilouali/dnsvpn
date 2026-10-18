// Package dnswire encodes opaque tunnel datagrams into DNS messages and back.
//
// Upstream (client -> server) a datagram is base32-packed into the QNAME labels of
// a query under the tunnel zone. Downstream (server -> client) a datagram is packed
// into answer-record RDATA (TXT today; larger shapes negotiated later).
//
// This package knows nothing about the datagram's internal structure; it only moves
// bytes in and out of DNS wire format. The tunnel header lives in package proto.
package dnswire

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// EDNSUDPSize is the UDP payload size the client advertises via EDNS0 so recursive
// resolvers return answers larger than the bare 512-byte limit. 1232 is the widely
// recommended safe value (DNS Flag Day 2020) that avoids IP fragmentation.
const EDNSUDPSize = 1232

// b32 is lowercase, unpadded RFC4648. Lowercase keeps the QNAME canonical regardless
// of any 0x20 case randomization a resolver applies, and unpadded avoids '=' in labels.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func init() {
	// Use a lowercase alphabet so names are case-stable through resolvers.
	b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
}

const (
	maxLabel = 63  // RFC1035 single-label limit
	maxName  = 254 // RFC1035 name limit (255 incl. root), leave margin
)

// nameWireMax is the hard DNS name limit in wire format, in bytes (RFC1035 §3.1).
// A name is a sequence of <len octet><label> pairs terminated by a zero octet, so its
// wire length counts one length octet per label plus the final root octet. This is the
// real ceiling a query must satisfy — the presentation (dotted) string can be shorter.
const nameWireMax = 255

// safetyMargin leaves headroom under the hard limit for resolver quirks (some apply
// 0x20 case randomization — length-neutral — or trim long names). Bytes of wire budget.
const safetyMargin = 4

// zoneWireLen returns the wire-format length of zone, including its terminating root
// octet: Σ(1 + len(label)) + 1.
func zoneWireLen(zone string) int {
	zone = strings.TrimSuffix(zone, ".")
	w := 1 // root octet
	for _, lbl := range strings.Split(zone, ".") {
		w += 1 + len(lbl)
	}
	return w
}

// MaxUpstreamPayload returns how many raw datagram bytes fit in one query QNAME for
// the given zone while keeping the name within the DNS wire limit. The zone must be the
// fully-qualified tunnel zone WITHOUT a trailing dot (e.g. "t.example.com").
//
// Encoding a raw payload of N bytes yields T = ceil(N*8/5) base32 chars, split into
// ceil(T/63) labels; those cost T + ceil(T/63) wire bytes, which together with the
// zone's wire length and a safety margin must stay <= 255.
func MaxUpstreamPayload(zone string) int {
	budget := nameWireMax - safetyMargin - zoneWireLen(zone)
	if budget <= 0 {
		return 0
	}
	best := 0
	for raw := 1; raw <= 255; raw++ {
		t := (raw*8 + 4) / 5    // ceil(raw*8/5)
		labels := (t + maxLabel - 1) / maxLabel // ceil(t/63)
		if t+labels <= budget {
			best = raw
			continue
		}
		break
	}
	return best
}

// PackName base32-encodes payload and splits it into <=63-char labels under zone,
// returning a fully-qualified name with a trailing dot, ready for a query.
func PackName(zone string, payload []byte) (string, error) {
	zone = strings.TrimSuffix(zone, ".")
	enc := b32.EncodeToString(payload)
	var b strings.Builder
	for i := 0; i < len(enc); i += maxLabel {
		end := i + maxLabel
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('.')
	}
	b.WriteString(zone)
	b.WriteByte('.')
	name := b.String()
	if len(name) > maxName+1 {
		return "", fmt.Errorf("dnswire: packed name %d > %d bytes", len(name), maxName)
	}
	return name, nil
}

// UnpackName is the inverse of PackName: it strips the zone suffix, concatenates the
// remaining labels and base32-decodes them back to the datagram payload.
func UnpackName(zone, name string) ([]byte, error) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	suffix := "." + zone
	if !strings.HasSuffix(n, suffix) {
		return nil, fmt.Errorf("dnswire: %q not under zone %q", name, zone)
	}
	labels := n[:len(n)-len(suffix)]
	enc := strings.ReplaceAll(labels, ".", "")
	data, err := b32.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("dnswire: base32 decode: %w", err)
	}
	return data, nil
}

// --- downstream TXT packing ---------------------------------------------------

// PackTXT splits payload into DNS character-strings (<=255 bytes each) for a TXT RR.
// A TXT record is a sequence of such strings concatenated on receipt.
func PackTXT(payload []byte) []string {
	if len(payload) == 0 {
		return []string{""}
	}
	var out []string
	for i := 0; i < len(payload); i += 255 {
		end := i + 255
		if end > len(payload) {
			end = len(payload)
		}
		out = append(out, string(payload[i:end]))
	}
	return out
}

// UnpackTXT concatenates TXT strings back into the datagram payload.
func UnpackTXT(strs []string) []byte {
	var out []byte
	for _, s := range strs {
		out = append(out, s...)
	}
	return out
}

// --- downstream datagram batching --------------------------------------------
//
// A single query QNAME can only carry ~130 bytes upstream, but one answer can carry
// up to ~1200 bytes downstream (with EDNS0). To exploit that asymmetry the server
// packs SEVERAL queued KCP datagrams into one answer. Each is framed with a uint16
// big-endian length prefix; PackDatagrams concatenates them, UnpackDatagrams splits
// them back out. This multiplies downstream throughput by the batch factor.

// PackDatagrams frames datagrams as [len16][bytes]... into a single blob.
func PackDatagrams(ds [][]byte) []byte {
	n := 0
	for _, d := range ds {
		n += 2 + len(d)
	}
	out := make([]byte, 0, n)
	var hdr [2]byte
	for _, d := range ds {
		binary.BigEndian.PutUint16(hdr[:], uint16(len(d)))
		out = append(out, hdr[:]...)
		out = append(out, d...)
	}
	return out
}

// UnpackDatagrams reverses PackDatagrams. A trailing partial frame is ignored.
func UnpackDatagrams(b []byte) [][]byte {
	var out [][]byte
	for len(b) >= 2 {
		n := int(binary.BigEndian.Uint16(b[:2]))
		if 2+n > len(b) {
			break
		}
		out = append(out, b[2:2+n])
		b = b[2+n:]
	}
	return out
}

// --- DNS message build/parse --------------------------------------------------

var errNoQuestion = errors.New("dnswire: message has no question")

// BuildQuery builds a wire-format DNS query for name/qtype with the given id.
func BuildQuery(id uint16, name string, qtype dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, fmt.Errorf("dnswire: name: %w", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  n,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	// Advertise a larger UDP buffer via EDNS0 so answers can exceed 512 bytes.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(EDNSUDPSize, dnsmessage.RCodeSuccess, false); err == nil {
		msg.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	return msg.Pack()
}

// Query is a parsed inbound question on the server side.
type Query struct {
	ID    uint16
	Name  string
	Type  dnsmessage.Type
	Raw   dnsmessage.Message
}

// ParseQuery parses a wire query and returns its first question.
func ParseQuery(wire []byte) (*Query, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(wire); err != nil {
		return nil, fmt.Errorf("dnswire: unpack query: %w", err)
	}
	if len(msg.Questions) == 0 {
		return nil, errNoQuestion
	}
	q := msg.Questions[0]
	return &Query{
		ID:   msg.Header.ID,
		Name: q.Name.String(),
		Type: q.Type,
		Raw:  msg,
	}, nil
}

// BuildTXTResponse builds a wire response to q carrying payload in a single TXT RR.
func BuildTXTResponse(q *Query, payload []byte) ([]byte, error) {
	name, err := dnsmessage.NewName(q.Name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            q.ID,
			Response:      true,
			Authoritative: true,
		},
		Questions: q.Raw.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			Body: &dnsmessage.TXTResource{TXT: PackTXT(payload)},
		}},
	}
	// Mirror EDNS0 so the response is a well-formed large-UDP answer.
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(EDNSUDPSize, dnsmessage.RCodeSuccess, false); err == nil {
		msg.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	return msg.Pack()
}

// ParseTXTResponse extracts the datagram payload from a TXT answer.
func ParseTXTResponse(wire []byte) ([]byte, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(wire); err != nil {
		return nil, fmt.Errorf("dnswire: unpack response: %w", err)
	}
	for _, a := range msg.Answers {
		if txt, ok := a.Body.(*dnsmessage.TXTResource); ok {
			return UnpackTXT(txt.TXT), nil
		}
	}
	return nil, errors.New("dnswire: no TXT answer")
}
