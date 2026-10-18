package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

// Resolver probing rides the same QNAME channel as tunnel data but is a distinct,
// self-contained request/response that never touches KCP. A client sends a probe
// through a candidate recursive resolver; if the authentic reply comes back, that
// resolver provably reaches our authoritative server AND the answer is genuine (not a
// hijack/NXDOMAIN page), because only a party holding the PSK can compute the reply.
// This is what lets the client's scanner keep good resolvers and reject poisoned ones.

// ProbeMagic prefixes a probe's name payload so the server can tell probes from the
// clientID||nonce||datagram of ordinary tunnel queries. Chosen random-ish; a genuine
// datagram colliding with it is ~2^-32 and merely costs one KCP retransmit.
var ProbeMagic = [4]byte{0xd5, 0x17, 0x7e, 0x53}

const (
	ProbeMagicLen     = 4
	ProbeChallengeLen = 16 // random challenge the server must authenticate
	ProbeReplyLen     = 16 // truncated HMAC returned by the server
	probePayloadLen   = ProbeMagicLen + ProbeChallengeLen
)

// NewProbeChallenge returns a fresh random challenge.
func NewProbeChallenge() []byte {
	c := make([]byte, ProbeChallengeLen)
	rand.Read(c)
	return c
}

// BuildProbe builds the name payload for a probe: magic || challenge.
func BuildProbe(challenge []byte) []byte {
	out := make([]byte, 0, probePayloadLen)
	out = append(out, ProbeMagic[:]...)
	out = append(out, challenge...)
	return out
}

// ParseProbe reports whether b is a probe payload and returns its challenge.
func ParseProbe(b []byte) (challenge []byte, ok bool) {
	if len(b) != probePayloadLen {
		return nil, false
	}
	if subtle.ConstantTimeCompare(b[:ProbeMagicLen], ProbeMagic[:]) != 1 {
		return nil, false
	}
	return b[ProbeMagicLen:], true
}

// ProbeReply computes the authenticated reply for a challenge: the first ProbeReplyLen
// bytes of HMAC-SHA256(psk, magic || challenge). Both ends derive it independently, so
// a matching reply proves the responder holds the PSK.
func ProbeReply(psk string, challenge []byte) []byte {
	m := hmac.New(sha256.New, []byte("dnsvpn-probe-v1:"+psk))
	m.Write(ProbeMagic[:])
	m.Write(challenge)
	return m.Sum(nil)[:ProbeReplyLen]
}

// VerifyProbeReply reports whether reply authenticates challenge under psk.
func VerifyProbeReply(psk string, challenge, reply []byte) bool {
	want := ProbeReply(psk, challenge)
	return subtle.ConstantTimeCompare(want, reply) == 1
}
