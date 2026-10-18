package dnswire

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNameRoundTrip(t *testing.T) {
	zone := "t.example.com"
	for _, size := range []int{1, 7, 31, MaxUpstreamPayload(zone)} {
		payload := make([]byte, size)
		rand.Read(payload)
		name, err := PackName(zone, payload)
		if err != nil {
			t.Fatalf("PackName(%d): %v", size, err)
		}
		got, err := UnpackName(zone, name)
		if err != nil {
			t.Fatalf("UnpackName(%d): %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: round-trip mismatch", size)
		}
	}
}

func TestMaxUpstreamFits(t *testing.T) {
	zone := "t.example.com"
	max := MaxUpstreamPayload(zone)
	payload := make([]byte, max)
	rand.Read(payload)
	name, err := PackName(zone, payload)
	if err != nil {
		t.Fatalf("max payload %d did not fit: %v", max, err)
	}
	// one more byte must still pack structurally but may exceed; ensure the
	// advertised max never overflows the name limit.
	if len(name) > maxName+1 {
		t.Fatalf("name len %d exceeds limit at advertised max", len(name))
	}
}

func TestQueryResponseRoundTrip(t *testing.T) {
	zone := "t.example.com"
	up := []byte("hello upstream datagram")
	name, err := PackName(zone, up)
	if err != nil {
		t.Fatal(err)
	}
	qwire, err := BuildQuery(0x1234, name, dnsmessage.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseQuery(qwire)
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 0x1234 {
		t.Fatalf("id=%x", q.ID)
	}
	gotUp, err := UnpackName(zone, q.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotUp, up) {
		t.Fatalf("upstream mismatch: %q", gotUp)
	}

	down := make([]byte, 600) // spans multiple TXT strings
	rand.Read(down)
	rwire, err := BuildTXTResponse(q, down)
	if err != nil {
		t.Fatal(err)
	}
	gotDown, err := ParseTXTResponse(rwire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDown, down) {
		t.Fatalf("downstream mismatch")
	}
}
