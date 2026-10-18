package engine

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"dnsvpn/internal/dnsnet"
	"dnsvpn/internal/proto"
	"dnsvpn/internal/tunnel"
)

// TestEndToEndEcho drives the whole stack with no network: app bytes -> smux -> KCP
// -> DNS name codec -> loopback into the server -> echo exit -> back again.
func TestEndToEndEcho(t *testing.T) {
	const zone = "t.example.com"
	const psk = "unit-test-psk"

	srv, err := New(Config{Zone: zone, PSK: psk})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	id, _ := proto.NewClientID()
	cli := dnsnet.NewClient(id, Loopback{S: srv}, dnsnet.ClientConfig{
		Workers:     32,
		MaxDatagram: tunnel.Mtu(zone),
	})
	defer cli.Close()

	mux, err := tunnel.Dial(cli.PacketConn(), proto.ServerAddr{}, psk, zone)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer mux.Close()

	stream, err := mux.OpenStream()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	if _, err := (proto.StreamPreface{Dest: "echo"}).WriteTo(stream); err != nil {
		t.Fatalf("preface: %v", err)
	}

	payload := make([]byte, 64*1024)
	rand.Read(payload)

	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Errorf("read: %v", err)
			done <- nil
			return
		}
		done <- got
	}()

	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: %d bytes", len(got))
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for echo")
	}
}
