// Package itest holds cross-component integration tests that exercise the real UDP
// datagram path: client -> dispatcher -> UDP socket -> authoritative server -> exit.
// The dispatcher points straight at the server's UDP port (the server answers any
// query under its zone), which stands in for the recursive-resolver hop.
package itest

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"dnsvpn/client/core"
	"dnsvpn/internal/dispatcher"
	"dnsvpn/server/engine"
)

func startEchoTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestRealUDPTunnel(t *testing.T) {
	const zone = "t.example.com"
	const psk = "itest-psk"

	srv, err := engine.New(engine.Config{Zone: zone, PSK: psk})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeUDPConn(udp)
	resolverAddr := udp.LocalAddr().String()
	t.Logf("server DNS on %s", resolverAddr)

	echoAddr := startEchoTCP(t)
	t.Logf("echo TCP on %s", echoAddr)

	cli := core.New(core.Config{
		Zone:      zone,
		PSK:       psk,
		Resolvers: []string{resolverAddr},
		Mode:      dispatcher.RoundRobin,
		Workers:   48,
	})
	defer cli.Close()

	// Carry real TCP traffic through the tunnel to the echo server.
	stream, err := cli.OpenStream(echoAddr)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	payload := make([]byte, 256*1024)
	rand.Read(payload)

	got := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stream, got)
		done <- err
	}()

	start := time.Now()
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timeout")
	}
	elapsed := time.Since(start)

	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch through real UDP tunnel")
	}
	kbps := float64(len(payload)) / 1024 / elapsed.Seconds()
	fmt.Printf("itest: %d KB round-tripped in %s (%.0f KB/s one-way-equiv over loopback)\n",
		len(payload)/1024, elapsed.Round(time.Millisecond), kbps)
}
