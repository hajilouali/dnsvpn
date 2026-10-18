// Package socks is a minimal SOCKS5 front end that funnels application connections
// into the DNS tunnel. It implements just enough of RFC1928 for CONNECT with no
// authentication (bind it to localhost only).
package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"dnsvpn/client/core"
)

// Server is a SOCKS5 listener bound to a tunnel client.
type Server struct {
	Client *core.Client
	Logger *log.Logger
}

// ListenAndServe serves SOCKS5 on addr until the listener errors.
func (s *Server) ListenAndServe(addr string) error {
	if s.Logger == nil {
		s.Logger = log.Default()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.Logger.Printf("socks: listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	dest, err := handshake(conn)
	if err != nil {
		return
	}
	stream, err := s.Client.OpenStream(dest)
	if err != nil {
		s.Logger.Printf("socks: open tunnel to %s: %v", dest, err)
		// 0x01 general failure
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()
	// success reply with dummy bound addr
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}

// handshake performs the SOCKS5 greeting + CONNECT parse, returning "host:port".
func handshake(conn net.Conn) (string, error) {
	// greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("socks: bad version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	// select "no auth"
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[1] != 0x01 { // CONNECT only
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("socks: unsupported cmd %d", req[1])
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("socks: bad atyp %d", req[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(pb)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
