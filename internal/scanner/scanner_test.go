package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"dnsvpn/internal/dnswire"
	"dnsvpn/server/engine"
)

// startHijacker stands up a fake resolver that answers every query with a bogus TXT,
// standing in for a captive-portal / court-order page that doesn't hold the PSK.
func startHijacker(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q, err := dnswire.ParseQuery(buf[:n])
			if err != nil {
				continue
			}
			resp, err := dnswire.BuildTXTResponse(q, []byte("hijacked-by-portal"))
			if err == nil {
				c.WriteToUDP(resp, src)
			}
		}
	}()
	return c.LocalAddr().String()
}

func TestScanValidatesResolvers(t *testing.T) {
	const zone = "t.example.com"
	const psk = "scan-psk"

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

	good := udp.LocalAddr().String()
	hijacker := startHijacker(t)
	dead := "127.0.0.1:1" // nothing listening

	results := Scan(context.Background(), Config{
		Zone: zone, PSK: psk, Timeout: time.Second, Attempts: 1,
	}, []string{good, hijacker, dead})

	ok := map[string]bool{}
	for _, r := range results {
		ok[r.Addr] = r.OK
	}
	if !ok[good] {
		t.Errorf("genuine server %s should pass the probe", good)
	}
	if ok[hijacker] {
		t.Errorf("hijacker %s must be rejected (bad reply)", hijacker)
	}
	if ok[dead] {
		t.Errorf("dead addr %s must be rejected (timeout)", dead)
	}

	// Best() must return the genuine resolver first and exclude the others.
	best := Best(results, 8)
	if len(best) != 1 || best[0] != good {
		t.Errorf("Best = %v, want [%s]", best, good)
	}
}
