//go:build linux

// Package mobile is the gomobile entry point for the Android client. `gomobile bind`
// turns it into an .aar the Android app imports. It brings up the same tunnel the
// desktop client uses, exposes it as a local SOCKS5 proxy, and feeds the Android
// VpnService's TUN file descriptor through a userspace TCP/IP stack (tun2socks) into
// that proxy, so app traffic is carried over DNS.
//
// Note: the tunnel carries TCP. UDP (including plain DNS and QUIC) is not tunneled yet;
// configure the VpnService DNS accordingly and expect apps to fall back to TCP.
package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnsvpn/client/core"
	"dnsvpn/client/socks"
	"dnsvpn/internal/configlink"
	"dnsvpn/internal/dispatcher"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const socksAddr = "127.0.0.1:1080"

// Protector is implemented in Java by the VpnService. For each outbound socket the Go
// client opens to a resolver, Protect is called with the socket fd so the service can
// VpnService.protect() it — keeping that traffic off the TUN and avoiding a routing loop.
type Protector interface {
	Protect(fd int) bool
}

type jsonConfig struct {
	Zone         string `json:"zone"`
	PSK          string `json:"psk"`
	Token        string `json:"token"`
	Resolvers    string `json:"resolvers"`
	Candidates   string `json:"candidates"`
	Mode         string `json:"mode"`
	Workers      int    `json:"workers"`
	MaxInflight  int    `json:"max_inflight"`
	MaxResolvers int    `json:"max_resolvers"`
	Scan         *bool  `json:"scan"`
	Rescan       string `json:"rescan"`
	QueryTimeout string `json:"query_timeout"`
}

var (
	mu      sync.Mutex
	client  *core.Client
	started bool
	status  = "stopped"
)

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parseMode(s string) dispatcher.Mode {
	switch strings.ToLower(s) {
	case "latency", "lowest-latency":
		return dispatcher.LowestLatency
	case "random":
		return dispatcher.Random
	default:
		return dispatcher.RoundRobin
	}
}

func dur(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

// Start brings the tunnel up and routes the given TUN fd through it. cfgJSON is the
// same JSON the desktop client's -config accepts. mtu is the VpnService MTU (e.g. 1500).
// It returns once the stack is running; call Stop to tear down.
func Start(cfgJSON string, tunFd int, mtu int, protector Protector) error {
	mu.Lock()
	defer mu.Unlock()
	if started {
		return errors.New("already started")
	}
	var c jsonConfig
	if err := json.Unmarshal([]byte(cfgJSON), &c); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if c.Zone == "" || c.PSK == "" {
		return errors.New("config: zone and psk are required")
	}
	scan := true
	if c.Scan != nil {
		scan = *c.Scan
	}
	if mtu <= 0 {
		mtu = 1500
	}

	// Protect every resolver socket so our own DNS traffic bypasses the TUN.
	var ctrl func(network, address string, rc syscall.RawConn) error
	if protector != nil {
		ctrl = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) { protector.Protect(int(fd)) })
		}
	}

	client = core.New(core.Config{
		DialControl:    ctrl,
		Zone:           c.Zone,
		PSK:            c.PSK,
		Token:          c.Token,
		Resolvers:      splitList(c.Resolvers),
		Candidates:     splitList(c.Candidates),
		Mode:           parseMode(c.Mode),
		Workers:        c.Workers,
		MaxInflight:    c.MaxInflight,
		MaxResolvers:   c.MaxResolvers,
		Scan:           scan,
		RescanInterval: dur(c.Rescan, 0),
		QueryTimeout:   dur(c.QueryTimeout, 0),
		Logger:         log.New(log.Writer(), "dnsvpn ", log.LstdFlags),
	})

	// Local SOCKS5 entry point for tun2socks.
	go func() {
		s := &socks.Server{Client: client}
		if err := s.ListenAndServe(socksAddr); err != nil {
			log.Printf("mobile: socks server stopped: %v", err)
		}
	}()

	// Userspace TCP/IP stack over the VpnService TUN, forwarding to the SOCKS proxy.
	engine.Insert(&engine.Key{
		Device:   "fd://" + strconv.Itoa(tunFd),
		Proxy:    "socks5://" + socksAddr,
		LogLevel: "warning",
		MTU:      mtu,
	})
	engine.Start() // this build's Start panics on fatal error rather than returning one

	started = true
	status = "connected"
	return nil
}

// Stop tears the stack and tunnel down. Safe to call when already stopped.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !started {
		return
	}
	engine.Stop()
	if client != nil {
		client.Close()
		client = nil
	}
	started = false
	status = "stopped"
}

// Status returns a short human-readable state ("stopped" / "connected").
func Status() string {
	mu.Lock()
	defer mu.Unlock()
	return status
}

// DecodeLink parses a dnsvpn:// config link and returns its fields as a JSON object
// {name,zone,psk,token,candidates}, for the app to fill its form from.
func DecodeLink(link string) (string, error) {
	c, err := configlink.Decode(link)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	return string(b), err
}
