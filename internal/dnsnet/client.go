package dnsnet

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dnsvpn/internal/dnswire"
	"dnsvpn/internal/proto"
)

// Exchanger performs one DNS round trip: it carries namePayload upstream (inside a
// query QNAME) and returns the datagram the server packed into the answer. An empty
// return with nil error means the server had nothing queued (an idle poll).
type Exchanger interface {
	Exchange(ctx context.Context, namePayload []byte) ([]byte, error)
	Close() error
}

// Client is the client-side DNS transport. KCP runs over PacketConn(); a window of
// worker goroutines keeps many queries in flight across the resolver pool, carrying
// upstream datagrams and pulling downstream datagrams via poll queries when idle.
type Client struct {
	id    proto.ClientID
	ex    Exchanger
	pc    *QueuePacketConn
	raddr net.Addr

	nonce        uint32
	pollInterval time.Duration
	exchangeTO   time.Duration

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

// ClientConfig tunes the client transport.
type ClientConfig struct {
	Workers      int           // queries kept in flight (window). 0 => 24
	PollInterval time.Duration // idle poll cadence per worker. 0 => 15ms
	ExchangeTO   time.Duration // per-exchange timeout. 0 => 4s
	MaxDatagram  int           // largest KCP datagram. 0 => 1024
}

// NewClient starts the worker window immediately.
func NewClient(id proto.ClientID, ex Exchanger, cfg ClientConfig) *Client {
	if cfg.Workers == 0 {
		cfg.Workers = 24
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 15 * time.Millisecond
	}
	if cfg.ExchangeTO == 0 {
		cfg.ExchangeTO = 4 * time.Second
	}
	if cfg.MaxDatagram == 0 {
		cfg.MaxDatagram = 1024
	}
	c := &Client{
		id:           id,
		ex:           ex,
		raddr:        proto.ServerAddr{},
		pc:           NewQueuePacketConn(id, 4096, cfg.MaxDatagram),
		pollInterval: cfg.PollInterval,
		exchangeTO:   cfg.ExchangeTO,
		closed:       make(chan struct{}),
	}
	out := c.pc.OutboundQueue(c.raddr)
	for i := 0; i < cfg.Workers; i++ {
		c.wg.Add(1)
		go c.worker(out)
	}
	return c
}

// PacketConn is the net.PacketConn KCP should run over on the client side.
func (c *Client) PacketConn() net.PacketConn { return c.pc }

func (c *Client) nextNonce() uint32 { return atomic.AddUint32(&c.nonce, 1) }

func (c *Client) worker(out <-chan []byte) {
	defer c.wg.Done()
	timer := time.NewTimer(c.pollInterval)
	defer timer.Stop()
	for {
		var datagram []byte
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(c.pollInterval)
		select {
		case datagram = <-out: // real upstream datagram
		case <-timer.C: // idle: send an empty poll to pull downstream
		case <-c.closed:
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), c.exchangeTO)
		np := proto.PackWire(c.id, c.nextNonce(), datagram)
		down, err := c.ex.Exchange(ctx, np)
		cancel()
		if err == nil && len(down) > 0 {
			// The server frames one-or-more KCP datagrams into the answer; unpack
			// and deliver each to KCP.
			for _, d := range dnswire.UnpackDatagrams(down) {
				c.pc.QueueIncoming(d, c.raddr)
			}
		}
	}
}

func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.pc.Close()
	})
	c.wg.Wait()
	return c.ex.Close()
}
