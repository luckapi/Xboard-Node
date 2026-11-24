package sudoku

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	api "github.com/SUDOKU-ASCII/sudoku/apis"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type routedConn struct {
	net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newRoutedConn(conn net.Conn) *routedConn {
	return &routedConn{Conn: conn, done: make(chan struct{})}
}
func (c *routedConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.Conn.Close(); close(c.done) })
	return err
}
func (c *routedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

func (h *Inbound) routeTCP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	c, ok := conn.(*routedConn)
	if !ok {
		c = newRoutedConn(conn)
	}
	defer c.Close()
	if !metadata.Destination.IsValid() || metadata.Destination.Port == 0 {
		return
	}
	select {
	case h.flowSlots <- struct{}{}:
		defer func() { <-h.flowSlots }()
	default:
		return
	}
	h.router.RouteConnectionEx(ctx, c, metadata, func(error) { _ = c.Close() })
	select {
	case <-c.done:
	case <-ctx.Done():
	}
}

// Native mux streams do not implement read deadlines; sing's deadline adapter
// keeps sniffing bounded while preserving the native stream's half-close.
type deadlineStream struct {
	net.Conn
	stream net.Conn
}

func (c *deadlineStream) CloseWrite() error {
	if s, ok := c.stream.(interface{ CloseWrite() error }); ok {
		return s.CloseWrite()
	}
	return c.Close()
}

type udpSession struct {
	net.Conn
	writeMu sync.Mutex
}

type packetConn struct {
	session      *udpSession
	destination  M.Socksaddr
	input        chan []byte
	done         chan struct{}
	once         sync.Once
	mu           sync.Mutex
	readDeadline time.Time
}

func (p *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	p.mu.Lock()
	deadline := p.readDeadline
	p.mu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(120 * time.Second)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case payload := <-p.input:
		_, err := buffer.Write(payload)
		return p.destination, err
	case <-p.done:
		return M.Socksaddr{}, net.ErrClosed
	case <-timer.C:
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}
func (p *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	p.session.writeMu.Lock()
	defer p.session.writeMu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	_ = p.session.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := api.WriteDatagram(p.session.Conn, destination.String(), buffer.Bytes())
	_ = p.session.SetWriteDeadline(time.Time{})
	return err
}
func (p *packetConn) Close() error        { p.once.Do(func() { close(p.done) }); return nil }
func (p *packetConn) LocalAddr() net.Addr { return p.session.LocalAddr() }
func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	return nil
}
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.session.SetWriteDeadline(t) }
func (p *packetConn) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}

func (h *Inbound) serveUDP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	session := &udpSession{Conn: conn}
	flows := make(map[string]*packetConn)
	var wg sync.WaitGroup
	defer func() {
		for _, p := range flows {
			_ = p.Close()
		}
		wg.Wait()
	}()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		target, payload, err := api.ReadDatagram(conn)
		if err != nil {
			return
		}
		destination := M.ParseSocksaddr(target)
		if !destination.IsValid() || destination.Port == 0 || len(payload) > 65507 {
			return
		}
		p := flows[target]
		if p != nil {
			select {
			case <-p.done:
				delete(flows, target)
				p = nil
			default:
			}
		}
		if p == nil {
			for key, flow := range flows {
				select {
				case <-flow.done:
					delete(flows, key)
				default:
				}
			}
			if len(flows) >= 64 {
				continue
			}
			select {
			case h.flowSlots <- struct{}{}:
			default:
				continue
			}
			p = &packetConn{session: session, destination: destination, input: make(chan []byte), done: make(chan struct{})}
			flows[target] = p
			md := metadata
			md.Destination = destination
			wg.Add(1)
			go func(p *packetConn, md adapter.InboundContext) {
				defer wg.Done()
				defer func() { <-h.flowSlots }()
				defer p.Close()
				h.router.RoutePacketConnectionEx(ctx, p, md, func(error) { _ = p.Close() })
				select {
				case <-p.done:
				case <-ctx.Done():
				}
			}(p, md)
		}
		select {
		case p.input <- payload:
		case <-p.done:
		case <-ctx.Done():
			return
		}
	}
}
