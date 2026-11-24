//go:build with_quic

package nw3

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type readyConn struct {
	net.Conn
	mu   sync.Mutex
	sent bool
	done chan struct{}
	once sync.Once
}

func newReadyConn(conn net.Conn) *readyConn { return &readyConn{Conn: conn, done: make(chan struct{})} }

func (c *readyConn) result(code wire.SetupResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent {
		return nil
	}
	c.sent = true
	_ = c.Conn.SetWriteDeadline(time.Now().Add(setupTimeout))
	defer c.Conn.SetWriteDeadline(time.Time{})
	return wire.WriteSetupResult(c.Conn, code)
}

func (c *readyConn) HandshakeSuccess() error      { return c.result(wire.SetupReady) }
func (c *readyConn) HandshakeFailure(error) error { return c.result(wire.SetupDialFailed) }
func (c *readyConn) CloseWrite() error {
	if c, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return c.Close()
}
func (c *readyConn) Close() error {
	var err error
	c.once.Do(func() {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = c.result(wire.SetupFlowLimit)
		err = c.Conn.Close()
		close(c.done)
	})
	return err
}

type packetConn struct {
	*readyConn
	ctx             context.Context
	destination     M.Socksaddr
	router          *dgram.Router
	flow            *dgram.Flow
	id              uint32
	mu              sync.Mutex
	readDeadline    time.Time
	readMu, writeMu sync.Mutex
	closeOnce       sync.Once
}

func newPacketConn(ctx context.Context, conn *readyConn, destination M.Socksaddr, router *dgram.Router, streamID uint64) (*packetConn, error) {
	p := &packetConn{readyConn: conn, ctx: ctx, destination: destination, router: router}
	if router != nil {
		id, err := wire.UDPFlowID(streamID, false)
		if err != nil {
			return nil, err
		}
		p.id = id
	}
	return p, nil
}

func (p *packetConn) HandshakeSuccess() error {
	if err := p.readyConn.HandshakeSuccess(); err != nil {
		return err
	}
	if p.router != nil {
		p.mu.Lock()
		p.flow = p.router.Register(p.id)
		p.mu.Unlock()
		go func() { var data [1]byte; _, _ = p.Conn.Read(data[:]); _ = p.Close() }()
	}
	return nil
}

func (p *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	var payload []byte
	if p.router == nil {
		p.mu.Lock()
		deadline := p.readDeadline
		p.mu.Unlock()
		if deadline.IsZero() {
			deadline = time.Now().Add(120 * time.Second)
		}
		_ = p.Conn.SetReadDeadline(deadline)
		var err error
		payload, err = wire.ReadUoT(p.Conn)
		if err != nil {
			return M.Socksaddr{}, err
		}
	} else {
		p.mu.Lock()
		flow, deadline := p.flow, p.readDeadline
		p.mu.Unlock()
		if flow == nil {
			return M.Socksaddr{}, io.ErrClosedPipe
		}
		if deadline.IsZero() {
			deadline = time.Now().Add(120 * time.Second)
		}
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case payload = <-flow.C:
			flow.ReleasePacket(payload)
		case <-flow.Done():
			return M.Socksaddr{}, net.ErrClosed
		case <-p.done:
			return M.Socksaddr{}, net.ErrClosed
		case <-p.ctx.Done():
			return M.Socksaddr{}, p.ctx.Err()
		case <-timer.C:
			return M.Socksaddr{}, os.ErrDeadlineExceeded
		}
	}
	_, err := buffer.Write(payload)
	return p.destination, err
}

func (p *packetConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.router != nil {
		return p.router.Send(p.id, buffer.Bytes())
	}
	return wire.WriteUoT(p.Conn, buffer.Bytes())
}

func (p *packetConn) Close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.router != nil {
			p.router.CloseFlow(p.id)
		}
		err = p.readyConn.Close()
	})
	return err
}

func (p *packetConn) SetReadDeadline(deadline time.Time) error {
	p.mu.Lock()
	p.readDeadline = deadline
	p.mu.Unlock()
	if p.router == nil {
		return p.Conn.SetReadDeadline(deadline)
	}
	return nil
}

func (p *packetConn) SetDeadline(deadline time.Time) error {
	_ = p.SetReadDeadline(deadline)
	return p.Conn.SetWriteDeadline(deadline)
}
