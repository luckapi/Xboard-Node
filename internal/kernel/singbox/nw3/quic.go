//go:build with_quic

package nw3

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
	quic "github.com/sagernet/quic-go"
)

func (h *Inbound) quicConfig(masked bool) *quic.Config {
	return &quic.Config{
		EnableDatagrams: true, Allow0RTT: false, Versions: []quic.Version{quic.Version1},
		MaxIdleTimeout: 120 * time.Second, KeepAlivePeriod: 30 * time.Second,
		HandshakeIdleTimeout: handshakeTimeout, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 256 << 10,
		InitialConnectionReceiveWindow: 64 << 10, MaxConnectionReceiveWindow: 4 << 20,
		AllowConnectionWindowIncrease: func(conn *quic.Conn, _ uint64) bool { _, ok := h.authorizedQUIC.Load(conn); return ok },
		DisablePathMTUDiscovery:       masked, InitialPacketSize: 1200,
	}
}

func (h *Inbound) startQUIC() error {
	if !h.morph {
		transport := &quic.Transport{Conn: h.packet}
		ln, err := transport.Listen(h.tlsConfig, h.quicConfig(false))
		if err != nil {
			_ = transport.Close()
			return err
		}
		h.all.Store(transport, func() { _ = ln.Close(); _ = transport.Close() })
		h.wg.Add(1)
		go h.acceptQUIC(ln, nil)
		return nil
	}
	h.wg.Add(1)
	go h.dispatchMaskedUDP()
	return nil
}

func (h *Inbound) acceptQUIC(ln *quic.Listener, expected *identity) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept(h.ctx)
		if err != nil {
			return
		}
		if !h.takeAuth() {
			_ = conn.CloseWithError(0, "admission")
			continue
		}
		h.all.Store(conn, func() { _ = conn.CloseWithError(0, "shutdown") })
		h.wg.Add(1)
		go h.serveQUIC(conn, expected)
	}
}

func (h *Inbound) serveQUIC(conn *quic.Conn, expected *identity) {
	defer func() { <-h.connections }()
	defer h.wg.Done()
	defer h.all.Delete(conn)
	defer conn.CloseWithError(0, "")
	held := true
	defer func() {
		if held {
			<-h.admission
		}
	}()
	ctx := conn.Context()
	dropCtx, cancelDrop := context.WithCancel(ctx)
	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		for {
			if _, err := conn.ReceiveDatagram(dropCtx); err != nil {
				return
			}
		}
	}()
	authCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	first, err := conn.AcceptStream(authCtx)
	cancel()
	if err != nil || first.StreamID() != 0 {
		cancelDrop()
		<-dropDone
		return
	}
	_ = first.SetDeadline(time.Now().Add(handshakeTimeout))
	user, err := h.authenticate(first, wire.AuthQUIC, conn.ConnectionState().TLS, expected)
	cancelDrop()
	<-dropDone
	if err != nil {
		return
	}
	if !registerSession(user, conn, func() { _ = conn.CloseWithError(0, "user removed") }) {
		return
	}
	defer unregisterSession(user, conn)
	h.authorizedQUIC.Store(conn, struct{}{})
	defer h.authorizedQUIC.Delete(conn)
	if h.morph {
		h.rememberSource(conn.RemoteAddr().String(), user)
	}
	<-h.admission
	held = false
	_ = first.SetDeadline(time.Time{})
	backend := &quicBackend{conn: conn}
	router := dgram.NewRouter(backend, 4<<20)
	if h.morph {
		router.SetOverhead(12)
	}
	go router.Run(ctx)
	var flows sync.WaitGroup
	defer flows.Wait()
	spawn := func(stream *quic.Stream) {
		flows.Add(1)
		go func() {
			defer flows.Done()
			h.handleFlow(ctx, user, &streamConn{Stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}, router, uint64(stream.StreamID()))
		}()
	}
	spawn(first)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if uint64(stream.StreamID())&3 != 0 {
			_ = conn.CloseWithError(0, "direction")
			return
		}
		if uint64(stream.StreamID()) > uint64(wire.MaxFlowID-1)<<2 {
			_ = stream.SetWriteDeadline(time.Now().Add(time.Second))
			_ = wire.WriteSetupResult(stream, wire.SetupFlowLimit)
			stream.CancelRead(0)
			_ = stream.Close()
			drained := make(chan struct{})
			go func() { flows.Wait(); close(drained) }()
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-drained:
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
			_ = conn.CloseWithError(0, "flow id exhausted")
			return
		}
		spawn(stream)
	}
}

type streamConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }
func (s *streamConn) CloseWrite() error    { return s.Stream.Close() }
func (s *streamConn) Close() error         { s.CancelRead(0); return s.Stream.Close() }

type quicStream struct{ *quic.Stream }

func (s *quicStream) ID() uint64        { return uint64(s.StreamID()) }
func (s *quicStream) CloseWrite() error { return s.Stream.Close() }
func (s *quicStream) Close() error      { s.CancelRead(0); return s.Stream.Close() }

type quicBackend struct {
	conn *quic.Conn
	max  atomic.Int64
}

func (c *quicBackend) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *quicBackend) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }
func (c *quicBackend) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
}
func (c *quicBackend) AcceptStream(ctx context.Context) (qio.Stream, error) {
	s, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s}, nil
}
func (c *quicBackend) OpenStream(ctx context.Context) (qio.Stream, error) {
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s}, nil
}
func (c *quicBackend) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}
func (c *quicBackend) SendDatagram(data []byte) error {
	err := c.conn.SendDatagram(data)
	var large *quic.DatagramTooLargeError
	if errors.As(err, &large) {
		c.max.Store(large.MaxDatagramPayloadSize)
	}
	return err
}
func (c *quicBackend) MaxDatagramSize() int {
	if !c.conn.ConnectionState().SupportsDatagrams.Remote {
		return 0
	}
	if n := c.max.Load(); n > 0 {
		return int(n)
	}
	return 1150
}
func (c *quicBackend) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}
func (c *quicBackend) Context() context.Context { return c.conn.Context() }
func (c *quicBackend) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

type udpPacket struct {
	data []byte
	addr net.Addr
}
type userEndpoint struct {
	host         *Inbound
	user         *identity
	packets      chan udpPacket
	done         chan struct{}
	once         sync.Once
	shutdownOnce sync.Once
	transport    *quic.Transport
	listener     *quic.Listener
}

func (p *userEndpoint) ReadFrom(data []byte) (int, net.Addr, error) {
	select {
	case packet := <-p.packets:
		return copy(data, packet.data), packet.addr, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	case <-p.host.ctx.Done():
		return 0, nil, net.ErrClosed
	}
}
func (p *userEndpoint) WriteTo(data []byte, addr net.Addr) (int, error) {
	encoded, err := maskDatagram(data, &p.user.keys.UDPS2C)
	if err != nil {
		return 0, err
	}
	n, err := p.host.packet.WriteTo(encoded, addr)
	if n == len(encoded) {
		return len(data), err
	}
	return 0, err
}
func (p *userEndpoint) Close() error { p.once.Do(func() { close(p.done) }); return nil }
func (p *userEndpoint) shutdown() {
	p.shutdownOnce.Do(func() {
		_ = p.Close()
		if p.listener != nil {
			_ = p.listener.Close()
		}
		if p.transport != nil {
			_ = p.transport.Close()
		}
		p.host.all.Delete(p)
	})
}
func (p *userEndpoint) LocalAddr() net.Addr              { return p.host.packet.LocalAddr() }
func (p *userEndpoint) SetDeadline(time.Time) error      { return nil }
func (p *userEndpoint) SetReadDeadline(time.Time) error  { return nil }
func (p *userEndpoint) SetWriteDeadline(time.Time) error { return nil }

type userCID struct{ prefix [4]byte }

func (g userCID) ConnectionIDLen() int { return 12 }
func (g userCID) GenerateConnectionID() (quic.ConnectionID, error) {
	var id [12]byte
	copy(id[:4], g.prefix[:])
	if _, err := rand.Read(id[4:]); err != nil {
		return quic.ConnectionID{}, err
	}
	return quic.ConnectionIDFromBytes(id[:]), nil
}

func packetMatchesUser(header []byte, prefix [4]byte) bool {
	if len(header) < 6 || header[0]&0x40 == 0 {
		return false
	}
	if header[0]&0x80 == 0 {
		return bytes.Equal(header[1:5], prefix[:])
	}
	if len(header) < 7 || binary.BigEndian.Uint32(header[1:5]) != 1 {
		return false
	}
	dcidLength := int(header[5])
	if dcidLength > 20 || len(header) < 7+dcidLength {
		return false
	}
	if dcidLength >= 4 && bytes.Equal(header[6:10], prefix[:]) {
		return true
	}
	// Only an Initial may introduce a client-chosen destination CID.
	return header[0]&0x30 == 0 && int(header[6+dcidLength]) <= 20
}

func (h *Inbound) dispatchMaskedUDP() {
	defer h.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, addr, err := h.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		if n <= 12 {
			continue
		}
		wireData := buffer[:n]
		cached := h.cachedSource(addr.String())
		if cached != nil && h.deliverMasked(wireData, addr, cached) {
			continue
		}
		for _, user := range h.users.Load().list {
			if user != cached && h.deliverMasked(wireData, addr, user) {
				break
			}
		}
	}
}

func (h *Inbound) deliverMasked(data []byte, addr net.Addr, user *identity) bool {
	var header [64]byte
	size := min(len(data)-12, len(header))
	if xorAt(header[:size], data[12:12+size], &user.keys.UDPC2S, data[:12], 0) != nil || !packetMatchesUser(header[:size], user.cidPrefix) {
		return false
	}
	endpoint, err := h.endpoint(user)
	if err != nil {
		return false
	}
	payload := make([]byte, len(data)-12)
	if xorAt(payload, data[12:], &user.keys.UDPC2S, data[:12], 0) != nil {
		return false
	}
	select {
	case endpoint.packets <- udpPacket{data: payload, addr: addr}:
	default:
	}
	return true
}

type sourceIdentity struct {
	user    *identity
	expires time.Time
}

func (h *Inbound) cachedSource(address string) *identity {
	h.sourceMu.Lock()
	defer h.sourceMu.Unlock()
	entry := h.sources[address]
	if time.Now().After(entry.expires) {
		delete(h.sources, address)
		return nil
	}
	entry.expires = time.Now().Add(5 * time.Minute)
	h.sources[address] = entry
	return entry.user
}

func (h *Inbound) rememberSource(address string, user *identity) {
	h.sourceMu.Lock()
	defer h.sourceMu.Unlock()
	if len(h.sources) >= 4096 {
		for key, entry := range h.sources {
			if time.Now().After(entry.expires) {
				delete(h.sources, key)
			}
		}
		if len(h.sources) >= 4096 {
			return
		}
	}
	h.sources[address] = sourceIdentity{user: user, expires: time.Now().Add(5 * time.Minute)}
}

func (h *Inbound) endpoint(user *identity) (*userEndpoint, error) {
	user.mu.Lock()
	defer user.mu.Unlock()
	if user.revoked || h.closed.Load() {
		return nil, os.ErrClosed
	}
	if user.endpoint != nil {
		return user.endpoint, nil
	}
	p := &userEndpoint{host: h, user: user, packets: make(chan udpPacket, 32), done: make(chan struct{})}
	p.transport = &quic.Transport{Conn: p, ConnectionIDGenerator: userCID{prefix: user.cidPrefix}}
	ln, err := p.transport.Listen(h.tlsConfig, h.quicConfig(true))
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	p.listener = ln
	user.endpoint = p
	h.all.Store(p, p.shutdown)
	h.wg.Add(1)
	go h.acceptQUIC(ln, user)
	return p, nil
}

var _ qio.Conn = (*quicBackend)(nil)
