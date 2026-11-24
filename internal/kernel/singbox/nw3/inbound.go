//go:build with_quic

package nw3

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	sbTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const handshakeTimeout = 5 * time.Second
const setupTimeout = 10 * time.Second

type identity struct {
	user      User
	key       [32]byte
	keys      morph.Keys
	cidPrefix [4]byte
	mu        sync.Mutex
	revoked   bool
	sessions  map[any]func()
	endpoint  *userEndpoint
}

type userTable struct {
	list   []*identity
	byName map[string]*identity
}

type Inbound struct {
	inbound.Adapter
	ctx            context.Context
	cancel         context.CancelFunc
	router         adapter.Router
	logger         log.ContextLogger
	tls            sbTLS.ServerConfig
	tlsConfig      *tls.Config
	options        Options
	morph          bool
	users          atomic.Pointer[userTable]
	updateMu       sync.Mutex
	all            sync.Map
	wg             sync.WaitGroup
	admission      chan struct{}
	connections    chan struct{}
	flows          chan struct{}
	packet         net.PacketConn
	authorizedQUIC sync.Map
	sourceMu       sync.Mutex
	sources        map[string]sourceIdentity
	closeOnce      sync.Once
	closed         atomic.Bool
}

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[Options](registry, Type, NewInbound)
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, fmt.Errorf("NW3 requires TLS")
	}
	if options.Network != "" && options.Network != "both" && options.Network != "tcp" && options.Network != "udp" {
		return nil, fmt.Errorf("NW3 network must be tcp, udp, or both")
	}
	tlsOptions := *options.TLS
	tlsOptions.ALPN = []string{wire.ALPN}
	tlsOptions.MinVersion, tlsOptions.MaxVersion = "1.3", "1.3"
	config, err := sbTLS.NewServer(ctx, logger, tlsOptions)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &Inbound{Adapter: inbound.NewAdapter(Type, tag), ctx: ctx, cancel: cancel, router: router, logger: logger, tls: config, options: options, morph: true, admission: make(chan struct{}, 256), connections: make(chan struct{}, 1024), flows: make(chan struct{}, 4096), sources: make(map[string]sourceIdentity)}
	if options.Morph != nil {
		h.morph = *options.Morph
	}
	h.users.Store(&userTable{byName: make(map[string]*identity)})
	if err := h.UpdateUsers(options.Users); err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}

func (h *Inbound) UpdateUsers(users []User) error {
	h.updateMu.Lock()
	defer h.updateMu.Unlock()
	if h.closed.Load() {
		return net.ErrClosed
	}
	previous := h.users.Load()
	next := &userTable{byName: make(map[string]*identity, len(users)), list: make([]*identity, 0, len(users))}
	seenKeys := make(map[string]bool, len(users))
	for _, user := range users {
		if user.Name == "" {
			return fmt.Errorf("NW3 user name is empty")
		}
		if err := wire.ValidateServiceKey(user.Key); err != nil {
			return err
		}
		if next.byName[user.Name] != nil || seenKeys[user.Key] {
			return fmt.Errorf("duplicate NW3 user or shared key")
		}
		seenKeys[user.Key] = true
		entry := previous.byName[user.Name]
		if entry == nil || entry.user.Key != user.Key {
			credentials, err := wire.NewCredentials(user.Key)
			if err != nil {
				return err
			}
			key, _ := credentials.RoleKey(wire.RoleVector)
			entry = &identity{user: user, key: key, keys: morph.Derive([]byte(user.Key))}
			hash := sha256.Sum256([]byte("xboard-nw3-cid:" + user.Key))
			copy(entry.cidPrefix[:], hash[:4])
		}
		next.byName[user.Name] = entry
		next.list = append(next.list, entry)
	}
	h.users.Store(next)
	for name, entry := range previous.byName {
		if next.byName[name] == entry {
			continue
		}
		entry.mu.Lock()
		entry.revoked = true
		var closes []func()
		for _, close := range entry.sessions {
			closes = append(closes, close)
		}
		if entry.endpoint != nil {
			closes = append(closes, entry.endpoint.shutdown)
			entry.endpoint = nil
		}
		entry.mu.Unlock()
		for _, close := range closes {
			close()
		}
		h.sourceMu.Lock()
		for address, source := range h.sources {
			if source.user == entry {
				delete(h.sources, address)
			}
		}
		h.sourceMu.Unlock()
	}
	return nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.tls.Start(); err != nil {
		return err
	}
	scope.Add(h.tls.Close)
	config, err := h.tls.STDConfig()
	if err != nil {
		return err
	}
	h.tlsConfig = nw3TLSConfig(config)
	scope.Add(h.Close)
	address := "::"
	if h.options.Listen != nil {
		address = h.options.Listen.Build(netip.IPv6Unspecified()).String()
	}
	address = net.JoinHostPort(address, strconv.Itoa(int(h.options.ListenPort)))
	if h.options.Network != "udp" {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		h.all.Store(ln, func() { _ = ln.Close() })
		h.wg.Add(1)
		go h.acceptTCP(ln)
	}
	if h.options.Network != "tcp" {
		h.packet, err = net.ListenPacket("udp", address)
		if err != nil {
			return err
		}
		if err := h.startQUIC(); err != nil {
			return err
		}
	}
	return nil
}

func (h *Inbound) Close() error {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		h.cancel()
		if h.packet != nil {
			_ = h.packet.Close()
		}
		h.all.Range(func(_, value any) bool { value.(func())(); return true })
		for _, entry := range h.users.Load().list {
			entry.mu.Lock()
			if entry.endpoint != nil {
				entry.endpoint.shutdown()
			}
			entry.mu.Unlock()
		}
		h.wg.Wait()
	})
	return nil
}

func (h *Inbound) takeAuth() bool {
	select {
	case h.connections <- struct{}{}:
	default:
		return false
	}
	select {
	case h.admission <- struct{}{}:
		return true
	default:
		<-h.connections
		return false
	}
}

func (h *Inbound) acceptTCP(ln net.Listener) {
	defer h.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		if !h.takeAuth() {
			_ = raw.Close()
			continue
		}
		h.wg.Add(1)
		h.all.Store(raw, func() { _ = raw.Close() })
		go h.serveTCP(raw)
	}
}

func (h *Inbound) authenticate(r io.Reader, transport wire.AuthTransport, state tls.ConnectionState, expected *identity) (*identity, error) {
	if state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("invalid NW3 TLS negotiation")
	}
	exported, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return nil, err
	}
	var exporter wire.Exporter
	copy(exporter[:], exported)
	var frame [wire.AuthFrameLen]byte
	if _, err := io.ReadFull(r, frame[:]); err != nil {
		return nil, err
	}
	var selected *identity
	for _, entry := range h.users.Load().list {
		tag, _ := wire.EncodeAuthFrame(entry.key, transport, exporter)
		if subtle.ConstantTimeCompare(tag[:], frame[:]) == 1 {
			selected = entry
		}
	}
	if selected == nil || (expected != nil && expected != selected) {
		return nil, fmt.Errorf("invalid NW3 authentication")
	}
	return selected, nil
}

func registerSession(user *identity, session any, close func()) bool {
	user.mu.Lock()
	defer user.mu.Unlock()
	if user.revoked {
		return false
	}
	if user.sessions == nil {
		user.sessions = make(map[any]func())
	}
	user.sessions[session] = close
	return true
}

func unregisterSession(user *identity, session any) {
	user.mu.Lock()
	delete(user.sessions, session)
	user.mu.Unlock()
}

func (h *Inbound) serveTCP(raw net.Conn) {
	defer func() { <-h.connections }()
	defer h.wg.Done()
	defer h.all.Delete(raw)
	defer raw.Close()
	held := true
	defer func() {
		if held {
			<-h.admission
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	conn := raw
	var expected *identity
	if h.morph {
		var err error
		conn, expected, err = h.unwrapTCP(raw)
		if err != nil {
			return
		}
	}
	secure := tls.Server(conn, h.tlsConfig)
	if err := secure.HandshakeContext(h.ctx); err != nil {
		return
	}
	user, err := h.authenticate(secure, wire.AuthTLS, secure.ConnectionState(), expected)
	if err != nil {
		return
	}
	if !registerSession(user, raw, func() { _ = raw.Close() }) {
		return
	}
	defer unregisterSession(user, raw)
	<-h.admission
	held = false
	_ = secure.SetDeadline(time.Time{})
	h.handleFlow(h.ctx, user, secure, nil, 0)
}

func (h *Inbound) handleFlow(ctx context.Context, user *identity, conn net.Conn, packets *dgram.Router, streamID uint64) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(setupTimeout))
	kind, target, present, err := wire.ReadFlowRequest(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if !present && err == nil {
		return
	}
	if err != nil {
		_ = wire.WriteSetupResult(conn, wire.SetupInvalidRequest)
		return
	}
	select {
	case h.flows <- struct{}{}:
		defer func() { <-h.flows }()
	default:
		_ = wire.WriteSetupResult(conn, wire.SetupFlowLimit)
		return
	}
	metadata := adapter.InboundContext{Inbound: h.Tag(), InboundType: Type, Protocol: Type, User: user.user.Name, Source: M.SocksaddrFromNet(conn.RemoteAddr()), Destination: M.Socksaddr{Addr: target.Addr, Fqdn: target.Host, Port: target.Port}}
	ready := newReadyConn(conn)
	if kind == wire.FlowTCP {
		h.router.RouteConnectionEx(ctx, ready, metadata, func(err error) { _ = ready.Close() })
		select {
		case <-ready.done:
		case <-ctx.Done():
			_ = ready.Close()
		}
		return
	}
	if packets != nil && packets.MaxDatagramSize() <= 0 {
		_ = ready.result(wire.SetupInternalError)
		return
	}
	packet, err := newPacketConn(ctx, ready, metadata.Destination, packets, streamID)
	if err != nil {
		_ = ready.result(wire.SetupFlowLimit)
		return
	}
	defer packet.Close()
	h.router.RoutePacketConnectionEx(ctx, packet, metadata, func(err error) { _ = packet.Close() })
	select {
	case <-ready.done:
	case <-ctx.Done():
		_ = packet.Close()
	}
}

var _ adapter.UpdatableInbound[User] = (*Inbound)(nil)
var _ N.HandshakeSuccess = (*readyConn)(nil)
