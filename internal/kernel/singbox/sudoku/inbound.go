package sudoku

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	api "github.com/SUDOKU-ASCII/sudoku/apis"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio/deadline"
	M "github.com/sagernet/sing/common/metadata"
)

type identity struct {
	user       User
	credential *api.Credential
	publicKey  string
	hash       string
	splitHash  string
}

type userTable struct {
	byName       map[string]*identity
	byCredential map[*api.Credential]*identity
	acceptor     *api.Acceptor
}

type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	cancel    context.CancelFunc
	router    adapter.Router
	logger    log.ContextLogger
	options   Options
	mu        sync.Mutex
	users     *userTable
	listener  net.Listener
	closed    bool
	all       map[net.Conn]*identity
	wg        sync.WaitGroup
	authSlots chan struct{}
	flowSlots chan struct{}
}

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[Options](registry, Type, NewInbound)
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	if options.Network != "" && options.Network != "tcp" {
		return nil, fmt.Errorf("Sudoku only supports TCP transport (UDP uses UoT)")
	}
	if options.AEAD == "" {
		options.AEAD = "chacha20-poly1305"
	}
	// Validate options even when the whitelist is empty.
	if _, err := api.NewCredential(api.Config{Key: "validation", ASCII: options.ASCII, PaddingMin: options.PaddingMin, PaddingMax: options.PaddingMax, CustomTables: options.CustomTables}, options.AEAD); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &Inbound{Adapter: inbound.NewAdapter(Type, tag), ctx: ctx, cancel: cancel, router: router, logger: logger, options: options, all: make(map[net.Conn]*identity), authSlots: make(chan struct{}, 32), flowSlots: make(chan struct{}, 4096)}
	h.users = &userTable{byName: make(map[string]*identity)}
	if err := h.UpdateUsers(options.Users); err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}

func (h *Inbound) UpdateUsers(users []User) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	next := &userTable{byName: make(map[string]*identity, len(users)), byCredential: make(map[*api.Credential]*identity, len(users))}
	credentials := make([]*api.Credential, 0, len(users))
	seen := make(map[string]bool, len(users))
	for _, u := range users {
		if u.Name == "" || next.byName[u.Name] != nil {
			return fmt.Errorf("empty or duplicate Sudoku identity")
		}
		entry := h.users.byName[u.Name]
		if entry == nil || entry.user.UUID != u.UUID {
			var err error
			entry, err = h.prepareIdentity(u, entry)
			if err != nil {
				return err
			}
		}
		if seen[entry.publicKey] {
			return fmt.Errorf("empty or duplicate Sudoku identity")
		}
		seen[entry.publicKey] = true
		next.byName[u.Name] = entry
		next.byCredential[entry.credential] = entry
		credentials = append(credentials, entry.credential)
	}
	next.acceptor = api.NewAcceptor(credentials)
	h.users = next
	for conn, entry := range h.all {
		if entry != nil && next.byName[entry.user.Name] != entry {
			_ = conn.Close()
		}
	}
	return nil
}

func (h *Inbound) prepareIdentity(u User, previous *identity) (*identity, error) {
	private, public, hash, err := Credentials(u.UUID)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.publicKey == public {
		return previous, nil
	}
	credential, err := api.NewCredential(api.Config{Key: public, ASCII: h.options.ASCII, PaddingMin: h.options.PaddingMin, PaddingMax: h.options.PaddingMax, EnablePureDownlink: h.options.PureDownlink, CustomTables: h.options.CustomTables}, h.options.AEAD)
	if err != nil {
		return nil, err
	}
	// Swift clients recover the public point only from the 64-byte
	// split representation. Its two scalars are x and zero.
	var splitKey [64]byte
	_, _ = hex.Decode(splitKey[:32], []byte(private))
	splitHash := sha256.Sum256(splitKey[:])
	return &identity{user: u, credential: credential, publicKey: public, hash: hash, splitHash: hex.EncodeToString(splitHash[:8])}, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return net.ErrClosed
	}
	address := "::"
	if h.options.Listen != nil {
		address = h.options.Listen.Build(netip.IPv6Unspecified()).String()
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(int(h.options.ListenPort))))
	if err != nil {
		return err
	}
	h.listener = ln
	scope.Add(h.Close)
	h.wg.Add(1)
	go h.accept(ln)
	return nil
}

func (h *Inbound) Close() error {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.cancel()
		if h.listener != nil {
			_ = h.listener.Close()
		}
		for conn := range h.all {
			_ = conn.Close()
		}
	}
	h.mu.Unlock()
	h.wg.Wait()
	return nil
}

func (h *Inbound) accept(ln net.Listener) {
	defer h.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed || len(h.all) >= 1024 {
			h.mu.Unlock()
			_ = raw.Close()
			continue
		}
		select {
		case h.authSlots <- struct{}{}:
		default:
			h.mu.Unlock()
			_ = raw.Close()
			continue
		}
		table := h.users
		h.all[raw] = nil
		h.wg.Add(1)
		h.mu.Unlock()
		go h.serve(raw, table)
	}
}

func (h *Inbound) serve(raw net.Conn, table *userTable) {
	defer h.wg.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.all, raw); h.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, credential, hash, err := table.acceptor.Accept(raw)
	<-h.authSlots
	if err != nil {
		h.logger.DebugContext(h.ctx, "Sudoku handshake rejected from ", raw.RemoteAddr(), ": ", err)
		return
	}
	defer conn.Close()
	entry := table.byCredential[credential]
	h.mu.Lock()
	valid := !h.closed && entry != nil && (entry.hash == hash || entry.splitHash == hash) && h.users.byName[entry.user.Name] == entry
	if valid {
		h.all[raw] = entry
	}
	h.mu.Unlock()
	if !valid {
		return
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	var message *api.Message
	for i := 0; i < 16; i++ {
		message, err = api.ReadMessage(conn)
		if err != nil {
			return
		}
		if message.Type != api.KeepAlive {
			break
		}
	}
	_ = raw.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	metadata := adapter.InboundContext{Inbound: h.Tag(), InboundType: Type, User: entry.user.Name, Source: M.SocksaddrFromNet(raw.RemoteAddr())}
	switch message.Type {
	case api.OpenTCP:
		target, err := api.DecodeTarget(message.Payload)
		if err != nil {
			return
		}
		metadata.Destination = M.ParseSocksaddr(target)
		h.routeTCP(ctx, conn, metadata)
	case api.StartMux:
		if len(message.Payload) != 0 {
			return
		}
		_ = api.HandleMuxStreams(conn, func(stream net.Conn, target string) {
			md := metadata
			md.Destination = M.ParseSocksaddr(target)
			h.routeTCP(ctx, &deadlineStream{Conn: deadline.NewConn(stream), stream: stream}, md)
		})
	case api.StartUoT:
		if len(message.Payload) != 0 {
			return
		}
		h.serveUDP(ctx, conn, metadata)
	}
}

// ClientCredential returns provisioning data, not a shared node-wide password.
func ClientCredential(value string, options Options) (*api.Credential, []byte, error) {
	private, public, _, err := Credentials(value)
	if err != nil {
		return nil, nil, err
	}
	key, _ := hex.DecodeString(private)
	if options.AEAD == "" {
		options.AEAD = "chacha20-poly1305"
	}
	c, err := api.NewCredential(api.Config{Key: public, ASCII: options.ASCII, PaddingMin: options.PaddingMin, PaddingMax: options.PaddingMax, EnablePureDownlink: options.PureDownlink, CustomTables: options.CustomTables}, options.AEAD)
	return c, key, err
}

var _ adapter.UpdatableInbound[User] = (*Inbound)(nil)
