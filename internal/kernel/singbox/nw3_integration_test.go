//go:build with_quic && with_utls

package singbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox/nw3"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/vector"
	"github.com/ohmycggk/nowhere-go/wire"
	quic "github.com/sagernet/quic-go"
)

type nw3TestQUIC struct{ conn *quic.Conn }
type nw3TestStream struct{ *quic.Stream }

func (s *nw3TestStream) ID() uint64        { return uint64(s.StreamID()) }
func (s *nw3TestStream) CloseWrite() error { return s.Stream.Close() }
func (s *nw3TestStream) Close() error      { s.CancelRead(0); return s.Stream.Close() }
func (q nw3TestQUIC) TLSVersion() uint16   { return q.conn.ConnectionState().TLS.Version }
func (q nw3TestQUIC) ALPN() string         { return q.conn.ConnectionState().TLS.NegotiatedProtocol }
func (q nw3TestQUIC) Exporter() ([]byte, error) {
	state := q.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, 32)
}
func (q nw3TestQUIC) AcceptStream(ctx context.Context) (qio.Stream, error) {
	s, e := q.conn.AcceptStream(ctx)
	if e != nil {
		return nil, e
	}
	return &nw3TestStream{s}, nil
}
func (q nw3TestQUIC) OpenStream(ctx context.Context) (qio.Stream, error) {
	s, e := q.conn.OpenStreamSync(ctx)
	if e != nil {
		return nil, e
	}
	return &nw3TestStream{s}, nil
}
func (q nw3TestQUIC) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}
func (q nw3TestQUIC) SendDatagram(b []byte) error { return q.conn.SendDatagram(b) }
func (q nw3TestQUIC) MaxDatagramSize() int {
	if !q.conn.ConnectionState().SupportsDatagrams.Remote {
		return 0
	}
	return 1100
}
func (q nw3TestQUIC) CloseWithError(code uint64, message string) error {
	return q.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}
func (q nw3TestQUIC) Context() context.Context { return q.conn.Context() }
func (q nw3TestQUIC) RemoteAddr() net.Addr     { return q.conn.RemoteAddr() }

func nw3Client(t *testing.T, address, key, transport string, masked bool) *vector.Client {
	t.Helper()
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{wire.ALPN}}
	options := vector.Config{SharedKey: key, PortalAddr: address, Morph: masked, TLS: tlsConfig}
	if transport == "tcp" {
		options.DialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	} else {
		options.DatagramOverhead = 12
		options.DialQUIC = func(ctx context.Context) (qio.Conn, error) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = pc.Close() })
			var packets net.PacketConn = pc
			if masked {
				packets, err = morph.WrapPacketConn(pc, morph.Derive([]byte(key)), true)
				if err != nil {
					return nil, err
				}
			}
			addr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, packets, addr, tlsConfig, &quic.Config{EnableDatagrams: true, Versions: []quic.Version{quic.Version1}, DisablePathMTUDiscovery: masked, InitialPacketSize: 1200})
			if err != nil {
				return nil, err
			}
			return nw3TestQUIC{conn}, nil
		}
	}
	client, err := vector.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func nw3Echo(t *testing.T, network string) wire.Target {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			data := make([]byte, 65535)
			for {
				n, addr, e := pc.ReadFrom(data)
				if e != nil {
					return
				}
				_, _ = pc.WriteTo(data[:n], addr)
			}
		}()
		return nw3Target(t, pc.LocalAddr().String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return nw3Target(t, ln.Addr().String())
}

func nw3Target(t *testing.T, address string) wire.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr(host), uint16(p))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestNW3TLSClientOfferingSessionTickets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	cert := runtimeCertificate(t)
	server := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
	node := &model.NodeSpec{Protocol: "nw3", ServerPort: port, Network: "tcp",
		NetworkSettings: map[string]any{"morph": false}, TLS: 1,
		CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.1/32"}}, Action: model.RouteAction{Type: "direct"}}}}
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
	if err := server.Start(node, users, cert); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert.CertPEM) {
		t.Fatal("failed to trust test certificate")
	}
	dialer := tls.Dialer{Config: &tls.Config{
		ServerName: "localhost", RootCAs: roots, NextProtos: []string{wire.ALPN},
		MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(2),
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	state := conn.(*tls.Conn).ConnectionState()
	if state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 || state.DidResume {
		t.Fatalf("unexpected TLS connection: ALPN=%q version=%#x resumed=%v",
			state.NegotiatedProtocol, state.Version, state.DidResume)
	}
	exp, err := state.ExportKeyingMaterial(wire.ExporterLabel, nil, wire.ExporterLen)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nw3.SharedKey(users[0].UUID)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := wire.NewCredentials(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteAuthFrame(conn, credentials, wire.RoleVector, wire.AuthTLS, wire.Exporter(exp)); err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFlowRequest(conn, wire.FlowTCP, nw3Echo(t, "tcp")); err != nil {
		t.Fatal(err)
	}
	if result, err := wire.ReadSetupResult(conn); err != nil || result != wire.SetupReady {
		t.Fatalf("NW3 setup with ticket-capable client: %v, %v", result, err)
	}
}

func TestNW3MultiUserInteropAndTraffic(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, masked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/morph=%t", transport, masked), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}, {ID: 2, UUID: "bbbbbbbb-1111-2222-3333-444444444444"}}
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := ln.Addr().(*net.TCPAddr).Port
				_ = ln.Close()
				node := &model.NodeSpec{Protocol: "nw3", ServerPort: port, Network: transport, NetworkSettings: map[string]any{"morph": masked}, TLS: 1,
					CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.1/32"}}, Action: model.RouteAction{Type: "direct"}}}}
				server := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
				if err := server.Start(node, users, runtimeCertificate(t)); err != nil {
					t.Fatal(err)
				}
				defer server.Stop()
				tcpTarget, udpTarget := nw3Echo(t, "tcp"), nw3Echo(t, "udp")
				var persistent net.Conn
				for _, user := range users {
					key, err := nw3.SharedKey(user.UUID)
					if err != nil {
						t.Fatal(err)
					}
					client := nw3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), key, transport, masked)
					stream, err := client.OpenTCP(ctx, tcpTarget)
					if err != nil {
						t.Fatalf("user %d TCP: %v", user.ID, err)
					}
					_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
					payload := []byte(strings.Repeat("x", user.ID*5))
					if _, err := stream.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("TCP echo: %q, %v", got, err)
					}
					if user.ID == 2 {
						persistent = stream
						defer persistent.Close()
					} else {
						_ = stream.Close()
					}
					packet, err := client.OpenUDP(ctx, udpTarget)
					if err != nil {
						t.Fatalf("user %d UDP: %v", user.ID, err)
					}
					_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
					payload = bytes.Repeat([]byte{byte(user.ID)}, 4096)
					if _, err := packet.Write(payload); err != nil {
						t.Fatal(err)
					}
					got = make([]byte, 65535)
					n, err := packet.Read(got)
					if err != nil || !bytes.Equal(got[:n], payload) {
						t.Fatalf("UDP echo: n=%d error=%v", n, err)
					}
					_ = packet.Close()
				}
				deadline := time.Now().Add(time.Second)
				for {
					traffic, _, _, err := server.GetUserTraffic(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if traffic[1] == [2]int64{4101, 4101} && traffic[2] == [2]int64{4106, 4106} {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("incorrect per-user payload accounting: %v", traffic)
					}
					time.Sleep(time.Millisecond)
				}
				if _, _, err := server.UpdateUsers(users[1:]); err != nil {
					t.Fatal(err)
				}
				removedKey, _ := nw3.SharedKey(users[0].UUID)
				removed := nw3Client(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), removedKey, transport, masked)
				deniedCtx, deniedCancel := context.WithTimeout(ctx, time.Second)
				if conn, err := removed.OpenTCP(deniedCtx, tcpTarget); err == nil {
					_ = conn.Close()
					deniedCancel()
					t.Fatal("removed user's key still authenticates")
				}
				deniedCancel()
				if _, err := persistent.Write([]byte("after")); err != nil {
					t.Fatalf("unrelated user's connection was interrupted: %v", err)
				}
				got := make([]byte, 5)
				if _, err := io.ReadFull(persistent, got); err != nil || string(got) != "after" {
					t.Fatalf("after update: %q %v", got, err)
				}
			})
		}
	}
}

func TestNW3ConnectionBoundAuthentication(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	server := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
	user := model.UserSpec{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}
	if err := server.Start(&model.NodeSpec{Protocol: "nw3", ServerPort: port, Network: "tcp", NetworkSettings: map[string]any{"morph": false}}, []model.UserSpec{user}, runtimeCertificate(t)); err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	dial := func(alpn []string) *tls.Conn {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: alpn})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		return conn
	}
	key, _ := nw3.SharedKey(user.UUID)
	credentials, _ := wire.NewCredentials(key)
	roleKey, _ := credentials.RoleKey(wire.RoleVector)
	frame := func(conn *tls.Conn, transport wire.AuthTransport) []byte {
		state := conn.ConnectionState()
		material, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, 32)
		if err != nil {
			t.Fatal(err)
		}
		var exporter wire.Exporter
		copy(exporter[:], material)
		tag, err := wire.EncodeAuthFrame(roleKey, transport, exporter)
		if err != nil {
			t.Fatal(err)
		}
		return tag[:]
	}
	original := dial([]string{wire.ALPN})
	defer original.Close()
	for _, kind := range []string{"replay", "wrong-transport", "invalid-target", "missing-alpn"} {
		t.Run(kind, func(t *testing.T) {
			alpn := []string{wire.ALPN}
			if kind == "missing-alpn" {
				alpn = nil
			}
			conn := dial(alpn)
			defer conn.Close()
			tag := frame(conn, wire.AuthTLS)
			if kind == "replay" {
				tag = frame(original, wire.AuthTLS)
			}
			if kind == "wrong-transport" {
				tag = frame(conn, wire.AuthQUIC)
			}
			// Invalid empty domain: authentication succeeds only in this case.
			_, _ = conn.Write(append(tag, 0, 3, 0, 0, 80))
			var result [1]byte
			n, err := conn.Read(result[:])
			if kind == "invalid-target" {
				if err != nil || n != 1 || wire.SetupResult(result[0]) != wire.SetupInvalidRequest {
					t.Fatalf("invalid target result: n=%d code=%d err=%v", n, result[0], err)
				}
			} else if n != 0 || err == nil {
				t.Fatal("invalid authentication produced a setup result")
			}
		})
	}
	traffic, _, _, err := server.GetUserTraffic(context.Background())
	if err != nil || len(traffic) != 0 {
		t.Fatalf("rejected requests were billed: %v %v", traffic, err)
	}
}
