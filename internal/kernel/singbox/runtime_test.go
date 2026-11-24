//go:build with_quic && with_utls

package singbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	mieruProtocol "github.com/sagernet/sing-box/protocol/mieru"
	singJSON "github.com/sagernet/sing/common/json"
	singM "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestMieruNewUserCanConnectAfterRefresh(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}, {ID: 2, UUID: "bbbbbbbb-1111-2222-3333-444444444444"}}
	node := &model.NodeSpec{Protocol: "mieru", ServerPort: port, Transport: "TCP", CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.1/32"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
	if err := s.Start(node, users[:1], kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if _, _, err := s.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	router := service.FromContext[adapter.Router](s.ctx)
	outbound, err := mieruProtocol.NewOutbound(s.ctx, router, log.NewNOPFactory().NewLogger("test"), "test", option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(port)}, Transport: "TCP", UserName: users[1].UUID, Password: users[1].UUID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.(interface{ Close() error }).Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := nw3Echo(t, "tcp")
	conn, err := outbound.DialContext(ctx, "tcp", singM.ParseSocksaddr(target.HostPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var data [5]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil || string(data[:]) != "hello" {
		t.Fatalf("new Mieru user failed: %q %v", data, err)
	}
}

func TestRuntimeRuleSetReloadAndRollback(t *testing.T) {
	s := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
	if err := s.Start(&model.NodeSpec{Protocol: "socks", ServerPort: 0}, nil, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	options, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, []byte(`{"route":{"rules":[{"rule_set":["audit"],"action":"reject"}],"rule_set":[{"type":"inline","tag":"audit","rules":[{"domain":["blocked.example"]}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	router := service.FromContext[adapter.Router](s.ctx)
	if err := router.UpdateRules(options.Route.Rules, options.Route.RuleSet); err != nil {
		t.Fatal(err)
	}
	if _, ok := router.RuleSet("audit"); !ok {
		t.Fatal("missing reloaded rule set")
	}
	metadata := &adapter.InboundContext{Destination: singM.ParseSocksaddr("blocked.example:443")}
	if rules := router.Rules(); len(rules) != 1 || !rules[0].Match(metadata) {
		t.Fatal("reloaded rule does not match")
	}
	bad, err := singJSON.UnmarshalExtendedContext[option.Options](s.ctx, []byte(`{"route":{"rules":[{"rule_set":["missing"],"action":"reject"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := router.UpdateRules(bad.Route.Rules, nil); err == nil {
		t.Fatal("expected invalid rule-set reference to fail")
	}
	if _, ok := router.RuleSet("audit"); !ok {
		t.Fatal("failed update discarded active rule sets")
	}
	metadata.ResetRuleCache()
	if !router.Rules()[0].Match(metadata) {
		t.Fatal("failed update damaged active rules")
	}
}

func runtimeCertificate(t *testing.T) kernel.TLSCert {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return kernel.TLSCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
}

func TestRuntimeProtocolStartAndUserReload(t *testing.T) {
	cert := runtimeCertificate(t)
	for _, name := range []string{"vmess", "vless", "trojan", "shadowsocks", "ss2022", "hysteria", "hysteria2", "tuic", "anytls", "naive", "socks", "http", "mieru", "nw3", "sudoku"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			node := &model.NodeSpec{Protocol: name, ServerPort: port, TLS: 1, ServerName: "localhost", Cipher: "aes-128-gcm", UpMbps: 100, DownMbps: 100}
			if name == "hysteria2" {
				node.Protocol, node.Version = "hysteria", 2
			}
			if name == "ss2022" {
				node.Protocol, node.Cipher = "shadowsocks", "2022-blake3-aes-128-gcm"
				node.ServerKey = base64.StdEncoding.EncodeToString(make([]byte, 16))
			}
			if name == "mieru" {
				node.Transport = "TCP"
			}
			users := []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}}
			s := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
			if err := s.Start(node, users, cert); err != nil {
				t.Fatal(err)
			}
			defer s.Stop()
			tracker := s.connTrackerSafe()
			users = append(users, model.UserSpec{ID: 2, UUID: "bbbbbbbb-1111-2222-3333-444444444444"})
			if _, _, err := s.UpdateUsers(users); err != nil {
				t.Fatalf("add user: %v", err)
			}
			if _, _, err := s.UpdateUsers(users[:1]); err != nil {
				t.Fatalf("remove user: %v", err)
			}
			if err := s.Reload(node, users[:1], cert); err != nil {
				t.Fatalf("reload: %v", err)
			}
			if s.connTrackerSafe() != tracker {
				t.Fatal("hot update replaced traffic counters")
			}
		})
	}
}
