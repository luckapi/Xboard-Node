package singbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	api "github.com/SUDOKU-ASCII/sudoku/apis"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/kernel/singbox/sudoku"
	"github.com/cedar2025/xboard-node/internal/model"
)

var sudokuUsers = []model.UserSpec{{ID: 1, UUID: "aaaaaaaa-1111-2222-3333-444444444444"}, {ID: 2, UUID: "bbbbbbbb-1111-2222-3333-444444444444"}}

func sudokuEcho(t *testing.T, network string) string {
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
				n, addr, err := pc.ReadFrom(data)
				if err != nil {
					return
				}
				_, _ = pc.WriteTo(data[:n], addr)
			}
		}()
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func sudokuServer(t *testing.T, settings map[string]any) (*SingBox, string, *model.NodeSpec) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	node := &model.NodeSpec{Protocol: "sudoku", ServerPort: port, Network: "tcp", NetworkSettings: settings, CustomRouteRules: []model.CustomRouteRule{{Match: model.RouteMatch{IPCIDRs: []string{"127.0.0.1/32"}}, Action: model.RouteAction{Type: "direct"}}}}
	s := New(config.KernelConfig{LogLevel: "error", ConfigDir: t.TempDir()})
	if err := s.Start(node, sudokuUsers, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop() })
	return s, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), node
}

func sudokuRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo %q: %v", got, err)
	}
}

func TestSudokuNativeInteropAndAccounting(t *testing.T) {
	for _, aead := range []string{"chacha20-poly1305", "aes-128-gcm"} {
		for _, ascii := range []string{"prefer_entropy", "up_ascii_down_entropy"} {
			for _, pure := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/pure=%t", aead, ascii, pure), func(t *testing.T) {
					server, address, _ := sudokuServer(t, map[string]any{"aead": aead, "ascii": ascii, "enable_pure_downlink": pure, "padding_min": 1, "padding_max": 3})
					tcp, udp := sudokuEcho(t, "tcp"), sudokuEcho(t, "udp")
					for _, user := range sudokuUsers {
						credential, key, err := sudoku.ClientCredential(user.UUID, sudoku.Options{AEAD: aead, ASCII: ascii, PureDownlink: pure, PaddingMin: 1, PaddingMax: 3})
						if err != nil {
							t.Fatal(err)
						}
						dialer := credential.Dialer(address, key)
						conn, err := dialer.Dial(tcp)
						if err != nil {
							t.Fatal(err)
						}
						sudokuRoundTrip(t, conn, []byte("direct"))
						_ = conn.Close()
						base, err := dialer.DialBase()
						if err != nil {
							t.Fatal(err)
						}
						_ = base.SetDeadline(time.Now().Add(5 * time.Second))
						if err := api.WriteMessage(base, api.StartMux, nil); err != nil {
							t.Fatal(err)
						}
						mux, err := api.NewMuxClient(base)
						if err != nil {
							t.Fatal(err)
						}
						for i := 0; i < 2; i++ {
							stream, err := mux.Dial(tcp)
							if err != nil {
								t.Fatal(err)
							}
							sudokuRoundTrip(t, stream, []byte("mux"))
							_ = stream.Close()
						}
						_ = mux.Close()
						packet, err := dialer.DialUDPOverTCP()
						if err != nil {
							t.Fatal(err)
						}
						_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
						payload := bytes.Repeat([]byte{byte(user.ID)}, 4096)
						if err := api.WriteDatagram(packet, udp, payload); err != nil {
							t.Fatal(err)
						}
						target, got, err := api.ReadDatagram(packet)
						if err != nil || target != udp || !bytes.Equal(got, payload) {
							t.Fatalf("UoT echo %s %d: %v", target, len(got), err)
						}
						_ = packet.Close()
					}
					deadline := time.Now().Add(time.Second)
					for {
						traffic, _, _, err := server.GetUserTraffic(context.Background())
						if err != nil {
							t.Fatal(err)
						}
						if traffic[1] == [2]int64{4108, 4108} && traffic[2] == [2]int64{4108, 4108} {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("incorrect payload accounting %v", traffic)
						}
						time.Sleep(time.Millisecond)
					}
				})
			}
		}
	}
}

func TestSudokuHotUpdateAndIsolation(t *testing.T) {
	server, address, _ := sudokuServer(t, nil)
	target := sudokuEcho(t, "tcp")
	first, key1, err := sudoku.ClientCredential(sudokuUsers[0].UUID, sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	second, key2, err := sudoku.ClientCredential(sudokuUsers[1].UUID, sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := first.Dialer(address, key1).Dial(target)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := second.Dialer(address, key2).Dial(target)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	sudokuRoundTrip(t, c1, []byte("one"))
	sudokuRoundTrip(t, c2, []byte("two"))
	splitKey1 := append(bytes.Clone(key1), make([]byte, 32)...)
	split, err := first.Dialer(address, splitKey1).Dial(target)
	if err != nil {
		t.Fatal(err)
	}
	defer split.Close()
	sudokuRoundTrip(t, split, []byte("ios"))
	// Knowing one user's key must not authorize another user's hash.
	spoof, err := first.Dialer(address, key2).Dial(target)
	if err == nil {
		defer spoof.Close()
		_ = spoof.SetDeadline(time.Now().Add(time.Second))
		_, _ = spoof.Write([]byte("bad"))
		var b [3]byte
		if _, err := io.ReadFull(spoof, b[:]); err == nil {
			t.Fatal("spoofed hash accepted")
		}
	}
	traffic, _, _, err := server.GetUserTraffic(context.Background())
	if err != nil || traffic[1] != [2]int64{6, 6} || traffic[2] != [2]int64{3, 3} {
		t.Fatalf("rejected identity was billed: %v %v", traffic, err)
	}
	unknown, key3, err := sudoku.ClientCredential("cccccccc-1111-2222-3333-444444444444", sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := unknown.Dialer(address, key3).DialBase(); err == nil {
		_ = conn.Close()
		t.Fatal("unknown key completed handshake")
	}
	tracker := server.connTracker
	if _, _, err := server.UpdateUsers(sudokuUsers[1:]); err != nil {
		t.Fatal(err)
	}
	if server.connTracker != tracker {
		t.Fatal("tracker replaced during user update")
	}
	_ = c1.SetDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := c1.Read(b[:]); err == nil {
		t.Fatal("removed user's existing session survived")
	}
	sudokuRoundTrip(t, c2, []byte("live"))
	if _, _, err := server.UpdateUsers(sudokuUsers); err != nil {
		t.Fatal(err)
	}
	c3, err := first.Dialer(address, key1).Dial(target)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	sudokuRoundTrip(t, c3, []byte("back"))
}

func TestSudokuSniffedDomainBlocking(t *testing.T) {
	server, address, node := sudokuServer(t, nil)
	next := *node
	next.CustomRouteRules = append([]model.CustomRouteRule{{Match: model.RouteMatch{Domains: []string{"blocked.example"}}, Action: model.RouteAction{Type: "block"}}}, node.CustomRouteRules...)
	if err := server.Reload(&next, sudokuUsers, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	target := sudokuEcho(t, "tcp")
	credential, key, err := sudoku.ClientCredential(sudokuUsers[0].UUID, sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dialer := credential.Dialer(address, key)
	for _, muxed := range []bool{false, true} {
		var conn net.Conn
		if muxed {
			base, err := dialer.DialBase()
			if err != nil {
				t.Fatal(err)
			}
			if err := api.WriteMessage(base, api.StartMux, nil); err != nil {
				t.Fatal(err)
			}
			mux, err := api.NewMuxClient(base)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			conn, err = mux.Dial(target)
			if err != nil {
				t.Fatal(err)
			}
			// Bound the test using the transport; the native client mux has no deadlines.
			_ = base.SetDeadline(time.Now().Add(5 * time.Second))
		} else {
			conn, err = dialer.Dial(target)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write(payload); err == nil {
			var b [1]byte
			if _, err := conn.Read(b[:]); err == nil {
				t.Fatalf("sniffed domain block bypassed (mux=%t)", muxed)
			}
		}
	}
	traffic, _, _, err := server.GetUserTraffic(context.Background())
	if err != nil || traffic[1] != [2]int64{} {
		t.Fatalf("blocked request was billed: %v %v", traffic, err)
	}
}

func TestSudokuUoTDestinationRules(t *testing.T) {
	server, address, node := sudokuServer(t, nil)
	denied, allowed := sudokuEcho(t, "udp"), sudokuEcho(t, "udp")
	_, port, _ := net.SplitHostPort(denied)
	next := *node
	next.CustomRouteRules = append([]model.CustomRouteRule{{Match: model.RouteMatch{Ports: []string{port}}, Action: model.RouteAction{Type: "block"}}}, node.CustomRouteRules...)
	if err := server.Reload(&next, sudokuUsers, kernel.TLSCert{}); err != nil {
		t.Fatal(err)
	}
	credential, key, err := sudoku.ClientCredential(sudokuUsers[0].UUID, sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := credential.Dialer(address, key).DialUDPOverTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := api.WriteDatagram(conn, denied, []byte("denied")); err != nil {
		t.Fatal(err)
	}
	if err := api.WriteDatagram(conn, allowed, []byte("allowed")); err != nil {
		t.Fatal(err)
	}
	target, got, err := api.ReadDatagram(conn)
	if err != nil || target != allowed || string(got) != "allowed" {
		t.Fatalf("per-destination UDP routing failed: %s %q %v", target, got, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		traffic, _, _, err := server.GetUserTraffic(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if traffic[1] == [2]int64{7, 7} {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP denied traffic was billed: %v", traffic)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSudokuFailedRestartPreservesAccounting(t *testing.T) {
	server, address, _ := sudokuServer(t, nil)
	credential, key, err := sudoku.ClientCredential(sudokuUsers[0].UUID, sudoku.Options{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := credential.Dialer(address, key).Dial(sudokuEcho(t, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sudokuRoundTrip(t, conn, []byte("before"))
	oldBox, oldTracker := server.box, server.connTracker
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	next := &model.NodeSpec{Protocol: "sudoku", ServerPort: occupied.Addr().(*net.TCPAddr).Port}
	if err := server.Start(next, sudokuUsers[:1], kernel.TLSCert{}); err == nil {
		t.Fatal("restart on occupied port unexpectedly succeeded")
	}
	if server.box != oldBox || server.connTracker != oldTracker || len(server.users) != 2 {
		t.Fatal("failed restart replaced working state")
	}
	sudokuRoundTrip(t, conn, []byte("after"))
	traffic, _, _, err := server.GetUserTraffic(context.Background())
	if err != nil || traffic[1] != [2]int64{11, 11} {
		t.Fatalf("failed restart lost accounting: %v %v", traffic, err)
	}
}
