//go:build with_quic

package nw3

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func testIdentities() *Inbound {
	h := &Inbound{connections: make(chan struct{}, 1024), admission: make(chan struct{}, 256)}
	h.users.Store(&userTable{byName: make(map[string]*identity)})
	return h
}

func TestUserUpdateIsAtomicAndRevokesSessions(t *testing.T) {
	h := testIdentities()
	users := []User{{Name: "a", Key: "0123456789abcdef0123456789abcdef"}, {Name: "b", Key: "1123456789abcdef0123456789abcdef"}}
	if err := h.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	before := h.users.Load()
	if before.byName["a"].sessions != nil || before.byName["b"].sessions != nil {
		t.Fatal("idle users allocated session maps")
	}
	if err := h.UpdateUsers([]User{users[0], users[0]}); err == nil {
		t.Fatal("duplicate credentials accepted")
	}
	if h.users.Load() != before {
		t.Fatal("invalid update changed active users")
	}
	closed := false
	if !registerSession(before.byName["a"], 1, func() { closed = true }) {
		t.Fatal("session registration failed")
	}
	if len(before.byName["a"].sessions) != 1 || before.byName["b"].sessions != nil {
		t.Fatal("session state was not allocated only for the connected user")
	}
	if err := h.UpdateUsers(users[1:]); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("removed user's session stayed open")
	}
	if registerSession(before.byName["a"], 2, func() {}) {
		t.Fatal("revoked identity accepted a new session")
	}
	if h.users.Load().byName["b"] != before.byName["b"] {
		t.Fatal("unrelated user's state replaced")
	}
}

func TestConnectionAndAuthenticationAdmissionAreBounded(t *testing.T) {
	h := testIdentities()
	for i := 0; i < 1024; i++ {
		if !h.takeAuth() {
			t.Fatal("premature connection limit")
		}
		<-h.admission
	}
	if h.takeAuth() {
		t.Fatal("connection limit exceeded")
	}
	for i := 0; i < 1024; i++ {
		<-h.connections
	}
	for i := 0; i < 256; i++ {
		if !h.takeAuth() {
			t.Fatal("premature authentication limit")
		}
	}
	if h.takeAuth() {
		t.Fatal("authentication limit exceeded")
	}
	if len(h.connections) != 256 {
		t.Fatal("failed admission leaked a connection slot")
	}
}

type partialConn struct{ bytes.Buffer }

func (c *partialConn) Write(p []byte) (int, error) {
	n := min(3, len(p))
	_, _ = c.Buffer.Write(p[:n])
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
func (*partialConn) Close() error                     { return nil }
func (*partialConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*partialConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*partialConn) SetDeadline(time.Time) error      { return nil }
func (*partialConn) SetReadDeadline(time.Time) error  { return nil }
func (*partialConn) SetWriteDeadline(time.Time) error { return nil }

func TestMorphPartialWriteAdvancesOnlyWrittenBytes(t *testing.T) {
	base := new(partialConn)
	conn := &maskedTCP{Conn: base}
	data := []byte("abcdefghi")
	for offset := 0; offset < len(data); {
		n, _ := conn.Write(data[offset:])
		offset += n
	}
	expected := make([]byte, len(data))
	if err := xorAt(expected, data, &conn.writeKey, conn.nonce[:], 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base.Bytes(), expected) {
		t.Fatal("partial writes reused or skipped Morph keystream")
	}
	if err := xorAt(make([]byte, 1), []byte{0}, &conn.writeKey, conn.nonce[:], morphLimit); err == nil {
		t.Fatal("Morph counter wrap accepted")
	}
}

func TestMorphKeySelectionWithThousandsOfUsers(t *testing.T) {
	h := testIdentities()
	users := make([]User, 2233)
	for i := range users {
		users[i] = User{Name: fmt.Sprint(i), Key: fmt.Sprintf("%032x", i+1)}
	}
	if err := h.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	last := h.users.Load().list[len(users)-1]
	var bootstrap [87]byte
	hello := []byte{22, 3, 1, 0, 64, 1, 0, 0, 60, 3, 3}
	if err := xorAt(bootstrap[76:], hello, &last.keys.TCPC2S, bootstrap[64:76], 0); err != nil {
		t.Fatal(err)
	}
	base := new(partialConn)
	_, _ = base.Buffer.Write(bootstrap[:])
	_, selected, err := h.unwrapTCP(base)
	if err != nil || selected != last {
		t.Fatalf("key selection: %v", err)
	}
}

func TestMorphKeySelectionAcrossTLSRecords(t *testing.T) {
	h := testIdentities()
	if err := h.UpdateUsers([]User{{Name: "user", Key: "0123456789abcdef0123456789abcdef"}}); err != nil {
		t.Fatal(err)
	}
	user := h.users.Load().list[0]
	plain := []byte{22, 3, 1, 0, 2, 1, 0, 22, 3, 3, 0, 2, 0, 60, 22, 3, 3, 0, 2, 3, 3}
	encoded := make([]byte, len(plain))
	var nonce [12]byte
	if err := xorAt(encoded, plain, &user.keys.TCPC2S, nonce[:], 0); err != nil {
		t.Fatal(err)
	}
	base := new(partialConn)
	_, _ = base.Buffer.Write(make([]byte, 76))
	_, _ = base.Buffer.Write(encoded)
	conn, selected, err := h.unwrapTCP(base)
	if err != nil || selected != user {
		t.Fatalf("fragmented ClientHello key lookup failed: %v", err)
	}
	got := make([]byte, len(plain))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("TLS records were not replayed intact: %v", err)
	}
}
