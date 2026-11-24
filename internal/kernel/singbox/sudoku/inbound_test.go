package sudoku

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
)

func testInbound(t *testing.T, options Options) *Inbound {
	t.Helper()
	value, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "test", options)
	if err != nil {
		t.Fatal(err)
	}
	h := value.(*Inbound)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestSudokuAtomicUserUpdate(t *testing.T) {
	users := []User{{Name: "one", UUID: "aaaaaaaa-1111-2222-3333-444444444444"}, {Name: "two", UUID: "bbbbbbbb-1111-2222-3333-444444444444"}}
	h := testInbound(t, Options{Users: users})
	previous := h.users
	for _, invalid := range [][]User{{users[0], users[0]}, {{Name: "x", UUID: users[0].UUID}, {Name: "y", UUID: users[0].UUID}}, {{Name: "bad", UUID: "bad"}}, {{Name: "", UUID: users[0].UUID}}} {
		if err := h.UpdateUsers(invalid); err == nil {
			t.Fatal("invalid update accepted")
		}
		if h.users != previous {
			t.Fatal("failed update changed live credentials")
		}
	}
	if err := h.UpdateUsers(users[1:]); err != nil {
		t.Fatal(err)
	}
	if h.users.byName["two"] != previous.byName["two"] {
		t.Fatal("unchanged key/table rebuilt")
	}
	alias := users[1]
	alias.UUID = strings.ToUpper(alias.UUID)
	if err := h.UpdateUsers([]User{alias}); err != nil || h.users.byName["two"] != previous.byName["two"] {
		t.Fatalf("equivalent UUID replaced the identity: %v", err)
	}
	alias.Name = "duplicate"
	if err := h.UpdateUsers([]User{users[1], alias}); err == nil {
		t.Fatal("accepted equivalent UUID under a second name")
	}
	rotated := users[0]
	rotated.Name = "two"
	if err := h.UpdateUsers([]User{rotated}); err != nil || h.users.byName["two"] == previous.byName["two"] {
		t.Fatalf("changed UUID did not replace the identity: %v", err)
	}
	if err := h.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	if len(h.users.byName) != 0 {
		t.Fatal("empty whitelist did not revoke all users")
	}
	_ = h.Close()
	if err := h.UpdateUsers(users); err == nil {
		t.Fatal("updated closed inbound")
	}
}

func TestSudokuOptionsValidation(t *testing.T) {
	for _, options := range []Options{{AEAD: "none"}, {AEAD: "bad"}, {ASCII: "bad"}, {PaddingMin: -1}, {PaddingMin: 10, PaddingMax: 5}, {PaddingMax: 101}, {Network: "udp"}, {CustomTables: []string{"bad"}}} {
		value, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("test"), "test", options)
		if err == nil {
			_ = value.(*Inbound).Close()
			t.Fatalf("accepted invalid options %+v", options)
		}
	}
}

func BenchmarkSudokuUserTable(b *testing.B) {
	for _, size := range []int{100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			users := make([]User, size)
			for i := range users {
				users[i] = User{Name: fmt.Sprint(i), UUID: fmt.Sprintf("%08x-1111-2222-3333-444444444444", i+1)}
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				value, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("bench"), "bench", Options{Users: users})
				if err != nil {
					b.Fatal(err)
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				runtime.KeepAlive(value)
				if after.HeapAlloc > before.HeapAlloc {
					b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(size), "retained-B/user")
				}
				_ = value.(*Inbound).Close()
			}
		})
	}
}

func BenchmarkSudokuUserRotation1895(b *testing.B) {
	users := make([]User, 1895)
	for i := range users {
		users[i] = User{Name: fmt.Sprint(i), UUID: fmt.Sprintf("%08x-1111-2222-3333-444444444444", i+1)}
	}
	rotated := append([]User(nil), users...)
	for i := len(users) - 95; i < len(users); i++ {
		rotated[i].UUID = fmt.Sprintf("%08x-1111-2222-3333-444444444444", i+1+len(users))
	}
	value, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("bench"), "bench", Options{Users: users})
	if err != nil {
		b.Fatal(err)
	}
	h := value.(*Inbound)
	b.Cleanup(func() { _ = h.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		next := rotated
		if i%2 != 0 {
			next = users
		}
		if err := h.UpdateUsers(next); err != nil {
			b.Fatal(err)
		}
	}
}
