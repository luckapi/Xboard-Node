//go:build with_quic

package nw3

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20"
)

const morphLimit = uint64(1) << 38

func xorAt(dst, source []byte, key *[32]byte, nonce []byte, offset uint64) error {
	if offset > morphLimit || uint64(len(source)) > morphLimit-offset {
		return fmt.Errorf("NW3 Morph keystream exhausted")
	}
	if len(source) == 0 {
		return nil
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		return err
	}
	cipher.SetCounter(uint32(offset / 64))
	if skip := offset % 64; skip != 0 {
		var padding [64]byte
		cipher.XORKeyStream(padding[:skip], padding[:skip])
	}
	cipher.XORKeyStream(dst, source)
	return nil
}

type maskedTCP struct {
	net.Conn
	nonce                   [12]byte
	readKey, writeKey       [32]byte
	readOffset, writeOffset uint64
	readMu, writeMu         sync.Mutex
	prefix                  []byte
}

func (c *maskedTCP) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var n int
	var err error
	if len(c.prefix) > 0 {
		n = copy(p, c.prefix)
		c.prefix = c.prefix[n:]
	} else {
		n, err = c.Conn.Read(p)
	}
	if e := xorAt(p[:n], p[:n], &c.readKey, c.nonce[:], c.readOffset); e != nil {
		return 0, e
	}
	c.readOffset += uint64(n)
	return n, err
}

func (c *maskedTCP) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	encoded := make([]byte, len(p))
	if err := xorAt(encoded, p, &c.writeKey, c.nonce[:], c.writeOffset); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(encoded)
	c.writeOffset += uint64(n)
	return n, err
}

// Morph masks, but does not authenticate, the wire image. The selected key is
// always verified again against the connection-bound TLS exporter tag.
func (h *Inbound) unwrapTCP(raw net.Conn) (net.Conn, *identity, error) {
	var bootstrap [76]byte
	if _, err := io.ReadFull(raw, bootstrap[:]); err != nil {
		return nil, nil, err
	}
	var encrypted []byte
	ensure := func(n int) error {
		if len(encrypted) >= n {
			return nil
		}
		start := len(encrypted)
		encrypted = append(encrypted, make([]byte, n-start)...)
		_, err := io.ReadFull(raw, encrypted[start:])
		return err
	}
	for _, user := range h.users.Load().list {
		var hello [6]byte
		collected, offset := 0, 0
		for records := 0; records < 64 && collected < len(hello); records++ {
			if err := ensure(offset + 5); err != nil {
				return nil, nil, err
			}
			var header [5]byte
			if xorAt(header[:], encrypted[offset:offset+5], &user.keys.TCPC2S, bootstrap[64:76], uint64(offset)) != nil {
				break
			}
			length := int(binary.BigEndian.Uint16(header[3:5]))
			if header[0] != 22 || header[1] != 3 || (header[2] != 1 && header[2] != 3) || length > 18432 {
				break
			}
			size := min(length, len(hello)-collected)
			if err := ensure(offset + 5 + size); err != nil {
				return nil, nil, err
			}
			if xorAt(hello[collected:collected+size], encrypted[offset+5:offset+5+size], &user.keys.TCPC2S, bootstrap[64:76], uint64(offset+5)) != nil {
				break
			}
			collected += size
			offset += 5 + length
		}
		bodyLength := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if collected != len(hello) || hello[0] != 1 || bodyLength < 34 || bodyLength > 65536 || hello[4] != 3 || hello[5] != 3 {
			continue
		}
		conn := &maskedTCP{Conn: raw, readKey: user.keys.TCPC2S, writeKey: user.keys.TCPS2C, prefix: append([]byte(nil), encrypted...)}
		copy(conn.nonce[:], bootstrap[64:76])
		return conn, user, nil
	}
	return nil, nil, fmt.Errorf("unrecognized NW3 Morph key")
}

func maskDatagram(payload []byte, key *[32]byte) ([]byte, error) {
	encoded := make([]byte, 12+len(payload))
	if _, err := rand.Read(encoded[:12]); err != nil {
		return nil, err
	}
	if err := xorAt(encoded[12:], payload, key, encoded[:12], 0); err != nil {
		return nil, err
	}
	return encoded, nil
}
