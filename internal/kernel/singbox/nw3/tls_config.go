//go:build with_quic

package nw3

import (
	"crypto/tls"

	"github.com/ohmycggk/nowhere-go/wire"
)

func nw3TLSConfig(base *tls.Config) *tls.Config {
	config := cloneWithNW3TLSOptions(base)
	if selectConfig := config.GetConfigForClient; selectConfig != nil {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := selectConfig(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			// The callback can replace the entire config during the handshake.
			return cloneWithNW3TLSOptions(selected), nil
		}
	}
	return config
}

func cloneWithNW3TLSOptions(base *tls.Config) *tls.Config {
	config := base.Clone()
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.NextProtos = []string{wire.ALPN}
	config.SessionTicketsDisabled = true
	return config
}
