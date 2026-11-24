//go:build !with_quic

package nw3

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[Options](registry, Type, func(context.Context, adapter.Router, log.ContextLogger, string, Options) (adapter.Inbound, error) {
		return nil, fmt.Errorf("NW3 requires a build with -tags with_quic")
	})
}
