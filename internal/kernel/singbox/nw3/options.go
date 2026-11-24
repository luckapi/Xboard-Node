package nw3

import (
	"strings"

	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing-box/option"
)

const Type = "nw3"

type User struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Options struct {
	option.ListenOptions
	Users   []User                    `json:"users"`
	TLS     *option.InboundTLSOptions `json:"tls"`
	Morph   *bool                     `json:"morph,omitempty"`
	Network string                    `json:"network,omitempty"`
}

func SharedKey(uuid string) (string, error) {
	key := strings.ToLower(strings.ReplaceAll(uuid, "-", ""))
	return key, wire.ValidateServiceKey(key)
}
