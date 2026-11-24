package sudoku

import (
	"github.com/cedar2025/xboard-node/internal/credentials"
	"github.com/sagernet/sing-box/option"
)

const Type = "sudoku"

type User struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type Options struct {
	option.ListenOptions
	Network      string   `json:"network,omitempty"`
	Users        []User   `json:"users"`
	AEAD         string   `json:"aead,omitempty"`
	ASCII        string   `json:"ascii,omitempty"`
	PaddingMin   int      `json:"padding_min,omitempty"`
	PaddingMax   int      `json:"padding_max,omitempty"`
	PureDownlink bool     `json:"enable_pure_downlink,omitempty"`
	CustomTables []string `json:"custom_tables,omitempty"`
}

// Credentials deterministically derives an independent, native Sudoku key pair.
// The UUID is a secret credential; this mapping must also be used by subscriptions.
func Credentials(value string) (privateKey, publicKey, userHash string, err error) {
	return credentials.Sudoku(value)
}
