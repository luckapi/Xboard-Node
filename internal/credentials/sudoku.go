package credentials

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/google/uuid"
)

// Sudoku derives independent native keys from a secret panel UUID. Subscriptions
// must apply this exact, versioned mapping rather than distribute a master key.
func Sudoku(value string) (privateKey, publicKey, userHash string, err error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return "", "", "", fmt.Errorf("Sudoku requires a valid UUID: %w", err)
	}
	if id == uuid.Nil {
		return "", "", "", fmt.Errorf("Sudoku UUID must not be zero")
	}
	seed := sha512.Sum512(append([]byte("xboard-sudoku-user-v1\x00"), id[:]...))
	scalar, err := edwards25519.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		return "", "", "", err
	}
	private := scalar.Bytes()
	public := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	hash := sha256.Sum256(private)
	return hex.EncodeToString(private), hex.EncodeToString(public), hex.EncodeToString(hash[:8]), nil
}
