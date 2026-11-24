package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/SUDOKU-ASCII/sudoku/pkg/crypto"
)

func TestSudokuCredentials(t *testing.T) {
	value := "aaaaaaaa-1111-2222-3333-444444444444"
	private, public, hash, err := Sudoku(value)
	if err != nil {
		t.Fatal(err)
	}
	p, err := crypto.RecoverPublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if crypto.EncodePoint(p) != public {
		t.Fatal("native client derives different public key")
	}
	b, _ := hex.DecodeString(private)
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:8]) != hash {
		t.Fatal("incorrect native user hash")
	}
	p2, u2, h2, err := Sudoku(strings.ToUpper(value))
	if err != nil || p2 != private || u2 != public || h2 != hash {
		t.Fatal("UUID normalization changes keys")
	}
	p3, u3, h3, err := Sudoku("bbbbbbbb-1111-2222-3333-444444444444")
	if err != nil || p3 == private || u3 == public || h3 == hash {
		t.Fatal("user key isolation failed")
	}
}
