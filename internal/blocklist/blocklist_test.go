package blocklist

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestLoadRulesParsesRakauStyleList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blockList")
	if err := os.WriteFile(path, []byte(`
# comment
falundafa
bbc.com
*.evil.example
10.0.0.0/8
bbc.com
`), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules(context.Background(), config.BlockListConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules: got %d, want 1", len(rules))
	}
	match := rules[0].Match
	if got, want := match.DomainKeywords, []string{"falundafa"}; !equalStrings(got, want) {
		t.Fatalf("domain keywords: got %v, want %v", got, want)
	}
	if got, want := match.DomainSuffixes, []string{"bbc.com", "evil.example"}; !equalStrings(got, want) {
		t.Fatalf("domain suffixes: got %v, want %v", got, want)
	}
	if got, want := match.IPCIDRs, []string{"10.0.0.0/8"}; !equalStrings(got, want) {
		t.Fatalf("ip cidrs: got %v, want %v", got, want)
	}
	if rules[0].Action.Type != "block" {
		t.Fatalf("action: got %q, want block", rules[0].Action.Type)
	}
}

func TestLoadRulesDisabled(t *testing.T) {
	disabled := false
	rules, err := LoadRules(context.Background(), config.BlockListConfig{
		Enabled: &disabled,
		Path:    "/does/not/matter",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules: got %d, want 0", len(rules))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
