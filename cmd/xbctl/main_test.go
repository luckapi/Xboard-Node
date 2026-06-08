package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

func TestWriteRootConfigPreservesBlockList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	root := &config.RootConfig{
		Instances: []config.Config{
			{
				InstanceID: "test-node",
				Panel: config.PanelConfig{
					URL:      "https://panel.example.com",
					TokenEnv: "TEST_TOKEN",
					NodeID:   1,
				},
				Kernel: config.KernelConfig{
					Type:      "singbox",
					ConfigDir: "/etc/xboard-node/instances/test-node",
					LogLevel:  "warn",
					BlockList: config.BlockListConfig{
						Path: "/etc/xboard-node/blockList",
					},
				},
				Log: config.LogConfig{
					Level:  "info",
					Output: "stdout",
				},
			},
		},
	}

	if err := writeRootConfig(path, root); err != nil {
		t.Fatalf("writeRootConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "blocklist:") {
		t.Fatalf("expected blocklist stanza in config, got:\n%s", content)
	}
	if !strings.Contains(content, "path: /etc/xboard-node/blockList") {
		t.Fatalf("expected blocklist path in config, got:\n%s", content)
	}
}

func TestEnsureBlockListSeedCreatesSample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blockList")

	if err := ensureBlockListSeed(path); err != nil {
		t.Fatalf("ensureBlockListSeed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "# Node-side audit/blocklist") {
		t.Fatalf("expected seed header, got:\n%s", content)
	}
	if !strings.Contains(content, "# bbc.com") {
		t.Fatalf("expected sample domain, got:\n%s", content)
	}
}
