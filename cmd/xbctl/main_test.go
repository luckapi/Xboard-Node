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

func TestConfigInitDefaultAndExistingBlockList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	args := []string{"--mode", "node", "--panel-url", "https://panel.example.com", "--node-id", "1", "--config", path, "--install-root", dir}
	if err := runConfigInit(args); err != nil {
		t.Fatal(err)
	}
	root, err := loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	audit := &root.Instances[0].Kernel.BlockList
	if audit.URL != "" || audit.Path != filepath.Join(dir, "blockList") || !audit.EffectiveEnabled() {
		t.Fatalf("unexpected audit defaults: %+v", audit)
	}
	if _, err := os.Stat(audit.Path); !os.IsNotExist(err) {
		t.Fatalf("config init should leave rule installation to the installer: %v", err)
	}
	disabled := false
	*audit = config.BlockListConfig{Enabled: &disabled, URL: "https://example.com/custom"}
	if err := writeRootConfig(path, root); err != nil {
		t.Fatal(err)
	}
	if err := runConfigInit(args); err != nil {
		t.Fatal(err)
	}
	root, err = loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got := root.Instances[0].Kernel.BlockList
	if got.EffectiveEnabled() || got.URL != "https://example.com/custom" {
		t.Fatalf("existing audit configuration overwritten: %+v", got)
	}
	const remote = "https://example.com/remote"
	if err := runConfigInit(append(args, "--blocklist-url", remote)); err != nil {
		t.Fatal(err)
	}
	root, err = loadWritableRootConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got = root.Instances[0].Kernel.BlockList
	if !got.EffectiveEnabled() || got.URL != remote || got.Path != "" {
		t.Fatalf("explicit remote audit not enabled: %+v", got)
	}
}
