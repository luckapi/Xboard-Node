//go:build ignore

// Prepare pinned upstream kernels with the node's compatibility patches.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

type kernel struct {
	Name    string `json:"name"`
	Module  string `json:"module"`
	Version string `json:"version"`
	Sum     string `json:"sum"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, "scripts/kernel-versions.json"))
	if err != nil {
		return err
	}
	var kernels []kernel
	if err := json.Unmarshal(data, &kernels); err != nil {
		return err
	}
	for _, k := range kernels {
		if err := prepare(root, k); err != nil {
			return fmt.Errorf("prepare %s: %w", k.Name, err)
		}
	}
	return nil
}

func prepare(root string, k kernel) error {
	patchPath := filepath.Join(root, "scripts/kernel-patches", k.Name+".patch")
	patchData, err := os.ReadFile(patchPath)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(append([]byte(k.Module+"@"+k.Version+"\n"+k.Sum+"\n"), patchData...))
	stamp := hex.EncodeToString(hash[:]) + "\n"
	dest := filepath.Join(root, "third_party", k.Name)
	marker := filepath.Join(dest, ".xboard-kernel")
	if old, err := os.ReadFile(marker); err == nil && string(old) == stamp {
		return nil
	}
	if _, err := os.Stat(dest); err == nil {
		if _, err := os.Stat(marker); err != nil {
			return fmt.Errorf("refusing to replace unmanaged directory %s", dest)
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dest), ".kernel-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// Run outside the host module so local replacements need not exist yet.
	download := exec.Command("go", "mod", "download", "-json", k.Module+"@"+k.Version)
	download.Dir = tmp
	download.Env = moduleEnv()
	output, err := download.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("download: %s", e.Stderr)
		}
		return err
	}
	var info struct {
		Dir   string
		Error string
		Sum   string
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return err
	}
	if info.Error != "" {
		return fmt.Errorf("download: %s", info.Error)
	}
	if k.Sum == "" || info.Sum != k.Sum {
		return fmt.Errorf("module checksum mismatch: got %q, expected %q", info.Sum, k.Sum)
	}
	if info.Dir == "" {
		return fmt.Errorf("module download returned no source directory")
	}
	if err := copyTree(info.Dir, tmp); err != nil {
		return err
	}
	patch := exec.Command("patch", "-p1", "-t", "-i", patchPath)
	patch.Dir = tmp
	patch.Stdout, patch.Stderr = os.Stdout, os.Stderr
	if err := patch.Run(); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, ".xboard-kernel"), []byte(stamp), 0644); err != nil {
		return err
	}
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	fmt.Printf("Prepared %s %s\n", k.Name, k.Version)
	return nil
}

func moduleEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if len(value) >= 12 && value[:12] == "GO111MODULE=" {
			continue
		}
		if len(value) >= 7 && value[:7] == "GOWORK=" {
			continue
		}
		env = append(env, value)
	}
	return append(env, "GO111MODULE=on", "GOWORK=off")
}

func copyTree(source, dest string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported module entry %s", path)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		info, err := entry.Info()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()|0200)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}
