// Copyright (c) 2024 The BitFS developers
// Use of this source code is governed by the Open BSV License v5
// that can be found in the LICENSE file.

// Package config provides configuration management for BitFS.
// Configuration uses a simple key=value file format with # comments.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Config holds the BitFS configuration.
type Config struct {
	// DataDir is the root data directory for BitFS.
	// Default: ~/.bitfs
	DataDir string

	// ListenAddr is the address for the daemon HTTP server.
	// Default: :8080
	ListenAddr string

	// Network is the BSV network: "mainnet" or "testnet".
	// Default: mainnet
	Network string

	// LogLevel controls the logging verbosity.
	// Valid values: "debug", "info", "warn", "error".
	// Default: info
	LogLevel string

	// LogFile is the path to the log file. Empty means stdout.
	// Default: "" (stdout)
	LogFile string
}

// DefaultDataDir returns the default data directory path.
// Priority:
//  1. BITFS_DATADIR env override
//  2. BITFS_NETWORK-aware default (mainnet/testnet/regtest)
//  3. mainnet default when network is empty/unknown
func DefaultDataDir() string {
	if v := strings.TrimSpace(os.Getenv("BITFS_DATADIR")); v != "" {
		return v
	}
	return DefaultDataDirForNetwork(os.Getenv("BITFS_NETWORK"))
}

// DefaultDataDirForNetwork returns the default data directory path for the
// given network.
//   - mainnet -> ~/.bitfs
//   - testnet -> ~/.bitfs-testnet
//   - regtest -> ~/.bitfs-regtest
func DefaultDataDirForNetwork(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	dirName := ".bitfs"
	switch network {
	case "testnet":
		dirName = ".bitfs-testnet"
	case "regtest":
		dirName = ".bitfs-regtest"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return dirName
	}
	return filepath.Join(home, dirName)
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		DataDir: DefaultDataDir(),
		// Bind to loopback by default (ConceptDesign #21): the daemon serves
		// localhost only unless the operator explicitly opts into exposure.
		ListenAddr: "127.0.0.1:8080",
		Network:    "mainnet",
		LogLevel:   "info",
		LogFile:    "",
	}
}

// LoadConfig reads a configuration file at the given path and returns
// a Config. The file uses simple key=value format (one per line) with
// # comments and blank lines ignored.
//
// Any keys not present in the file retain their default values.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, ErrConfigNotFound
		}
		return Config{}, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	cfg := DefaultConfig()
	if err := parseConfig(f, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseConfig reads key=value pairs from r into cfg.
func parseConfig(r io.Reader, cfg *Config) error {
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := parseKeyValue(line)
		if !ok {
			return fmt.Errorf("%w: line %d: %q", ErrInvalidConfigLine, lineNum, line)
		}

		setConfigField(cfg, key, value)
	}
	return scanner.Err()
}

// parseKeyValue splits a "key=value" or "key = value" line.
func parseKeyValue(line string) (key, value string, ok bool) {
	idx := strings.IndexByte(line, '=')
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// setConfigField assigns value to the Config field identified by key.
func setConfigField(cfg *Config, key, value string) {
	switch key {
	case "datadir":
		cfg.DataDir = value
	case "listen":
		cfg.ListenAddr = value
	case "network":
		cfg.Network = value
	case "loglevel":
		cfg.LogLevel = value
	case "logfile":
		cfg.LogFile = value
	default:
		// Unknown keys are silently ignored for forward compatibility.
	}
}

// SaveConfig writes the configuration to the given path in key=value format.
// Uses atomic write-to-tmp-then-rename to prevent partial writes from corrupting
// the config file if the process is interrupted. [Audit fix L-6]
func SaveConfig(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("config: create directory %s: %w", dir, err)
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("config: create %s: %w", tmp, err)
	}

	w := bufio.NewWriter(f)
	writeConfigFile(w, cfg)
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("config: flush %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("config: rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// writeConfigFile writes a human-readable config file to w.
func writeConfigFile(w *bufio.Writer, cfg Config) {
	_, _ = fmt.Fprintln(w, "# BitFS Configuration")
	_, _ = fmt.Fprintln(w, "# Generated by bitfs")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "datadir = %s\n", cfg.DataDir)
	_, _ = fmt.Fprintf(w, "listen = %s\n", cfg.ListenAddr)
	_, _ = fmt.Fprintf(w, "network = %s\n", cfg.Network)
	_, _ = fmt.Fprintf(w, "loglevel = %s\n", cfg.LogLevel)
	_, _ = fmt.Fprintf(w, "logfile = %s\n", cfg.LogFile)
}

// ConfigPath returns the path to the config file within the data directory.
func ConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "config")
}
