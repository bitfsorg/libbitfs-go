package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bitfsorg/libbitfs-go/config"
	"github.com/bitfsorg/libbitfs-go/wallet"
)

// Engine provides wallet-state mutation operations with process-level locking.
type Engine struct {
	dataDir  string
	password string
}

// New creates a new engine instance.
func New(dataDir, password string) *Engine {
	return &Engine{
		dataDir:  dataDir,
		password: password,
	}
}

// withState runs fn under a shared or exclusive file lock.
// For exclusive mode, updated state is persisted after fn returns nil.
func (e *Engine) withState(exclusive bool, fn func(w *wallet.Wallet, state *wallet.WalletState) error) error {
	return e.withLock(exclusive, func() error {
		w, state, err := e.loadWalletAndState()
		if err != nil {
			return err
		}
		if err := fn(w, state); err != nil {
			return err
		}
		if exclusive {
			if err := e.saveWalletState(state); err != nil {
				return err
			}
		}
		return nil
	})
}

func (e *Engine) withLock(exclusive bool, fn func() error) error {
	lockPath := filepath.Join(e.dataDir, "vault.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("engine: open lock file: %w", err)
	}
	defer func() { _ = lockFile.Close() }()

	lockMode := syscall.LOCK_SH
	if exclusive {
		lockMode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lockFile.Fd()), lockMode); err != nil {
		return fmt.Errorf("engine: lock file: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	return fn()
}

func (e *Engine) loadWalletAndState() (*wallet.Wallet, *wallet.WalletState, error) {
	if e.password == "" {
		return nil, nil, fmt.Errorf("engine: wallet password is required")
	}

	encrypted, err := os.ReadFile(filepath.Join(e.dataDir, "wallet.enc"))
	if err != nil {
		return nil, nil, fmt.Errorf("engine: read wallet: %w", err)
	}
	seed, err := wallet.DecryptSeed(encrypted, e.password)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: decrypt wallet: %w", err)
	}

	netCfg := &wallet.MainNet
	if cfg, cfgErr := config.LoadConfig(config.ConfigPath(e.dataDir)); cfgErr == nil {
		if resolved, netErr := wallet.GetNetwork(cfg.Network); netErr == nil {
			netCfg = resolved
		}
	}

	w, err := wallet.NewWallet(seed, netCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: create wallet: %w", err)
	}

	statePath := filepath.Join(e.dataDir, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: read wallet state: %w", err)
	}
	var state wallet.WalletState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, nil, fmt.Errorf("engine: parse wallet state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return nil, nil, fmt.Errorf("engine: invalid wallet state: %w", err)
	}
	return w, &state, nil
}

func (e *Engine) saveWalletState(state *wallet.WalletState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("engine: marshal wallet state: %w", err)
	}
	statePath := filepath.Join(e.dataDir, "state.json")
	// Atomic write via tmp+rename to prevent corruption on crash. [Audit fix M]
	tmpPath := statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("engine: write tmp state: %w", err)
	}
	if err := os.Rename(tmpPath, statePath); err != nil {
		return fmt.Errorf("engine: rename state: %w", err)
	}
	return nil
}
