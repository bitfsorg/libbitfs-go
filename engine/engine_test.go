package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bitfsorg/libbitfs-go/wallet"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func setupEngineDataDir(t *testing.T) (string, string) {
	t.Helper()

	dataDir := t.TempDir()
	password := "testpass"

	seed, err := wallet.SeedFromMnemonic(testMnemonic, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic: %v", err)
	}
	encrypted, err := wallet.EncryptSeed(seed, password)
	if err != nil {
		t.Fatalf("EncryptSeed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "wallet.enc"), encrypted, 0600); err != nil {
		t.Fatalf("write wallet.enc: %v", err)
	}

	w, err := wallet.NewWallet(seed, &wallet.MainNet)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	state := wallet.NewWalletState()
	if _, err := w.CreateVault(state, "default"); err != nil {
		t.Fatalf("CreateVault default: %v", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.json"), data, 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	return dataDir, password
}

func TestEngine_PaymailFlow(t *testing.T) {
	dataDir, password := setupEngineDataDir(t)
	eng := New(dataDir, password)

	pubHex, err := eng.PaymailBind("alice", "default")
	if err != nil {
		t.Fatalf("PaymailBind: %v", err)
	}
	if len(pubHex) != 66 {
		t.Fatalf("pubkey hex len = %d, want 66", len(pubHex))
	}

	list, err := eng.PaymailList()
	if err != nil {
		t.Fatalf("PaymailList: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("PaymailList len = %d, want 1", len(list))
	}
	if list[0].Alias != "alice" || list[0].Vault != "default" {
		t.Fatalf("unexpected binding: %+v", list[0])
	}

	vaultName, err := eng.PaymailUnbind("alice")
	if err != nil {
		t.Fatalf("PaymailUnbind: %v", err)
	}
	if vaultName != "default" {
		t.Fatalf("PaymailUnbind vault = %q, want %q", vaultName, "default")
	}

	list, err = eng.PaymailList()
	if err != nil {
		t.Fatalf("PaymailList after unbind: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("PaymailList len after unbind = %d, want 0", len(list))
	}
}

func TestEngine_PaymailBindInvalidAlias(t *testing.T) {
	dataDir, password := setupEngineDataDir(t)
	eng := New(dataDir, password)

	_, err := eng.PaymailBind("Alice", "default")
	if !errors.Is(err, wallet.ErrInvalidAlias) {
		t.Fatalf("PaymailBind invalid alias error = %v, want ErrInvalidAlias", err)
	}
}

func TestEngine_VaultExport(t *testing.T) {
	dataDir, password := setupEngineDataDir(t)
	eng := New(dataDir, password)

	path, err := eng.VaultExport("default", "seed-path")
	if err != nil {
		t.Fatalf("VaultExport: %v", err)
	}
	if path == "" {
		t.Fatal("VaultExport returned empty path")
	}
}
