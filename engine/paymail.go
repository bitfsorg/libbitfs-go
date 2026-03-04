package engine

import (
	"encoding/hex"

	"github.com/bitfsorg/libbitfs-go/wallet"
)

// PaymailEntry represents one paymail binding with its resolved public key.
type PaymailEntry struct {
	Alias  string
	Vault  string
	Pubkey string
}

// PaymailBind binds alias -> vault and returns the vault root public key hex.
func (e *Engine) PaymailBind(alias, vaultName string) (string, error) {
	var pubHex string
	err := e.withState(true, func(w *wallet.Wallet, state *wallet.WalletState) error {
		if err := w.BindPaymail(state, alias, vaultName); err != nil {
			return err
		}
		v, err := w.GetVault(state, vaultName)
		if err != nil {
			return err
		}
		rootKey, err := w.DeriveVaultRootKey(v.AccountIndex)
		if err != nil {
			return err
		}
		pubHex = hex.EncodeToString(rootKey.PublicKey.Compressed())
		return nil
	})
	return pubHex, err
}

// PaymailUnbind removes alias binding and returns the previously bound vault name.
func (e *Engine) PaymailUnbind(alias string) (string, error) {
	var vaultName string
	err := e.withState(true, func(w *wallet.Wallet, state *wallet.WalletState) error {
		v, err := w.ResolvePaymailAlias(state, alias)
		if err != nil {
			return err
		}
		vaultName = v
		return w.UnbindPaymail(state, alias)
	})
	return vaultName, err
}

// PaymailList returns all paymail bindings with derived root public keys.
func (e *Engine) PaymailList() ([]PaymailEntry, error) {
	var entries []PaymailEntry
	err := e.withState(false, func(w *wallet.Wallet, state *wallet.WalletState) error {
		bindings := w.ListPaymailBindings(state)
		if len(bindings) == 0 {
			return nil
		}
		entries = make([]PaymailEntry, 0, len(bindings))
		for _, b := range bindings {
			pubHex := "(error)"
			v, err := w.GetVault(state, b.Vault)
			if err == nil {
				rootKey, err := w.DeriveVaultRootKey(v.AccountIndex)
				if err == nil {
					pubHex = hex.EncodeToString(rootKey.PublicKey.Compressed())
				}
			}
			entries = append(entries, PaymailEntry{
				Alias:  b.Alias,
				Vault:  b.Vault,
				Pubkey: pubHex,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
