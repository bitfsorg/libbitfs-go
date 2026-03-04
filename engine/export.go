package engine

import "github.com/bitfsorg/libbitfs-go/wallet"

// VaultExport exports the vault root key in the requested format.
func (e *Engine) VaultExport(vaultName, format string) (string, error) {
	var out string
	err := e.withState(false, func(w *wallet.Wallet, state *wallet.WalletState) error {
		result, err := w.ExportVaultKey(state, vaultName, format)
		if err != nil {
			return err
		}
		out = result
		return nil
	})
	return out, err
}
