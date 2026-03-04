package wallet

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

// Vault represents an independent Metanet directory tree.
// Each Vault = one BIP32 account = one independent Metanet tree.
type Vault struct {
	Name         string `json:"name"`
	AccountIndex uint32 `json:"account_index"` // BIP44 account (1-based for vaults)
	RootTxID     []byte `json:"root_txid"`     // Root node transaction ID (nil if unpublished)
	Deleted      bool   `json:"deleted"`       // Soft-deleted flag
}

// PaymailBinding maps a paymail alias to a vault (1:1 relationship).
type PaymailBinding struct {
	Alias string `json:"alias"`
	Vault string `json:"vault"`
}

// aliasPattern validates paymail alias format: lowercase alphanumeric, dots,
// hyphens, underscores. Must start with alphanumeric. Max 64 chars.
var aliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// isValidAlias checks whether the given alias matches the allowed format.
func isValidAlias(alias string) bool {
	return aliasPattern.MatchString(alias)
}

// WalletState holds persisted wallet metadata.
type WalletState struct {
	NextReceiveIndex uint32           `json:"next_receive_index"`         // Fee chain next receive address
	NextChangeIndex  uint32           `json:"next_change_index"`          // Fee chain next change address
	Vaults           []Vault          `json:"vaults"`
	NextVaultIndex   uint32           `json:"next_vault_index"`           // Next available vault account index
	PaymailBindings  []PaymailBinding `json:"paymail_bindings,omitempty"`
}

// NewWalletState creates a new empty WalletState.
func NewWalletState() *WalletState {
	return &WalletState{
		NextReceiveIndex: 0,
		NextChangeIndex:  0,
		Vaults:           []Vault{},
		NextVaultIndex:   0,
	}
}

// Validate checks the integrity of a deserialized WalletState.
func (ws *WalletState) Validate() error {
	seen := make(map[uint32]string)
	var maxIdx uint32

	for _, v := range ws.Vaults {
		if v.Deleted {
			continue
		}
		// Check account index within BIP32 range.
		if v.AccountIndex >= Hardened-DefaultVaultAccount {
			return fmt.Errorf("vault %q: account index %d exceeds BIP32 hardened boundary", v.Name, v.AccountIndex)
		}
		// Check for duplicate account indices among active vaults.
		if prev, ok := seen[v.AccountIndex]; ok {
			return fmt.Errorf("duplicate account index %d: vaults %q and %q", v.AccountIndex, prev, v.Name)
		}
		seen[v.AccountIndex] = v.Name

		if v.AccountIndex >= maxIdx {
			maxIdx = v.AccountIndex + 1
		}
	}

	// NextVaultIndex must be >= max seen index + 1 (to avoid reuse).
	if len(seen) > 0 && ws.NextVaultIndex < maxIdx {
		return fmt.Errorf("NextVaultIndex (%d) is less than max account index + 1 (%d)", ws.NextVaultIndex, maxIdx)
	}

	// Validate paymail bindings.
	activeVaults := make(map[string]bool)
	for _, v := range ws.Vaults {
		if !v.Deleted {
			activeVaults[v.Name] = true
		}
	}

	seenAliases := make(map[string]bool)
	seenBoundVaults := make(map[string]bool)
	for _, b := range ws.PaymailBindings {
		if !isValidAlias(b.Alias) {
			return fmt.Errorf("paymail binding: invalid alias format %q", b.Alias)
		}
		if seenAliases[b.Alias] {
			return fmt.Errorf("paymail binding: duplicate alias %q", b.Alias)
		}
		seenAliases[b.Alias] = true

		if seenBoundVaults[b.Vault] {
			return fmt.Errorf("paymail binding: vault %q bound more than once", b.Vault)
		}
		seenBoundVaults[b.Vault] = true

		if !activeVaults[b.Vault] {
			return fmt.Errorf("paymail binding: alias %q references non-existent vault %q", b.Alias, b.Vault)
		}
	}

	return nil
}

// CreateVault creates a new vault with the given name.
// Allocates the next available account index (0-based vault index,
// which maps to BIP44 account index = vaultIndex + 1).
func (w *Wallet) CreateVault(state *WalletState, name string) (*Vault, error) {
	// Guard: next vault index must stay below Hardened boundary.
	if state.NextVaultIndex >= Hardened-DefaultVaultAccount {
		return nil, fmt.Errorf("vault limit reached: account index would exceed BIP32 hardened boundary")
	}

	// Check for duplicate names
	for _, v := range state.Vaults {
		if v.Name == name && !v.Deleted {
			return nil, fmt.Errorf("%w: %q", ErrVaultExists, name)
		}
	}

	vault := Vault{
		Name:         name,
		AccountIndex: state.NextVaultIndex,
		RootTxID:     nil,
		Deleted:      false,
	}

	state.Vaults = append(state.Vaults, vault)
	state.NextVaultIndex++

	return &vault, nil
}

// GetVault retrieves a vault by name. Returns ErrVaultNotFound if not found.
func (w *Wallet) GetVault(state *WalletState, name string) (*Vault, error) {
	for i := range state.Vaults {
		if state.Vaults[i].Name == name && !state.Vaults[i].Deleted {
			return &state.Vaults[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrVaultNotFound, name)
}

// ListVaults returns all active (non-deleted) vaults.
func (w *Wallet) ListVaults(state *WalletState) []Vault {
	var active []Vault
	for _, v := range state.Vaults {
		if !v.Deleted {
			active = append(active, v)
		}
	}
	return active
}

// RenameVault renames an existing vault. Any paymail binding is also updated.
func (w *Wallet) RenameVault(state *WalletState, oldName, newName string) error {
	// Check new name doesn't conflict
	for _, v := range state.Vaults {
		if v.Name == newName && !v.Deleted {
			return fmt.Errorf("%w: %q", ErrVaultExists, newName)
		}
	}

	found := false
	for i := range state.Vaults {
		if state.Vaults[i].Name == oldName && !state.Vaults[i].Deleted {
			state.Vaults[i].Name = newName
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrVaultNotFound, oldName)
	}

	// Update paymail binding vault reference.
	for i := range state.PaymailBindings {
		if state.PaymailBindings[i].Vault == oldName {
			state.PaymailBindings[i].Vault = newName
			break
		}
	}

	return nil
}

// DeleteVault marks a vault as deleted (soft delete).
// The account index is not reused. Any paymail binding is also removed.
func (w *Wallet) DeleteVault(state *WalletState, name string) error {
	found := false
	for i := range state.Vaults {
		if state.Vaults[i].Name == name && !state.Vaults[i].Deleted {
			state.Vaults[i].Deleted = true
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrVaultNotFound, name)
	}

	// Remove paymail binding for the deleted vault.
	for i, b := range state.PaymailBindings {
		if b.Vault == name {
			state.PaymailBindings = append(state.PaymailBindings[:i], state.PaymailBindings[i+1:]...)
			break
		}
	}

	return nil
}

// BindPaymail creates a 1:1 mapping between a paymail alias and a vault.
func (w *Wallet) BindPaymail(state *WalletState, alias, vaultName string) error {
	if !isValidAlias(alias) {
		return fmt.Errorf("%w: %q", ErrInvalidAlias, alias)
	}

	// Verify vault exists.
	if _, err := w.GetVault(state, vaultName); err != nil {
		return err
	}

	// Check alias and vault uniqueness (1:1 constraint).
	for _, b := range state.PaymailBindings {
		if b.Alias == alias {
			return fmt.Errorf("%w: %q", ErrAliasExists, alias)
		}
		if b.Vault == vaultName {
			return fmt.Errorf("%w: %q", ErrVaultAlreadyBound, vaultName)
		}
	}

	state.PaymailBindings = append(state.PaymailBindings, PaymailBinding{
		Alias: alias,
		Vault: vaultName,
	})
	return nil
}

// UnbindPaymail removes a paymail alias binding.
func (w *Wallet) UnbindPaymail(state *WalletState, alias string) error {
	for i, b := range state.PaymailBindings {
		if b.Alias == alias {
			state.PaymailBindings = append(state.PaymailBindings[:i], state.PaymailBindings[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrAliasNotFound, alias)
}

// ListPaymailBindings returns all paymail bindings.
func (w *Wallet) ListPaymailBindings(state *WalletState) []PaymailBinding {
	if len(state.PaymailBindings) == 0 {
		return nil
	}
	// Return a copy to avoid mutation.
	out := make([]PaymailBinding, len(state.PaymailBindings))
	copy(out, state.PaymailBindings)
	return out
}

// ResolvePaymailAlias returns the vault name bound to the given alias.
func (w *Wallet) ResolvePaymailAlias(state *WalletState, alias string) (string, error) {
	for _, b := range state.PaymailBindings {
		if b.Alias == alias {
			return b.Vault, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrAliasNotFound, alias)
}

// ExportVaultKey exports the vault root key in the specified format.
// Supported formats: "wif", "hex", "seed-path".
func (w *Wallet) ExportVaultKey(state *WalletState, vaultName, format string) (string, error) {
	vault, err := w.GetVault(state, vaultName)
	if err != nil {
		return "", err
	}

	kp, err := w.DeriveVaultRootKey(vault.AccountIndex)
	if err != nil {
		return "", err
	}

	switch format {
	case "wif":
		return kp.PrivateKey.Wif(), nil
	case "hex":
		return hex.EncodeToString(kp.PrivateKey.Serialize()), nil
	case "seed-path":
		return kp.Path, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedKeyFormat, format)
	}
}
