package wallet

import "fmt"

// Vault represents an independent Metanet directory tree.
// Each Vault = one BIP32 account = one independent Metanet tree.
type Vault struct {
	Name         string `json:"name"`
	AccountIndex uint32 `json:"account_index"` // BIP44 account (1-based for vaults)
	RootTxID     []byte `json:"root_txid"`     // Root node transaction ID (nil if unpublished)
	Deleted      bool   `json:"deleted"`       // Soft-deleted flag
}

// WalletState holds persisted wallet metadata.
type WalletState struct {
	NextReceiveIndex uint32  `json:"next_receive_index"` // Fee chain next receive address
	NextChangeIndex  uint32  `json:"next_change_index"`  // Fee chain next change address
	Vaults           []Vault `json:"vaults"`
	NextVaultIndex   uint32  `json:"next_vault_index"` // Next available vault account index
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

// RenameVault renames an existing vault.
func (w *Wallet) RenameVault(state *WalletState, oldName, newName string) error {
	// Check new name doesn't conflict
	for _, v := range state.Vaults {
		if v.Name == newName && !v.Deleted {
			return fmt.Errorf("%w: %q", ErrVaultExists, newName)
		}
	}

	for i := range state.Vaults {
		if state.Vaults[i].Name == oldName && !state.Vaults[i].Deleted {
			state.Vaults[i].Name = newName
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrVaultNotFound, oldName)
}

// DeleteVault marks a vault as deleted (soft delete).
// The account index is not reused.
func (w *Wallet) DeleteVault(state *WalletState, name string) error {
	for i := range state.Vaults {
		if state.Vaults[i].Name == name && !state.Vaults[i].Deleted {
			state.Vaults[i].Deleted = true
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrVaultNotFound, name)
}
