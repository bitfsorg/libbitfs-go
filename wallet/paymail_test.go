package wallet

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PaymailBinding tests ---

// Test 1: bind valid alias to existing vault — success.
func TestBindPaymail_ValidAlias(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)

	require.Len(t, state.PaymailBindings, 1)
	assert.Equal(t, "alice", state.PaymailBindings[0].Alias)
	assert.Equal(t, "personal", state.PaymailBindings[0].Vault)
}

// Test 2: bind to nonexistent vault — ErrVaultNotFound.
func TestBindPaymail_NonexistentVault(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	err := w.BindPaymail(state, "alice", "no-such-vault")
	assert.ErrorIs(t, err, ErrVaultNotFound)
}

// Test 3: bind already-taken alias — ErrAliasExists.
func TestBindPaymail_DuplicateAlias(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "vault-a")
	require.NoError(t, err)
	_, err = w.CreateVault(state, "vault-b")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "vault-a")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "vault-b")
	assert.ErrorIs(t, err, ErrAliasExists)
}

// Test 4: bind vault that already has a binding — ErrVaultAlreadyBound.
func TestBindPaymail_VaultAlreadyBound(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "bob", "personal")
	assert.ErrorIs(t, err, ErrVaultAlreadyBound)
}

// Test 5: invalid alias formats — ErrInvalidAlias.
func TestBindPaymail_InvalidAliasFormats(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	tests := []struct {
		name  string
		alias string
	}{
		{"uppercase", "Alice"},
		{"special chars", "alice@home"},
		{"empty", ""},
		{"space", "alice bob"},
		{"starts with hyphen", "-alice"},
		{"starts with dot", ".alice"},
		{"starts with underscore", "_alice"},
		{"too long (65 chars)", strings.Repeat("a", 65)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.BindPaymail(state, tt.alias, "personal")
			assert.ErrorIs(t, err, ErrInvalidAlias, "alias=%q should be invalid", tt.alias)
		})
	}
}

// Test 5b: valid alias edge cases.
func TestBindPaymail_ValidAliasEdgeCases(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	// Create enough vaults for each test case.
	names := []string{"v1", "v2", "v3", "v4"}
	for _, n := range names {
		_, err := w.CreateVault(state, n)
		require.NoError(t, err)
	}

	validAliases := []struct {
		alias string
		vault string
	}{
		{"a", "v1"},                              // single char
		{"alice.bob", "v2"},                      // dots allowed
		{"alice-bob", "v3"},                      // hyphens allowed
		{strings.Repeat("a", 64), "v4"},          // exactly 64 chars
	}

	for _, tc := range validAliases {
		err := w.BindPaymail(state, tc.alias, tc.vault)
		assert.NoError(t, err, "alias=%q should be valid", tc.alias)
	}
}

// Test 6: unbind existing alias — success.
func TestUnbindPaymail_Existing(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)

	err = w.UnbindPaymail(state, "alice")
	require.NoError(t, err)

	assert.Empty(t, state.PaymailBindings)
}

// Test 7: unbind nonexistent alias — ErrAliasNotFound.
func TestUnbindPaymail_Nonexistent(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	err := w.UnbindPaymail(state, "nobody")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

// Test 8: resolve bound alias — correct vault name + pubkey derivable.
func TestResolvePaymailAlias_Bound(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)

	vaultName, err := w.ResolvePaymailAlias(state, "alice")
	require.NoError(t, err)
	assert.Equal(t, "personal", vaultName)

	// Verify we can derive a key for the resolved vault.
	vault, err := w.GetVault(state, vaultName)
	require.NoError(t, err)

	kp, err := w.DeriveVaultRootKey(vault.AccountIndex)
	require.NoError(t, err)
	assert.NotNil(t, kp.PublicKey)
	assert.NotEmpty(t, kp.PublicKey.Compressed())
}

// Test 9: resolve unbound alias — ErrAliasNotFound.
func TestResolvePaymailAlias_Unbound(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.ResolvePaymailAlias(state, "nobody")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

// Test 10: delete vault with binding — vault deleted + binding removed.
func TestDeleteVault_WithBinding(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)
	require.Len(t, state.PaymailBindings, 1)

	err = w.DeleteVault(state, "personal")
	require.NoError(t, err)

	// Vault should be gone.
	_, err = w.GetVault(state, "personal")
	assert.ErrorIs(t, err, ErrVaultNotFound)

	// Binding should also be removed.
	assert.Empty(t, state.PaymailBindings)

	// Resolve should fail.
	_, err = w.ResolvePaymailAlias(state, "alice")
	assert.ErrorIs(t, err, ErrAliasNotFound)
}

// Test 11: rename vault with binding — binding.vault updated.
func TestRenameVault_WithBinding(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "old-name")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "old-name")
	require.NoError(t, err)

	err = w.RenameVault(state, "old-name", "new-name")
	require.NoError(t, err)

	// Binding should now reference the new name.
	require.Len(t, state.PaymailBindings, 1)
	assert.Equal(t, "new-name", state.PaymailBindings[0].Vault)
	assert.Equal(t, "alice", state.PaymailBindings[0].Alias)

	// Resolve should return the new vault name.
	vaultName, err := w.ResolvePaymailAlias(state, "alice")
	require.NoError(t, err)
	assert.Equal(t, "new-name", vaultName)
}

// Test 12: validate — binding references deleted vault.
func TestValidate_BindingReferencesDeletedVault(t *testing.T) {
	state := &WalletState{
		Vaults:          []Vault{{Name: "v1", AccountIndex: 0, Deleted: true}},
		NextVaultIndex:  1,
		PaymailBindings: []PaymailBinding{{Alias: "alice", Vault: "v1"}},
	}

	err := state.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-existent vault")
}

// Test 13: validate — duplicate alias.
func TestValidate_DuplicateAlias(t *testing.T) {
	state := &WalletState{
		Vaults:         []Vault{{Name: "v1", AccountIndex: 0}, {Name: "v2", AccountIndex: 1}},
		NextVaultIndex: 2,
		PaymailBindings: []PaymailBinding{
			{Alias: "alice", Vault: "v1"},
			{Alias: "alice", Vault: "v2"},
		},
	}

	err := state.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate alias")
}

// Test 14: validate — same vault bound twice.
func TestValidate_VaultBoundTwice(t *testing.T) {
	state := &WalletState{
		Vaults:         []Vault{{Name: "v1", AccountIndex: 0}},
		NextVaultIndex: 1,
		PaymailBindings: []PaymailBinding{
			{Alias: "alice", Vault: "v1"},
			{Alias: "bob", Vault: "v1"},
		},
	}

	err := state.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bound more than once")
}

// Test 15: old JSON without paymail_bindings deserializes OK.
func TestDeserialize_OldJSONWithoutPaymailBindings(t *testing.T) {
	oldJSON := `{
		"next_receive_index": 5,
		"next_change_index": 3,
		"vaults": [{"name": "personal", "account_index": 0, "root_txid": null, "deleted": false}],
		"next_vault_index": 1
	}`

	var state WalletState
	err := json.Unmarshal([]byte(oldJSON), &state)
	require.NoError(t, err)

	assert.Equal(t, uint32(5), state.NextReceiveIndex)
	assert.Equal(t, uint32(3), state.NextChangeIndex)
	assert.Len(t, state.Vaults, 1)
	assert.Equal(t, "personal", state.Vaults[0].Name)
	assert.Nil(t, state.PaymailBindings, "omitted paymail_bindings should deserialize as nil")

	// Validate should succeed.
	err = state.Validate()
	assert.NoError(t, err)
}

// Test 16: reserved for daemon test.
func TestPaymail_Reserved16(t *testing.T) {
	t.Skip("reserved for daemon integration test")
}

// Test 17: reserved for daemon test.
func TestPaymail_Reserved17(t *testing.T) {
	t.Skip("reserved for daemon integration test")
}

// Test 18: export vault key in WIF, hex, and seed-path formats.
func TestExportVaultKey(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	t.Run("wif", func(t *testing.T) {
		wif, err := w.ExportVaultKey(state, "personal", "wif")
		require.NoError(t, err)
		assert.NotEmpty(t, wif)
		// WIF starts with 'K', 'L', or '5' for mainnet compressed/uncompressed.
		assert.True(t, wif[0] == 'K' || wif[0] == 'L' || wif[0] == '5',
			"WIF should start with K, L, or 5; got %q", wif)
	})

	t.Run("hex", func(t *testing.T) {
		hexKey, err := w.ExportVaultKey(state, "personal", "hex")
		require.NoError(t, err)
		assert.NotEmpty(t, hexKey)
		// Private key is 32 bytes = 64 hex chars.
		assert.Len(t, hexKey, 64, "hex private key should be 64 hex chars")
	})

	t.Run("seed-path", func(t *testing.T) {
		path, err := w.ExportVaultKey(state, "personal", "seed-path")
		require.NoError(t, err)
		assert.Equal(t, "m/44'/236'/1'/0/0", path)
	})

	t.Run("unsupported format", func(t *testing.T) {
		_, err := w.ExportVaultKey(state, "personal", "pem")
		assert.ErrorIs(t, err, ErrUnsupportedKeyFormat)
	})

	t.Run("nonexistent vault", func(t *testing.T) {
		_, err := w.ExportVaultKey(state, "no-such-vault", "wif")
		assert.ErrorIs(t, err, ErrVaultNotFound)
	})
}

// Additional: ListPaymailBindings returns a defensive copy.
func TestListPaymailBindings(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "v1")
	require.NoError(t, err)
	_, err = w.CreateVault(state, "v2")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "v1")
	require.NoError(t, err)
	err = w.BindPaymail(state, "bob", "v2")
	require.NoError(t, err)

	bindings := w.ListPaymailBindings(state)
	require.Len(t, bindings, 2)
	assert.Equal(t, "alice", bindings[0].Alias)
	assert.Equal(t, "bob", bindings[1].Alias)

	// Mutating the returned slice should not affect state.
	bindings[0].Alias = "mutated"
	assert.Equal(t, "alice", state.PaymailBindings[0].Alias)
}

// Additional: ListPaymailBindings on empty state returns nil.
func TestListPaymailBindings_Empty(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	bindings := w.ListPaymailBindings(state)
	assert.Nil(t, bindings)
}

// Additional: JSON round-trip with paymail bindings.
func TestPaymailBindings_JSONRoundTrip(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "personal")
	require.NoError(t, err)

	data, err := json.Marshal(state)
	require.NoError(t, err)

	var restored WalletState
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	require.Len(t, restored.PaymailBindings, 1)
	assert.Equal(t, "alice", restored.PaymailBindings[0].Alias)
	assert.Equal(t, "personal", restored.PaymailBindings[0].Vault)

	err = restored.Validate()
	assert.NoError(t, err)
}

// Additional: unbind then rebind — alias can be reused.
func TestUnbindThenRebind(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "v1")
	require.NoError(t, err)
	_, err = w.CreateVault(state, "v2")
	require.NoError(t, err)

	err = w.BindPaymail(state, "alice", "v1")
	require.NoError(t, err)

	err = w.UnbindPaymail(state, "alice")
	require.NoError(t, err)

	// Should be able to bind same alias to different vault.
	err = w.BindPaymail(state, "alice", "v2")
	assert.NoError(t, err)

	vaultName, err := w.ResolvePaymailAlias(state, "alice")
	require.NoError(t, err)
	assert.Equal(t, "v2", vaultName)
}

// Additional: ExportVaultKey determinism — same vault produces same key.
func TestExportVaultKey_Deterministic(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	wif1, err := w.ExportVaultKey(state, "personal", "wif")
	require.NoError(t, err)

	wif2, err := w.ExportVaultKey(state, "personal", "wif")
	require.NoError(t, err)

	assert.Equal(t, wif1, wif2, "same vault should produce same WIF")
}

// Additional: validate — binding with invalid alias format.
func TestValidate_InvalidAliasInBinding(t *testing.T) {
	state := &WalletState{
		Vaults:          []Vault{{Name: "v1", AccountIndex: 0}},
		NextVaultIndex:  1,
		PaymailBindings: []PaymailBinding{{Alias: "UPPERCASE", Vault: "v1"}},
	}

	err := state.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid alias format")
}
