package wallet

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mnemonic tests ---

func TestGenerateMnemonic_12Words(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)

	words := strings.Fields(mnemonic)
	assert.Len(t, words, 12, "12-word mnemonic should have 12 words")
	assert.True(t, ValidateMnemonic(mnemonic), "generated mnemonic should be valid")
}

func TestGenerateMnemonic_24Words(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic24Words)
	require.NoError(t, err)

	words := strings.Fields(mnemonic)
	assert.Len(t, words, 24, "24-word mnemonic should have 24 words")
	assert.True(t, ValidateMnemonic(mnemonic), "generated mnemonic should be valid")
}

func TestGenerateMnemonic_InvalidEntropy(t *testing.T) {
	_, err := GenerateMnemonic(64) // invalid
	assert.ErrorIs(t, err, ErrInvalidEntropy)

	_, err = GenerateMnemonic(192) // invalid
	assert.ErrorIs(t, err, ErrInvalidEntropy)
}

func TestGenerateMnemonic_Unique(t *testing.T) {
	m1, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)

	m2, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)

	assert.NotEqual(t, m1, m2, "two generated mnemonics should be different")
}

func TestValidateMnemonic(t *testing.T) {
	tests := []struct {
		name     string
		mnemonic string
		valid    bool
	}{
		{"valid 12-word", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", true},
		{"invalid words", "foo bar baz qux quux corge grault garply waldo fred plugh xyzzy", false},
		{"empty", "", false},
		{"partial", "abandon abandon", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, ValidateMnemonic(tt.mnemonic))
		})
	}
}

// --- Seed derivation tests ---

func TestSeedFromMnemonic_Deterministic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed1, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	seed2, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	assert.Equal(t, seed1, seed2, "same mnemonic+passphrase should produce same seed")
	assert.Len(t, seed1, 64, "BIP39 seed should be 64 bytes")
}

func TestSeedFromMnemonic_DifferentPassphrase(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed1, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	seed2, err := SeedFromMnemonic(mnemonic, "my secret passphrase")
	require.NoError(t, err)

	assert.NotEqual(t, seed1, seed2, "different passphrases should produce different seeds")
}

func TestSeedFromMnemonic_InvalidMnemonic(t *testing.T) {
	_, err := SeedFromMnemonic("invalid mnemonic words here", "")
	assert.ErrorIs(t, err, ErrInvalidMnemonic)
}

// --- Seed encryption tests ---

func TestEncryptDecryptSeed_RoundTrip(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	password := "test-password-123"

	encrypted, err := EncryptSeed(seed, password)
	require.NoError(t, err)
	assert.Greater(t, len(encrypted), len(seed), "encrypted should be larger than seed")

	decrypted, err := DecryptSeed(encrypted, password)
	require.NoError(t, err)
	assert.Equal(t, seed, decrypted, "decrypted seed should match original")
}

func TestDecryptSeed_WrongPassword(t *testing.T) {
	seed := make([]byte, 64)
	password := "correct-password"

	encrypted, err := EncryptSeed(seed, password)
	require.NoError(t, err)

	_, err = DecryptSeed(encrypted, "wrong-password")
	assert.ErrorIs(t, err, ErrDecryptionFailed, "wrong password should fail")
}

func TestEncryptSeed_EmptySeed(t *testing.T) {
	_, err := EncryptSeed([]byte{}, "password")
	assert.ErrorIs(t, err, ErrInvalidSeed)
}

func TestDecryptSeed_TooShort(t *testing.T) {
	_, err := DecryptSeed([]byte{0x01, 0x02, 0x03}, "password")
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestEncryptSeed_DifferentCiphertexts(t *testing.T) {
	seed := make([]byte, 64)
	password := "same-password"

	enc1, err := EncryptSeed(seed, password)
	require.NoError(t, err)

	enc2, err := EncryptSeed(seed, password)
	require.NoError(t, err)

	// Should differ due to random salt and nonce
	assert.NotEqual(t, enc1, enc2, "same seed+password should produce different ciphertexts")

	// But both should decrypt correctly
	dec1, err := DecryptSeed(enc1, password)
	require.NoError(t, err)
	assert.Equal(t, seed, dec1)

	dec2, err := DecryptSeed(enc2, password)
	require.NoError(t, err)
	assert.Equal(t, seed, dec2)
}

// --- HD Key Derivation tests ---

func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)
	return w
}

func TestNewWallet(t *testing.T) {
	w := newTestWallet(t)
	assert.NotNil(t, w)
	assert.Equal(t, "mainnet", w.Network().Name)
}

func TestNewWallet_EmptySeed(t *testing.T) {
	_, err := NewWallet([]byte{}, nil)
	assert.ErrorIs(t, err, ErrInvalidSeed)
}

func TestNewWallet_NilNetwork(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, nil)
	require.NoError(t, err)
	assert.Equal(t, "mainnet", w.Network().Name, "nil network should default to mainnet")
}

func TestDeriveFeeKey(t *testing.T) {
	w := newTestWallet(t)

	// Derive receive key
	kp, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, kp.PrivateKey)
	assert.NotNil(t, kp.PublicKey)
	assert.Equal(t, "m/44'/236'/0'/0/0", kp.Path)

	// Derive change key
	kp2, err := w.DeriveFeeKey(InternalChain, 0)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/0'/1/0", kp2.Path)

	// Different chains should produce different keys
	assert.NotEqual(t, kp.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

func TestDeriveFeeKey_Deterministic(t *testing.T) {
	w := newTestWallet(t)

	kp1, err := w.DeriveFeeKey(ExternalChain, 5)
	require.NoError(t, err)

	kp2, err := w.DeriveFeeKey(ExternalChain, 5)
	require.NoError(t, err)

	assert.Equal(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

func TestDeriveFeeKey_DifferentIndices(t *testing.T) {
	w := newTestWallet(t)

	kp1, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)

	kp2, err := w.DeriveFeeKey(ExternalChain, 1)
	require.NoError(t, err)

	assert.NotEqual(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

func TestDeriveVaultRootKey(t *testing.T) {
	w := newTestWallet(t)

	kp, err := w.DeriveVaultRootKey(0)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0", kp.Path)

	kp2, err := w.DeriveVaultRootKey(1)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/2'/0/0", kp2.Path)

	assert.NotEqual(t, kp.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

func TestDeriveNodeKey_RootDirectory(t *testing.T) {
	w := newTestWallet(t)

	kp, err := w.DeriveNodeKey(0, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0", kp.Path)
}

func TestDeriveNodeKey_ChildNode(t *testing.T) {
	w := newTestWallet(t)

	// First child of root (hardened by default)
	kp, err := w.DeriveNodeKey(0, []uint32{1}, nil)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0/1'", kp.Path)
}

func TestDeriveNodeKey_NestedPath(t *testing.T) {
	w := newTestWallet(t)

	// Nested path: root -> child 3 -> child 1 -> child 7
	kp, err := w.DeriveNodeKey(0, []uint32{3, 1, 7}, nil)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0/3'/1'/7'", kp.Path)
}

func TestDeriveNodeKey_NonHardened(t *testing.T) {
	w := newTestWallet(t)

	// Explicit non-hardened derivation
	kp, err := w.DeriveNodeKey(0, []uint32{1, 2}, []bool{false, false})
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0/1/2", kp.Path)
}

func TestDeriveNodeKey_MixedHardened(t *testing.T) {
	w := newTestWallet(t)

	// Mix: index 1 non-hardened, index 2 hardened
	kp, err := w.DeriveNodeKey(0, []uint32{1, 2}, []bool{false, true})
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0/1/2'", kp.Path)
}

func TestDeriveNodeKey_HardenedDefault(t *testing.T) {
	w := newTestWallet(t)

	// Default (nil hardened array) = all hardened (design decision #82)
	kpHardened, err := w.DeriveNodeKey(0, []uint32{5}, nil)
	require.NoError(t, err)

	kpExplicit, err := w.DeriveNodeKey(0, []uint32{5}, []bool{true})
	require.NoError(t, err)

	assert.Equal(t, kpHardened.PublicKey.Compressed(), kpExplicit.PublicKey.Compressed())
}

func TestDeriveNodeKey_Deterministic(t *testing.T) {
	w := newTestWallet(t)

	kp1, err := w.DeriveNodeKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)

	kp2, err := w.DeriveNodeKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)

	assert.Equal(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

func TestDeriveNodeKey_DifferentVaults(t *testing.T) {
	w := newTestWallet(t)

	kp1, err := w.DeriveNodeKey(0, []uint32{1}, nil)
	require.NoError(t, err)

	kp2, err := w.DeriveNodeKey(1, []uint32{1}, nil)
	require.NoError(t, err)

	assert.NotEqual(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed(),
		"same path in different vaults should produce different keys")
}

func TestDeriveNodeKey_PathTooDeep(t *testing.T) {
	w := newTestWallet(t)

	deepPath := make([]uint32, MaxPathDepth+1)
	for i := range deepPath {
		deepPath[i] = 1
	}

	_, err := w.DeriveNodeKey(0, deepPath, nil)
	assert.ErrorIs(t, err, ErrPathTooDeep)
}

func TestDeriveNodeKey_MaxDepthOK(t *testing.T) {
	w := newTestWallet(t)

	path := make([]uint32, MaxPathDepth) // exactly at limit
	for i := range path {
		path[i] = 1
	}

	kp, err := w.DeriveNodeKey(0, path, nil)
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestDeriveNodePubKey(t *testing.T) {
	w := newTestWallet(t)

	pubKey, err := w.DeriveNodePubKey(0, []uint32{1}, nil)
	require.NoError(t, err)

	kp, err := w.DeriveNodeKey(0, []uint32{1}, nil)
	require.NoError(t, err)

	assert.Equal(t, kp.PublicKey.Compressed(), pubKey.Compressed())
}

// --- Vault management tests ---

func TestCreateVault(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	vault, err := w.CreateVault(state, "personal")
	require.NoError(t, err)
	assert.Equal(t, "personal", vault.Name)
	assert.Equal(t, uint32(0), vault.AccountIndex)
	assert.Nil(t, vault.RootTxID)
	assert.False(t, vault.Deleted)
	assert.Len(t, state.Vaults, 1)
	assert.Equal(t, uint32(1), state.NextVaultIndex)
}

func TestCreateVault_Multiple(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	v1, err := w.CreateVault(state, "personal")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), v1.AccountIndex)

	v2, err := w.CreateVault(state, "company")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), v2.AccountIndex)

	assert.Len(t, state.Vaults, 2)
}

func TestCreateVault_DuplicateName(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	_, err = w.CreateVault(state, "personal")
	assert.ErrorIs(t, err, ErrVaultExists)
}

func TestGetVault(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.CreateVault(state, "personal")
	require.NoError(t, err)

	vault, err := w.GetVault(state, "personal")
	require.NoError(t, err)
	assert.Equal(t, "personal", vault.Name)
}

func TestGetVault_NotFound(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	_, err := w.GetVault(state, "nonexistent")
	assert.ErrorIs(t, err, ErrVaultNotFound)
}

func TestListVaults(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "personal")
	w.CreateVault(state, "company")

	vaults := w.ListVaults(state)
	assert.Len(t, vaults, 2)
}

func TestListVaults_ExcludesDeleted(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "personal")
	w.CreateVault(state, "company")
	w.DeleteVault(state, "company")

	vaults := w.ListVaults(state)
	assert.Len(t, vaults, 1)
	assert.Equal(t, "personal", vaults[0].Name)
}

func TestRenameVault(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "old-name")

	err := w.RenameVault(state, "old-name", "new-name")
	require.NoError(t, err)

	_, err = w.GetVault(state, "new-name")
	require.NoError(t, err)

	_, err = w.GetVault(state, "old-name")
	assert.ErrorIs(t, err, ErrVaultNotFound)
}

func TestRenameVault_ConflictingName(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "a")
	w.CreateVault(state, "b")

	err := w.RenameVault(state, "a", "b")
	assert.ErrorIs(t, err, ErrVaultExists)
}

func TestDeleteVault(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "personal")

	err := w.DeleteVault(state, "personal")
	require.NoError(t, err)

	_, err = w.GetVault(state, "personal")
	assert.ErrorIs(t, err, ErrVaultNotFound, "deleted vault should not be found")
}

func TestDeleteVault_NotFound(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	err := w.DeleteVault(state, "nonexistent")
	assert.ErrorIs(t, err, ErrVaultNotFound)
}

func TestCreateVault_CanReuseDeletedName(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	w.CreateVault(state, "temp")
	w.DeleteVault(state, "temp")

	// Should be able to create a new vault with the same name
	vault, err := w.CreateVault(state, "temp")
	require.NoError(t, err)
	assert.Equal(t, "temp", vault.Name)
	// But it gets a new account index (indices are never reused)
	assert.Equal(t, uint32(1), vault.AccountIndex)
}

// --- Network tests ---

func TestGetNetwork(t *testing.T) {
	tests := []struct {
		name    string
		netName string
		wantErr bool
	}{
		{"mainnet", "mainnet", false},
		{"testnet", "testnet", false},
		{"regtest", "regtest", false},
		{"teratestnet", "teratestnet", false},
		{"unknown", "foonet", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net, err := GetNetwork(tt.netName)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidNetwork)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.netName, net.Name)
			}
		})
	}
}

func TestMainNetConfig(t *testing.T) {
	assert.Equal(t, byte(0x00), MainNet.AddressVersion)
	assert.Equal(t, byte(0x05), MainNet.P2SHVersion)
	assert.Equal(t, uint16(8333), MainNet.DefaultPort)
}

func TestTestNetConfig(t *testing.T) {
	assert.Equal(t, byte(0x6f), TestNet.AddressVersion)
	assert.Equal(t, uint16(18333), TestNet.DefaultPort)
}

// --- Supplementary tests (audit gaps) ---

// GAP 1: ErrFileIndexOutOfRange never triggered.
func TestDeriveNodeKey_FileIndexOutOfRange(t *testing.T) {
	w := newTestWallet(t)

	// MaxFileIndex+1 == 2^31, which exceeds the non-hardened BIP32 limit.
	outOfRange := uint32(MaxFileIndex) + 1
	_, err := w.DeriveNodeKey(0, []uint32{outOfRange}, nil)
	assert.ErrorIs(t, err, ErrFileIndexOutOfRange)
}

func TestDeriveNodeKey_MaxFileIndexOK(t *testing.T) {
	w := newTestWallet(t)

	// Exactly MaxFileIndex (2^31-1) should succeed.
	maxIdx := uint32(MaxFileIndex)
	kp, err := w.DeriveNodeKey(0, []uint32{maxIdx}, nil)
	require.NoError(t, err)
	assert.NotNil(t, kp)
	assert.NotNil(t, kp.PublicKey)
}

// GAP 3: LoadCustomNetwork not tested.
func TestLoadCustomNetwork_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/custom.json"

	content := `{
		"name": "custom-net",
		"address_version": 111,
		"p2sh_version": 196,
		"default_port": 19999,
		"rpc_port": 19998,
		"seeds": ["seed.custom.example.com"],
		"genesis_hash": "00000000deadbeef"
	}`
	require.NoError(t, writeFile(path, []byte(content)))

	net, err := LoadCustomNetwork(path)
	require.NoError(t, err)
	assert.Equal(t, "custom-net", net.Name)
	assert.Equal(t, byte(111), net.AddressVersion)
	assert.Equal(t, byte(196), net.P2SHVersion)
	assert.Equal(t, uint16(19999), net.DefaultPort)
	assert.Equal(t, uint16(19998), net.RPCPort)
	assert.Equal(t, []string{"seed.custom.example.com"}, net.DNSSeeds)
	assert.Equal(t, "00000000deadbeef", net.GenesisHash)
}

func TestLoadCustomNetwork_FileNotFound(t *testing.T) {
	_, err := LoadCustomNetwork("/nonexistent/path/network.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read network config")
}

func TestLoadCustomNetwork_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.json"
	require.NoError(t, writeFile(path, []byte("{not valid json!!")))

	_, err := LoadCustomNetwork(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse network config")
}

func TestLoadCustomNetwork_MissingName(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/noname.json"
	require.NoError(t, writeFile(path, []byte(`{"default_port": 8333}`)))

	_, err := LoadCustomNetwork(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must have a name")
}

// GAP 6: DecryptSeed with bit-flipped (corrupted) ciphertext.
func TestDecryptSeed_CorruptedCiphertext(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	password := "correct-password"

	encrypted, err := EncryptSeed(seed, password)
	require.NoError(t, err)

	// Flip a byte in the ciphertext portion (after salt+nonce).
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	ciphertextOffset := SaltLen + NonceLen
	corrupted[ciphertextOffset+5] ^= 0xFF // bit-flip

	_, err = DecryptSeed(corrupted, password)
	assert.ErrorIs(t, err, ErrDecryptionFailed, "tampered ciphertext should fail AES-GCM authentication")
}

// GAP 7: EncryptSeed output format validation.
func TestEncryptSeed_OutputFormat(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i * 3)
	}

	encrypted, err := EncryptSeed(seed, "format-test")
	require.NoError(t, err)

	// AES-GCM overhead = 16 bytes (auth tag).
	// Plaintext = seed(64) + checksum(4) = 68 bytes.
	// Expected minimum: salt(16) + nonce(12) + plaintext(68) + tag(16) = 112.
	expectedMinLen := SaltLen + NonceLen + len(seed) + ChecksumLen + 16 // GCM tag
	assert.GreaterOrEqual(t, len(encrypted), expectedMinLen,
		"output must be at least salt+nonce+seed+checksum+GCM_tag bytes")

	// Salt (first 16 bytes) should not be all zeros (extremely unlikely with random).
	salt := encrypted[:SaltLen]
	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "salt should not be all zeros")

	// Nonce (next 12 bytes) should not be all zeros.
	nonce := encrypted[SaltLen : SaltLen+NonceLen]
	allZero = true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "nonce should not be all zeros")
}

// GAP 8: RenameVault with nonexistent old name.
func TestRenameVault_NonexistentOldName(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	err := w.RenameVault(state, "does-not-exist", "new-name")
	assert.ErrorIs(t, err, ErrVaultNotFound)
}

// GAP 9: DeriveFeeKey with invalid chain value.
func TestDeriveFeeKey_InvalidChain(t *testing.T) {
	w := newTestWallet(t)

	// chain=2 is invalid — only 0 (external) and 1 (internal) are allowed per BIP44.
	_, err := w.DeriveFeeKey(2, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain 2")

	// Valid chains still work.
	kpExt, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, kpExt.PublicKey)

	kpInt, err := w.DeriveFeeKey(InternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, kpInt.PublicKey)

	assert.NotEqual(t, kpExt.PublicKey.Compressed(), kpInt.PublicKey.Compressed(),
		"external and internal chains should produce different keys")
}

// GAP 10: DeriveNodeKey with mismatched hardened array length (partial).
func TestDeriveNodeKey_PartialHardenedArray(t *testing.T) {
	w := newTestWallet(t)

	// filePath has 3 elements, hardened has only 1 element.
	// Index 0 -> non-hardened (from array), indices 1-2 -> hardened (default fallback).
	kp, err := w.DeriveNodeKey(0, []uint32{1, 2, 3}, []bool{false})
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0/1/2'/3'", kp.Path,
		"partial hardened array: index 0 non-hardened, rest default to hardened")
}

// GAP 11: RegTest and TeraTestNet field-level assertions.
func TestRegTestConfig(t *testing.T) {
	net, err := GetNetwork("regtest")
	require.NoError(t, err)

	assert.Equal(t, "regtest", net.Name)
	assert.Equal(t, byte(0x6f), net.AddressVersion)
	assert.Equal(t, byte(0xc4), net.P2SHVersion)
	assert.Equal(t, uint16(18444), net.DefaultPort)
	assert.Equal(t, uint16(18443), net.RPCPort)
	assert.Nil(t, net.DNSSeeds, "regtest has no DNS seeds")
	assert.Equal(t, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", net.GenesisHash)
}

func TestTeraTestNetConfig(t *testing.T) {
	net, err := GetNetwork("teratestnet")
	require.NoError(t, err)

	assert.Equal(t, "teratestnet", net.Name)
	assert.Equal(t, byte(0x6f), net.AddressVersion)
	assert.Equal(t, byte(0xc4), net.P2SHVersion)
	assert.Equal(t, uint16(0), net.DefaultPort, "teratestnet port is placeholder 0")
	assert.Equal(t, uint16(0), net.RPCPort, "teratestnet RPC port is placeholder 0")
	assert.Empty(t, net.DNSSeeds, "teratestnet has no DNS seeds")
	assert.Empty(t, net.GenesisHash, "teratestnet genesis hash is empty placeholder")
}

// GAP 12: NewWalletState return value validation.
func TestNewWalletState(t *testing.T) {
	state := NewWalletState()
	require.NotNil(t, state)

	assert.Equal(t, uint32(0), state.NextReceiveIndex)
	assert.Equal(t, uint32(0), state.NextChangeIndex)
	assert.NotNil(t, state.Vaults, "Vaults should be initialized, not nil")
	assert.Empty(t, state.Vaults, "Vaults should be empty")
	assert.Equal(t, uint32(0), state.NextVaultIndex)
}

// GAP 13: Wallet.Network() accessor isolation.
func TestWallet_Network(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, &TestNet)
	require.NoError(t, err)

	assert.Equal(t, "testnet", w.Network().Name)
	assert.Equal(t, &TestNet, w.Network(), "Network() should return pointer to the provided config")
}

// Edge case: empty password for EncryptSeed/DecryptSeed round-trip.
func TestEncryptDecryptSeed_EmptyPassword(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 100)
	}

	encrypted, err := EncryptSeed(seed, "")
	require.NoError(t, err)

	decrypted, err := DecryptSeed(encrypted, "")
	require.NoError(t, err)
	assert.Equal(t, seed, decrypted, "empty password round-trip should succeed")
}

// Edge case: Unicode password for EncryptSeed/DecryptSeed.
func TestEncryptDecryptSeed_UnicodePassword(t *testing.T) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 50)
	}
	password := "\u4f60\u597d\u4e16\u754c\U0001f512"

	encrypted, err := EncryptSeed(seed, password)
	require.NoError(t, err)

	decrypted, err := DecryptSeed(encrypted, password)
	require.NoError(t, err)
	assert.Equal(t, seed, decrypted, "unicode password round-trip should succeed")
}

// Edge case: DeriveNodeKey with empty filePath slice (not nil) and empty hardened slice (not nil).
func TestDeriveNodeKey_EmptySlices(t *testing.T) {
	w := newTestWallet(t)

	kp, err := w.DeriveNodeKey(0, []uint32{}, []bool{})
	require.NoError(t, err)
	assert.Equal(t, "m/44'/236'/1'/0/0", kp.Path,
		"empty (non-nil) slices should behave same as nil")

	kpNil, err := w.DeriveNodeKey(0, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey.Compressed(), kpNil.PublicKey.Compressed(),
		"empty slices and nil should derive the same key")
}

// M-NEW-10: BIP32 account index overflow — DeriveNodeKey must reject vault index near Hardened boundary.
func TestDeriveNodeKey_RejectsOverflowVaultIndex(t *testing.T) {
	w := newTestWallet(t)
	// vaultIndex + DefaultVaultAccount (1) would overflow into Hardened range.
	_, err := w.DeriveNodeKey(Hardened-1, nil, nil)
	assert.Error(t, err, "vault index that produces account >= Hardened must be rejected")
	assert.ErrorIs(t, err, ErrFileIndexOutOfRange)
}

// M-NEW-10: CreateVault must reject when NextVaultIndex is at Hardened boundary.
func TestCreateVault_RejectsAtHardenedBoundary(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()
	state.NextVaultIndex = Hardened - 1 // Next creation would wrap
	_, err := w.CreateVault(state, "overflow")
	assert.Error(t, err, "creating vault at Hardened boundary must fail")
}

// M-NEW-12: WalletState.Validate checks structural integrity.
func TestWalletState_Validate(t *testing.T) {
	tests := []struct {
		name    string
		state   *WalletState
		wantErr string
	}{
		{
			name:  "valid empty state",
			state: NewWalletState(),
		},
		{
			name: "valid state with vault",
			state: &WalletState{
				Vaults:         []Vault{{Name: "v0", AccountIndex: 0}},
				NextVaultIndex: 1,
			},
		},
		{
			name: "NextVaultIndex too low",
			state: &WalletState{
				Vaults:         []Vault{{Name: "v0", AccountIndex: 5}},
				NextVaultIndex: 3,
			},
			wantErr: "NextVaultIndex",
		},
		{
			name: "duplicate account index",
			state: &WalletState{
				Vaults:         []Vault{{Name: "a", AccountIndex: 0}, {Name: "b", AccountIndex: 0}},
				NextVaultIndex: 1,
			},
			wantErr: "duplicate",
		},
		{
			name: "account index at Hardened boundary",
			state: &WalletState{
				Vaults:         []Vault{{Name: "v0", AccountIndex: Hardened - 1}},
				NextVaultIndex: Hardened,
			},
			wantErr: "exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.state.Validate()
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Edge case: large vault index for DeriveNodeKey.
func TestDeriveNodeKey_LargeVaultIndex(t *testing.T) {
	w := newTestWallet(t)

	kp, err := w.DeriveNodeKey(1000, nil, nil)
	require.NoError(t, err)
	assert.Contains(t, kp.Path, "m/44'/236'/1001'/0/0",
		"vault 1000 maps to account 1001")
	assert.NotNil(t, kp.PublicKey)
}

// Edge case: vault with empty string name.
func TestCreateVault_EmptyName(t *testing.T) {
	w := newTestWallet(t)
	state := NewWalletState()

	// The implementation does not prohibit empty names.
	vault, err := w.CreateVault(state, "")
	require.NoError(t, err)
	assert.Equal(t, "", vault.Name)

	// Verify it can be retrieved.
	v, err := w.GetVault(state, "")
	require.NoError(t, err)
	assert.Equal(t, "", v.Name)
}

// Edge case: DeriveNodeKey with multiple out-of-range indices (only first matters).
func TestDeriveNodeKey_MultipleOutOfRange(t *testing.T) {
	w := newTestWallet(t)

	outOfRange := uint32(MaxFileIndex) + 1
	_, err := w.DeriveNodeKey(0, []uint32{0, outOfRange}, nil)
	assert.ErrorIs(t, err, ErrFileIndexOutOfRange)
}

// =============================================================================
// Benchmarks
// =============================================================================

func newBenchWallet(b *testing.B) *Wallet {
	b.Helper()
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed, err := SeedFromMnemonic(mnemonic, "")
	if err != nil {
		b.Fatal(err)
	}
	w, err := NewWallet(seed, &MainNet)
	if err != nil {
		b.Fatal(err)
	}
	return w
}

func BenchmarkDeriveNodeKey(b *testing.B) {
	b.Run("root", func(b *testing.B) {
		w := newBenchWallet(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := w.DeriveNodeKey(0, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("depth_1", func(b *testing.B) {
		w := newBenchWallet(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := w.DeriveNodeKey(0, []uint32{1}, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("depth_3", func(b *testing.B) {
		w := newBenchWallet(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := w.DeriveNodeKey(0, []uint32{3, 1, 7}, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("depth_10", func(b *testing.B) {
		w := newBenchWallet(b)
		path := make([]uint32, 10)
		for i := range path {
			path[i] = uint32(i + 1)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := w.DeriveNodeKey(0, path, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDeriveFeeKey(b *testing.B) {
	w := newBenchWallet(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := w.DeriveFeeKey(ExternalChain, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveVaultRootKey(b *testing.B) {
	w := newBenchWallet(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := w.DeriveVaultRootKey(0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeedFromMnemonic(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SeedFromMnemonic(mnemonic, "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptSeed(b *testing.B) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	password := "benchmark-password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := EncryptSeed(seed, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptSeed(b *testing.B) {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	password := "benchmark-password"

	encrypted, err := EncryptSeed(seed, password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecryptSeed(encrypted, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// writeFile is a test helper for writing temporary files.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// --- Integration: Full wallet workflow ---

func TestFullWalletWorkflow(t *testing.T) {
	// 1. Generate mnemonic
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)

	// 2. Derive seed
	seed, err := SeedFromMnemonic(mnemonic, "my-passphrase")
	require.NoError(t, err)
	assert.Len(t, seed, 64)

	// 3. Encrypt seed
	encrypted, err := EncryptSeed(seed, "wallet-password")
	require.NoError(t, err)

	// 4. Create wallet (simulating app start)
	decryptedSeed, err := DecryptSeed(encrypted, "wallet-password")
	require.NoError(t, err)

	w, err := NewWallet(decryptedSeed, &MainNet)
	require.NoError(t, err)

	// 5. Create vaults
	state := NewWalletState()
	_, err = w.CreateVault(state, "personal")
	require.NoError(t, err)

	// 6. Derive keys for filesystem nodes
	rootKey, err := w.DeriveVaultRootKey(0)
	require.NoError(t, err)
	assert.Contains(t, rootKey.Path, "m/44'/236'/1'/0/0")

	// 7. Derive key for a file in the root directory
	fileKey, err := w.DeriveNodeKey(0, []uint32{1}, nil)
	require.NoError(t, err)
	assert.Contains(t, fileKey.Path, "m/44'/236'/1'/0/0/1'")

	// 8. Derive fee chain key
	feeKey, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, feeKey.PrivateKey)
}
