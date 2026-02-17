package wallet

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/compat/bip39"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NewWallet — nil network defaults to MainNet
// ---------------------------------------------------------------------------

func TestNewWallet_NilNetworkFallsBackToMainNet(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, nil)
	require.NoError(t, err)
	assert.Equal(t, "mainnet", w.Network().Name)

	// Derivation should work.
	kp, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, kp.PublicKey)
}

// ---------------------------------------------------------------------------
// NewWallet — empty seed
// ---------------------------------------------------------------------------

func TestNewWallet_NilAndEmptySeedReturnsError(t *testing.T) {
	_, err := NewWallet(nil, &MainNet)
	assert.ErrorIs(t, err, ErrInvalidSeed)

	_, err = NewWallet([]byte{}, &MainNet)
	assert.ErrorIs(t, err, ErrInvalidSeed)
}

// ---------------------------------------------------------------------------
// EncryptSeed/DecryptSeed — empty password round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecryptSeed_EmptyPassphraseRoundTrip(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	encrypted, err := EncryptSeed(seed, "")
	require.NoError(t, err)

	decrypted, err := DecryptSeed(encrypted, "")
	require.NoError(t, err)
	assert.Equal(t, seed, decrypted)
}

// ---------------------------------------------------------------------------
// DecryptSeed — edge cases around minimum length
// ---------------------------------------------------------------------------

func TestDecryptSeed_ExactMinLength(t *testing.T) {
	// Exactly SaltLen + NonceLen + ChecksumLen = 32 bytes.
	// Passes the length check but fails at GCM decryption.
	data := make([]byte, SaltLen+NonceLen+ChecksumLen)
	_, err := DecryptSeed(data, "password")
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptSeed_OneBelowMinLength(t *testing.T) {
	data := make([]byte, SaltLen+NonceLen+ChecksumLen-1)
	_, err := DecryptSeed(data, "password")
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// ---------------------------------------------------------------------------
// EncryptSeed — empty seed
// ---------------------------------------------------------------------------

func TestEncryptSeed_NilAndEmptySeedReturnsError(t *testing.T) {
	_, err := EncryptSeed(nil, "password")
	assert.ErrorIs(t, err, ErrInvalidSeed)

	_, err = EncryptSeed([]byte{}, "password")
	assert.ErrorIs(t, err, ErrInvalidSeed)
}

// ---------------------------------------------------------------------------
// DeriveNodeKey — root key (empty file path)
// ---------------------------------------------------------------------------

func TestDeriveNodeKey_EmptyPath(t *testing.T) {
	w := makeWallet(t)
	kp, err := w.DeriveNodeKey(0, nil, nil)
	require.NoError(t, err)
	assert.Contains(t, kp.Path, "m/44'/236'/1'/0/0")
	assert.NotNil(t, kp.PrivateKey)
	assert.NotNil(t, kp.PublicKey)
}

func TestDeriveNodeKey_EmptySlicePath(t *testing.T) {
	w := makeWallet(t)
	kp, err := w.DeriveNodeKey(0, []uint32{}, nil)
	require.NoError(t, err)
	assert.Contains(t, kp.Path, "m/44'/236'/1'/0/0")
}

// ---------------------------------------------------------------------------
// DeriveNodeKey — determinism
// ---------------------------------------------------------------------------

func TestDeriveNodeKey_SameSeedProducesSameKey(t *testing.T) {
	mnemonic, err := bip39.NewMnemonic(make([]byte, 16))
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w1, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)
	w2, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)

	kp1, err := w1.DeriveNodeKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)
	kp2, err := w2.DeriveNodeKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)

	assert.Equal(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed())
	assert.Equal(t, kp1.Path, kp2.Path)
}

// ---------------------------------------------------------------------------
// DeriveFeeKey — determinism across wallet instances
// ---------------------------------------------------------------------------

func TestDeriveFeeKey_SameSeedProducesSameKey(t *testing.T) {
	mnemonic, err := bip39.NewMnemonic(make([]byte, 16))
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w1, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)
	w2, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)

	kp1, err := w1.DeriveFeeKey(ExternalChain, 5)
	require.NoError(t, err)
	kp2, err := w2.DeriveFeeKey(ExternalChain, 5)
	require.NoError(t, err)

	assert.Equal(t, kp1.PublicKey.Compressed(), kp2.PublicKey.Compressed())
}

// ---------------------------------------------------------------------------
// DeriveVaultRootKey — multiple vaults produce distinct keys
// ---------------------------------------------------------------------------

func TestDeriveVaultRootKey_DistinctPerVault(t *testing.T) {
	w := makeWallet(t)
	seen := make(map[string]bool)

	for vault := uint32(0); vault < 10; vault++ {
		kp, err := w.DeriveVaultRootKey(vault)
		require.NoError(t, err, "vault=%d", vault)
		pub := string(kp.PublicKey.Compressed())
		assert.False(t, seen[pub], "vault %d produced duplicate root key", vault)
		seen[pub] = true
	}
}

// ---------------------------------------------------------------------------
// DeriveNodeKey — deep path near MaxPathDepth limit
// ---------------------------------------------------------------------------

func TestDeriveNodeKey_MaxPathDepth(t *testing.T) {
	w := makeWallet(t)

	// Exactly at MaxPathDepth — should succeed.
	path := make([]uint32, MaxPathDepth)
	for i := range path {
		path[i] = uint32(i % 10)
	}
	kp, err := w.DeriveNodeKey(0, path, nil)
	require.NoError(t, err)
	assert.NotNil(t, kp.PublicKey)
}

// ---------------------------------------------------------------------------
// DeriveNodeKey — single level paths with different hardened settings
// ---------------------------------------------------------------------------

func TestDeriveNodeKey_SingleLevelHardened(t *testing.T) {
	w := makeWallet(t)

	kpH, err := w.DeriveNodeKey(0, []uint32{5}, []bool{true})
	require.NoError(t, err)
	assert.Contains(t, kpH.Path, "/5'")

	kpN, err := w.DeriveNodeKey(0, []uint32{5}, []bool{false})
	require.NoError(t, err)
	assert.NotContains(t, kpN.Path[len("m/44'/236'/1'/0/0"):], "'")

	// Hardened vs non-hardened must produce different keys.
	assert.NotEqual(t, kpH.PublicKey.Compressed(), kpN.PublicKey.Compressed())
}
