package wallet

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/compat/bip39"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeWallet creates a wallet from a deterministic mnemonic for coverage tests.
func makeWallet(t *testing.T) *Wallet {
	t.Helper()
	mnemonic, err := bip39.NewMnemonic(make([]byte, 16)) // deterministic 12-word
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)
	w, err := NewWallet(seed, &MainNet)
	require.NoError(t, err)
	return w
}

// ---------------------------------------------------------------------------
// DeriveNodePubKey — error propagation (75% → higher)
// ---------------------------------------------------------------------------

func TestDeriveNodePubKey_PathTooDeep(t *testing.T) {
	w := makeWallet(t)
	path := make([]uint32, MaxPathDepth+1)
	_, err := w.DeriveNodePubKey(0, path, nil)
	assert.ErrorIs(t, err, ErrPathTooDeep)
}

func TestDeriveNodePubKey_FileIndexOutOfRange(t *testing.T) {
	w := makeWallet(t)
	_, err := w.DeriveNodePubKey(0, []uint32{uint32(MaxFileIndex) + 1}, nil)
	assert.ErrorIs(t, err, ErrFileIndexOutOfRange)
}

func TestDeriveNodePubKey_Success(t *testing.T) {
	w := makeWallet(t)
	pubKey, err := w.DeriveNodePubKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)

	// Should match the public key from DeriveNodeKey.
	kp, err := w.DeriveNodeKey(0, []uint32{1, 2, 3}, nil)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey.Compressed(), pubKey.Compressed())
}

// ---------------------------------------------------------------------------
// DeriveFeeKey — different chain/index combos (70% → higher)
// ---------------------------------------------------------------------------

func TestDeriveFeeKey_AllChains(t *testing.T) {
	w := makeWallet(t)
	tests := []struct {
		chain uint32
		index uint32
	}{
		{ExternalChain, 0},
		{ExternalChain, 1},
		{ExternalChain, 100},
		{InternalChain, 0},
		{InternalChain, 1},
		{InternalChain, 50},
	}
	for _, tc := range tests {
		kp, err := w.DeriveFeeKey(tc.chain, tc.index)
		require.NoError(t, err, "chain=%d index=%d", tc.chain, tc.index)
		assert.NotNil(t, kp.PrivateKey)
		assert.NotNil(t, kp.PublicKey)
		assert.Contains(t, kp.Path, "m/44'/236'/0'")
	}
}

func TestDeriveFeeKey_UniqueAcrossIndices(t *testing.T) {
	w := makeWallet(t)
	keys := make(map[string]bool)
	for i := uint32(0); i < 10; i++ {
		kp, err := w.DeriveFeeKey(ExternalChain, i)
		require.NoError(t, err)
		pubHex := string(kp.PublicKey.Compressed())
		assert.False(t, keys[pubHex], "duplicate key at index %d", i)
		keys[pubHex] = true
	}
}

// ---------------------------------------------------------------------------
// deriveAccount — exercised through DeriveNodeKey with different accounts
// ---------------------------------------------------------------------------

func TestDeriveAccount_MultipleVaults(t *testing.T) {
	w := makeWallet(t)
	keys := make(map[string]bool)
	for vault := uint32(0); vault < 5; vault++ {
		kp, err := w.DeriveVaultRootKey(vault)
		require.NoError(t, err, "vault=%d", vault)
		pubHex := string(kp.PublicKey.Compressed())
		assert.False(t, keys[pubHex], "duplicate vault root key at index %d", vault)
		keys[pubHex] = true
	}
}

// ---------------------------------------------------------------------------
// GenerateMnemonic — entropy validation
// ---------------------------------------------------------------------------

func TestGenerateMnemonic_InvalidEntropyValues(t *testing.T) {
	invalidBits := []int{0, 64, 96, 160, 192, 512}
	for _, bits := range invalidBits {
		_, err := GenerateMnemonic(bits)
		assert.ErrorIs(t, err, ErrInvalidEntropy, "bits=%d", bits)
	}
}

// ---------------------------------------------------------------------------
// SeedFromMnemonic — error paths
// ---------------------------------------------------------------------------

func TestSeedFromMnemonic_EmptyString(t *testing.T) {
	_, err := SeedFromMnemonic("", "")
	assert.ErrorIs(t, err, ErrInvalidMnemonic)
}

func TestSeedFromMnemonic_GarbageWords(t *testing.T) {
	_, err := SeedFromMnemonic("foo bar baz qux quux corge grault garply waldo fred plugh xyzzy", "")
	assert.ErrorIs(t, err, ErrInvalidMnemonic)
}

func TestSeedFromMnemonic_DifferentPassphrases(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)

	seed1, err := SeedFromMnemonic(mnemonic, "pass1")
	require.NoError(t, err)
	seed2, err := SeedFromMnemonic(mnemonic, "pass2")
	require.NoError(t, err)

	assert.NotEqual(t, seed1, seed2)
	assert.Len(t, seed1, 64)
	assert.Len(t, seed2, 64)
}

// ---------------------------------------------------------------------------
// EncryptSeed / DecryptSeed — edge cases
// ---------------------------------------------------------------------------

func TestEncryptSeed_LargeSeed(t *testing.T) {
	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i)
	}
	encrypted, err := EncryptSeed(seed, "pass")
	require.NoError(t, err)

	decrypted, err := DecryptSeed(encrypted, "pass")
	require.NoError(t, err)
	assert.Equal(t, seed, decrypted)
}

func TestDecryptSeed_TruncatedCiphertext(t *testing.T) {
	seed := []byte("a valid seed for testing truncation")
	encrypted, err := EncryptSeed(seed, "pass")
	require.NoError(t, err)

	// Truncate to various lengths below minimum.
	for _, l := range []int{0, 1, SaltLen, SaltLen + NonceLen - 1, SaltLen + NonceLen} {
		if l > len(encrypted) {
			continue
		}
		_, err := DecryptSeed(encrypted[:l], "pass")
		assert.Error(t, err, "len=%d should fail", l)
	}
}

func TestDecryptSeed_CorruptedSalt(t *testing.T) {
	seed := []byte("testing corrupted salt area")
	encrypted, err := EncryptSeed(seed, "mypassword")
	require.NoError(t, err)

	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[0] ^= 0xff // flip a bit in salt
	_, err = DecryptSeed(corrupted, "mypassword")
	assert.Error(t, err)
}

func TestDecryptSeed_CorruptedNonce(t *testing.T) {
	seed := []byte("testing corrupted nonce area")
	encrypted, err := EncryptSeed(seed, "pass")
	require.NoError(t, err)

	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[SaltLen] ^= 0xff // flip a bit in nonce
	_, err = DecryptSeed(corrupted, "pass")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// NewWallet — edge cases
// ---------------------------------------------------------------------------

func TestNewWallet_TestNet(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, &TestNet)
	require.NoError(t, err)
	assert.Equal(t, "testnet", w.Network().Name)
}

func TestNewWallet_RegTestUsesTestNetParams(t *testing.T) {
	mnemonic, err := GenerateMnemonic(Mnemonic12Words)
	require.NoError(t, err)
	seed, err := SeedFromMnemonic(mnemonic, "")
	require.NoError(t, err)

	w, err := NewWallet(seed, &RegTest)
	require.NoError(t, err)
	assert.Equal(t, "regtest", w.Network().Name)

	// Derivation should still work.
	kp, err := w.DeriveFeeKey(ExternalChain, 0)
	require.NoError(t, err)
	assert.NotNil(t, kp.PublicKey)
}

// ---------------------------------------------------------------------------
// DeriveNodeKey — mixed hardened arrays and path building
// ---------------------------------------------------------------------------

func TestDeriveNodeKey_AllNonHardened(t *testing.T) {
	w := makeWallet(t)
	path := []uint32{1, 2, 3}
	hardened := []bool{false, false, false}
	kp, err := w.DeriveNodeKey(0, path, hardened)
	require.NoError(t, err)
	assert.NotContains(t, kp.Path[len("m/44'/236'/1'/0/0"):], "'")
}

func TestDeriveNodeKey_MixedHardenedLonger(t *testing.T) {
	w := makeWallet(t)
	path := []uint32{1, 2, 3, 4, 5}
	hardened := []bool{true, false, true, false, true}
	kp, err := w.DeriveNodeKey(0, path, hardened)
	require.NoError(t, err)
	assert.NotEmpty(t, kp.Path)
	assert.NotNil(t, kp.PrivateKey)
}

func TestDeriveNodeKey_PartialHardenedShorterThanPath(t *testing.T) {
	w := makeWallet(t)
	// hardened array shorter than path — remaining should default to hardened.
	path := []uint32{1, 2, 3, 4}
	hardened := []bool{false, false} // only 2 elements for 4-element path
	kp, err := w.DeriveNodeKey(0, path, hardened)
	require.NoError(t, err)
	assert.NotNil(t, kp.PrivateKey)
}
