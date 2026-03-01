package method42

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genKP(t *testing.T) (*ec.PrivateKey, *ec.PublicKey) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	return priv, priv.PubKey()
}

// ---------------------------------------------------------------------------
// aesGCMEncrypt / aesGCMDecrypt — error branches
// ---------------------------------------------------------------------------

func TestAesGCMEncrypt_InvalidKeyLength(t *testing.T) {
	_, err := aesGCMEncrypt([]byte("hello"), make([]byte, 15), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AES cipher creation failed")
}

func TestAesGCMDecrypt_InvalidKeyLength(t *testing.T) {
	ct := make([]byte, MinCiphertextLen+1)
	_, err := aesGCMDecrypt(ct, make([]byte, 15), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestAesGCMEncrypt_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	ct, err := aesGCMEncrypt([]byte{}, key, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(ct), MinCiphertextLen)

	pt, err := aesGCMDecrypt(ct, key, nil)
	require.NoError(t, err)
	assert.Empty(t, pt)
}

func TestAesGCMDecrypt_ExactMinLength(t *testing.T) {
	ct := make([]byte, MinCiphertextLen)
	key := make([]byte, 32)
	_, err := aesGCMDecrypt(ct, key, nil)
	assert.Error(t, err)
}

func TestAesGCMDecrypt_NonceSizeEdge(t *testing.T) {
	key := make([]byte, 32)
	ct := make([]byte, MinCiphertextLen+1)
	_, err := aesGCMDecrypt(ct, key, nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Encrypt — error propagation branches
// ---------------------------------------------------------------------------

func TestEncrypt_NilPublicKey_AllModes(t *testing.T) {
	priv, _ := genKP(t)
	modes := []Access{AccessFree, AccessPrivate, AccessPaid}
	for _, mode := range modes {
		_, err := Encrypt([]byte("data"), priv, nil, mode)
		assert.ErrorIs(t, err, ErrNilPublicKey, "mode=%v", mode)
	}
}

func TestEncrypt_NilPrivateKey_RequiredModes(t *testing.T) {
	_, pub := genKP(t)
	for _, mode := range []Access{AccessPrivate, AccessPaid} {
		_, err := Encrypt([]byte("data"), nil, pub, mode)
		assert.ErrorIs(t, err, ErrNilPrivateKey, "mode=%v", mode)
	}
}

func TestEncrypt_FreeMode_NilPrivateKeyOK(t *testing.T) {
	_, pub := genKP(t)
	result, err := Encrypt([]byte("free content"), nil, pub, AccessFree)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
	assert.Len(t, result.KeyHash, 32)
}

// ---------------------------------------------------------------------------
// Decrypt — error propagation branches
// ---------------------------------------------------------------------------

func TestDecrypt_BadKeyHashLen(t *testing.T) {
	priv, pub := genKP(t)
	_, err := Decrypt(make([]byte, 64), priv, pub, make([]byte, 16), AccessFree)
	assert.ErrorIs(t, err, ErrKeyHashMismatch)
}

func TestDecrypt_NilPublicKey_AllModes(t *testing.T) {
	priv, _ := genKP(t)
	kh := make([]byte, 32)
	for _, mode := range []Access{AccessFree, AccessPrivate, AccessPaid} {
		_, err := Decrypt(make([]byte, 64), priv, nil, kh, mode)
		assert.ErrorIs(t, err, ErrNilPublicKey, "mode=%v", mode)
	}
}

func TestDecrypt_BadAccessMode(t *testing.T) {
	priv, pub := genKP(t)
	kh := make([]byte, 32)
	_, err := Decrypt(make([]byte, 64), priv, pub, kh, Access(99))
	assert.ErrorIs(t, err, ErrInvalidAccess)
}

func TestDecrypt_TooShortCiphertext(t *testing.T) {
	priv, pub := genKP(t)
	kh := ComputeKeyHash([]byte("x"))
	_, err := Decrypt(make([]byte, 5), priv, pub, kh, AccessFree)
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

func TestDecrypt_TamperedCiphertextAllModes(t *testing.T) {
	priv, pub := genKP(t)
	plaintext := []byte("secret data for all modes")

	for _, mode := range []Access{AccessFree, AccessPrivate, AccessPaid} {
		result, err := Encrypt(plaintext, priv, pub, mode)
		require.NoError(t, err)

		tampered := make([]byte, len(result.Ciphertext))
		copy(tampered, result.Ciphertext)
		tampered[len(tampered)-1] ^= 0xff

		_, err = Decrypt(tampered, priv, pub, result.KeyHash, mode)
		assert.Error(t, err, "mode=%v", mode)
	}
}

// ---------------------------------------------------------------------------
// DecryptWithCapsule — error branches
// ---------------------------------------------------------------------------

func TestDecryptWithCapsule_BadKeyHashLen(t *testing.T) {
	buyerPriv, _ := genKP(t)
	_, nodePub := genKP(t)
	// keyHash must be 32 bytes; 16 bytes should fail validation.
	_, err := DecryptWithCapsule(make([]byte, 64), make([]byte, 32), make([]byte, 16), buyerPriv, nodePub)
	assert.ErrorIs(t, err, ErrKeyHashMismatch)
}

func TestDecryptWithCapsule_BadCapsuleLen(t *testing.T) {
	buyerPriv, _ := genKP(t)
	_, nodePub := genKP(t)
	// capsule must be 32 bytes
	_, err := DecryptWithCapsule(make([]byte, 64), []byte("capsule"), make([]byte, 32), buyerPriv, nodePub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "capsule must be 32 bytes")
}

func TestDecryptWithCapsule_NilBuyerKey(t *testing.T) {
	_, nodePub := genKP(t)
	_, err := DecryptWithCapsule(make([]byte, 64), make([]byte, 32), make([]byte, 32), nil, nodePub)
	assert.ErrorIs(t, err, ErrNilPrivateKey)
}

func TestDecryptWithCapsule_NilNodePubKey(t *testing.T) {
	buyerPriv, _ := genKP(t)
	_, err := DecryptWithCapsule(make([]byte, 64), make([]byte, 32), make([]byte, 32), buyerPriv, nil)
	assert.ErrorIs(t, err, ErrNilPublicKey)
}

func TestDecryptWithCapsule_TooShortCiphertext(t *testing.T) {
	buyerPriv, _ := genKP(t)
	_, nodePub := genKP(t)
	_, err := DecryptWithCapsule(make([]byte, 5), make([]byte, 32), make([]byte, 32), buyerPriv, nodePub)
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

func TestDecryptWithCapsule_WrongCapsuleDecryptFails(t *testing.T) {
	priv, pub := genKP(t)
	result, err := Encrypt([]byte("paid content"), priv, pub, AccessPaid)
	require.NoError(t, err)

	buyer, err := ec.NewPrivateKey()
	require.NoError(t, err)
	capsule, err := ComputeCapsule(priv, pub, buyer.PubKey(), result.KeyHash)
	require.NoError(t, err)

	wrongCapsule := make([]byte, len(capsule))
	_, err = DecryptWithCapsule(result.Ciphertext, wrongCapsule, result.KeyHash, buyer, pub)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ECDH — x-coordinate padding
// ---------------------------------------------------------------------------

func TestECDH_OutputAlways32Bytes(t *testing.T) {
	for i := 0; i < 50; i++ {
		priv, pub := genKP(t)
		shared, err := ECDH(priv, pub)
		require.NoError(t, err)
		assert.Len(t, shared, 32, "iteration %d", i)
	}
}

func TestECDH_SymmetryMultiplePairs(t *testing.T) {
	for i := 0; i < 10; i++ {
		priv1, pub1 := genKP(t)
		priv2, pub2 := genKP(t)

		s1, err := ECDH(priv1, pub2)
		require.NoError(t, err)
		s2, err := ECDH(priv2, pub1)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(s1, s2), "iteration %d", i)
	}
}

// ---------------------------------------------------------------------------
// DeriveAESKey — edge cases
// ---------------------------------------------------------------------------

func TestDeriveAESKey_ZeroKeyHash(t *testing.T) {
	shared := make([]byte, 32)
	rand.Read(shared)
	kh := make([]byte, 32)

	key, err := DeriveAESKey(shared, kh)
	require.NoError(t, err)
	assert.Len(t, key, AESKeyLen)
}

func TestDeriveAESKey_MaxLengthSharedSecret(t *testing.T) {
	shared := make([]byte, 128)
	rand.Read(shared)
	kh := make([]byte, 32)
	rand.Read(kh)

	key, err := DeriveAESKey(shared, kh)
	require.NoError(t, err)
	assert.Len(t, key, AESKeyLen)
}

// ---------------------------------------------------------------------------
// Full roundtrip — all three modes
// ---------------------------------------------------------------------------

func TestFullRoundTrip_AllModes(t *testing.T) {
	priv, pub := genKP(t)
	plaintext := []byte("test all access modes roundtrip")

	for _, mode := range []Access{AccessFree, AccessPrivate, AccessPaid} {
		enc, err := Encrypt(plaintext, priv, pub, mode)
		require.NoError(t, err, "Encrypt mode=%v", mode)

		dec, err := Decrypt(enc.Ciphertext, priv, pub, enc.KeyHash, mode)
		require.NoError(t, err, "Decrypt mode=%v", mode)
		assert.Equal(t, plaintext, dec.Plaintext, "mode=%v", mode)
		assert.Equal(t, enc.KeyHash, dec.KeyHash, "mode=%v keyHash mismatch", mode)
	}
}

// ---------------------------------------------------------------------------
// R01-M1 — xorBytes panics on mismatched lengths
// ---------------------------------------------------------------------------

func TestXorBytes_MismatchedLengthsPanics(t *testing.T) {
	assert.PanicsWithValue(t,
		"method42: xorBytes called with mismatched lengths",
		func() { xorBytes([]byte{0x01, 0x02}, []byte{0x03}) },
		"xorBytes should panic when input lengths differ",
	)
}

func TestXorBytes_EqualLengths(t *testing.T) {
	a := []byte{0xff, 0x00, 0xaa}
	b := []byte{0x0f, 0xf0, 0x55}
	result := xorBytes(a, b)
	assert.Equal(t, []byte{0xf0, 0xf0, 0xff}, result)
}

func TestXorBytes_EmptySlices(t *testing.T) {
	result := xorBytes([]byte{}, []byte{})
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// R01-M2 — ComputeCapsuleHash returns nil for invalid fileTxID length
// ---------------------------------------------------------------------------

func TestComputeCapsuleHash_InvalidFileTxIDLength(t *testing.T) {
	capsule := bytes.Repeat([]byte{0xab}, 32)

	tests := []struct {
		name     string
		fileTxID []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short (16 bytes)", bytes.Repeat([]byte{0x01}, 16)},
		{"too long (33 bytes)", bytes.Repeat([]byte{0x01}, 33)},
		{"one byte", []byte{0x42}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputeCapsuleHash(tt.fileTxID, capsule)
			assert.Nil(t, result, "ComputeCapsuleHash should return nil for fileTxID of length %d", len(tt.fileTxID))
		})
	}
}

func TestComputeCapsuleHash_ValidFileTxID(t *testing.T) {
	fileTxID := bytes.Repeat([]byte{0xf0}, 32)
	capsule := bytes.Repeat([]byte{0xab}, 32)
	result := ComputeCapsuleHash(fileTxID, capsule)
	assert.NotNil(t, result)
	assert.Len(t, result, 32)
}

// ---------------------------------------------------------------------------
// R01-M3 — ComputeCapsuleWithNonce rejects invalid keyHash length
// ---------------------------------------------------------------------------

func TestComputeCapsuleWithNonce_InvalidKeyHashLength(t *testing.T) {
	nodePriv, nodePub := genKP(t)
	_, buyerPub := genKP(t)

	tests := []struct {
		name    string
		keyHash []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"16 bytes", bytes.Repeat([]byte{0x01}, 16)},
		{"33 bytes", bytes.Repeat([]byte{0x01}, 33)},
		{"64 bytes", bytes.Repeat([]byte{0x01}, 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ComputeCapsuleWithNonce(nodePriv, nodePub, buyerPub, tt.keyHash, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "keyHash must be 32 bytes")
		})
	}
}

// ---------------------------------------------------------------------------
// R01-M4 — RabinSign bounded iteration (structural test)
// ---------------------------------------------------------------------------

func TestRabinSign_MaxIterationsConstant(t *testing.T) {
	// Verify the constant exists and has a reasonable value.
	assert.Equal(t, 1_000_000, maxRabinPaddingIterations,
		"maxRabinPaddingIterations should be 1,000,000")
}

// ---------------------------------------------------------------------------
// R01-M5 — GenerateRabinKey rejects p == q
// ---------------------------------------------------------------------------

func TestGenerateRabinKey_ProducesDistinctPrimes(t *testing.T) {
	// Run multiple times to increase confidence (the p == q path is
	// astronomically unlikely with real crypto/rand, but we verify the
	// structural property that p != q holds).
	for i := 0; i < 5; i++ {
		key, err := GenerateRabinKey(512)
		require.NoError(t, err)
		assert.NotEqual(t, 0, key.P.Cmp(key.Q),
			"generated primes p and q must differ (iteration %d)", i)
		// Verify n = p * q
		expected := new(big.Int).Mul(key.P, key.Q)
		assert.Equal(t, 0, expected.Cmp(key.N))
	}
}

// ---------------------------------------------------------------------------
// R01-M6 — aesGCMEncrypt does NOT wrap ErrDecryptionFailed
// ---------------------------------------------------------------------------

func TestAesGCMEncrypt_ErrorNotDecryptionFailed(t *testing.T) {
	// Trigger an error in aesGCMEncrypt by using an invalid key length.
	_, err := aesGCMEncrypt([]byte("data"), make([]byte, 15), nil)
	require.Error(t, err)

	// The error should NOT wrap ErrDecryptionFailed (that was the M6 bug).
	assert.False(t, errors.Is(err, ErrDecryptionFailed),
		"aesGCMEncrypt error should not wrap ErrDecryptionFailed; got: %v", err)

	// It should contain the correct message.
	assert.Contains(t, err.Error(), "AES cipher creation failed")
}

func TestAesGCMDecrypt_ErrorIsDecryptionFailed(t *testing.T) {
	// In contrast, aesGCMDecrypt errors SHOULD wrap ErrDecryptionFailed.
	ct := make([]byte, MinCiphertextLen+1)
	_, err := aesGCMDecrypt(ct, make([]byte, 15), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed),
		"aesGCMDecrypt error should wrap ErrDecryptionFailed; got: %v", err)
}
