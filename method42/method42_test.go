package method42

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// --- Helper functions ---

func generateKeyPair(t *testing.T) (*ec.PrivateKey, *ec.PublicKey) {
	t.Helper()
	privKey, err := ec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()
	require.NotNil(t, pubKey)
	return privKey, pubKey
}

// --- ComputeKeyHash tests ---

func TestComputeKeyHash(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty input", []byte{}},
		{"hello world", []byte("hello world")},
		{"binary data", []byte{0x00, 0x01, 0xff, 0xfe}},
		{"large input", bytes.Repeat([]byte("a"), 1024*1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := ComputeKeyHash(tt.plaintext)
			assert.Len(t, hash, 32, "key hash should be 32 bytes")

			// Verify it's actually double-SHA256
			first := sha256.Sum256(tt.plaintext)
			second := sha256.Sum256(first[:])
			assert.Equal(t, second[:], hash, "should be SHA256(SHA256(plaintext))")
		})
	}
}

func TestComputeKeyHash_Deterministic(t *testing.T) {
	plaintext := []byte("deterministic test data")
	hash1 := ComputeKeyHash(plaintext)
	hash2 := ComputeKeyHash(plaintext)
	assert.Equal(t, hash1, hash2, "same input should produce same hash")
}

func TestComputeKeyHash_DifferentInputs(t *testing.T) {
	hash1 := ComputeKeyHash([]byte("input a"))
	hash2 := ComputeKeyHash([]byte("input b"))
	assert.NotEqual(t, hash1, hash2, "different inputs should produce different hashes")
}

// --- ECDH tests ---

func TestECDH(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)

	shared, err := ECDH(privKey, pubKey)
	require.NoError(t, err)
	assert.Len(t, shared, 32, "shared secret should be 32 bytes")
}

func TestECDH_Symmetry(t *testing.T) {
	// ECDH(D_a, P_b) == ECDH(D_b, P_a)
	privA, pubA := generateKeyPair(t)
	privB, pubB := generateKeyPair(t)

	sharedAB, err := ECDH(privA, pubB)
	require.NoError(t, err)

	sharedBA, err := ECDH(privB, pubA)
	require.NoError(t, err)

	assert.Equal(t, sharedAB, sharedBA, "ECDH should be symmetric")
}

func TestECDH_Deterministic(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)

	shared1, err := ECDH(privKey, pubKey)
	require.NoError(t, err)

	shared2, err := ECDH(privKey, pubKey)
	require.NoError(t, err)

	assert.Equal(t, shared1, shared2, "same keys should produce same shared secret")
}

func TestECDH_NilPrivateKey(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	_, err := ECDH(nil, pubKey)
	assert.ErrorIs(t, err, ErrNilPrivateKey)
}

func TestECDH_NilPublicKey(t *testing.T) {
	privKey, _ := generateKeyPair(t)
	_, err := ECDH(privKey, nil)
	assert.ErrorIs(t, err, ErrNilPublicKey)
}

func TestECDH_DifferentKeys(t *testing.T) {
	privA, _ := generateKeyPair(t)
	_, pubB := generateKeyPair(t)
	_, pubC := generateKeyPair(t)

	sharedAB, err := ECDH(privA, pubB)
	require.NoError(t, err)

	sharedAC, err := ECDH(privA, pubC)
	require.NoError(t, err)

	assert.NotEqual(t, sharedAB, sharedAC, "different public keys should produce different shared secrets")
}

// --- FreePrivateKey tests ---

func TestFreePrivateKey(t *testing.T) {
	freeKey := FreePrivateKey()
	require.NotNil(t, freeKey)

	// Scalar value should be 1
	assert.Equal(t, int64(1), freeKey.D.Int64(), "free key scalar should be 1")
}

func TestFreePrivateKey_ECDHEqualsPublicKey(t *testing.T) {
	// ECDH(1, P) should return P.x
	_, pubKey := generateKeyPair(t)
	freeKey := FreePrivateKey()

	shared, err := ECDH(freeKey, pubKey)
	require.NoError(t, err)

	// shared should equal pubKey.X (32 bytes, zero-padded)
	xBytes := pubKey.X.Bytes()
	expected := make([]byte, 32)
	copy(expected[32-len(xBytes):], xBytes)

	assert.Equal(t, expected, shared, "ECDH(1, P) should return P.x")
}

// --- DeriveAESKey tests ---

func TestDeriveAESKey(t *testing.T) {
	sharedX := bytes.Repeat([]byte{0xab}, 32)
	keyHash := bytes.Repeat([]byte{0xcd}, 32)

	key, err := DeriveAESKey(sharedX, keyHash)
	require.NoError(t, err)
	assert.Len(t, key, 32, "AES key should be 32 bytes")
}

func TestDeriveAESKey_Deterministic(t *testing.T) {
	sharedX := bytes.Repeat([]byte{0x01}, 32)
	keyHash := bytes.Repeat([]byte{0x02}, 32)

	key1, err := DeriveAESKey(sharedX, keyHash)
	require.NoError(t, err)

	key2, err := DeriveAESKey(sharedX, keyHash)
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "same inputs should produce same key")
}

func TestDeriveAESKey_DifferentSalt(t *testing.T) {
	sharedX := bytes.Repeat([]byte{0x01}, 32)
	keyHash1 := bytes.Repeat([]byte{0x02}, 32)
	keyHash2 := bytes.Repeat([]byte{0x03}, 32)

	key1, err := DeriveAESKey(sharedX, keyHash1)
	require.NoError(t, err)

	key2, err := DeriveAESKey(sharedX, keyHash2)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different salts should produce different keys")
}

func TestDeriveAESKey_EmptySharedSecret(t *testing.T) {
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	_, err := DeriveAESKey([]byte{}, keyHash)
	assert.ErrorIs(t, err, ErrHKDFFailure)
}

func TestDeriveAESKey_InvalidKeyHashLength(t *testing.T) {
	sharedX := bytes.Repeat([]byte{0x01}, 32)
	_, err := DeriveAESKey(sharedX, []byte{0x01, 0x02}) // too short
	assert.ErrorIs(t, err, ErrHKDFFailure)
}

// --- AES-GCM encrypt/decrypt tests ---

func TestAESGCM_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("hello")},
		{"medium", bytes.Repeat([]byte("test"), 1000)},
		{"binary", []byte{0x00, 0x01, 0xff, 0xfe, 0x80}},
	}

	key := bytes.Repeat([]byte{0xab}, 32)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := aesGCMEncrypt(tt.plaintext, key)
			require.NoError(t, err)
			assert.Greater(t, len(ciphertext), len(tt.plaintext), "ciphertext should be longer due to nonce+tag")

			decrypted, err := aesGCMDecrypt(ciphertext, key)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted, "round-trip should preserve plaintext")
		})
	}
}

func TestAESGCM_DifferentNonces(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	plaintext := []byte("same plaintext")

	ct1, err := aesGCMEncrypt(plaintext, key)
	require.NoError(t, err)

	ct2, err := aesGCMEncrypt(plaintext, key)
	require.NoError(t, err)

	// Ciphertexts should differ due to random nonce
	assert.NotEqual(t, ct1, ct2, "same plaintext should produce different ciphertexts due to random nonce")
}

func TestAESGCM_WrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0xab}, 32)
	key2 := bytes.Repeat([]byte{0xcd}, 32)
	plaintext := []byte("secret data")

	ciphertext, err := aesGCMEncrypt(plaintext, key1)
	require.NoError(t, err)

	_, err = aesGCMDecrypt(ciphertext, key2)
	assert.ErrorIs(t, err, ErrDecryptionFailed, "wrong key should fail decryption")
}

func TestAESGCM_TamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	plaintext := []byte("authentic data")

	ciphertext, err := aesGCMEncrypt(plaintext, key)
	require.NoError(t, err)

	// Tamper with the ciphertext (after nonce, before tag)
	if len(ciphertext) > NonceLen+1 {
		ciphertext[NonceLen+1] ^= 0xff
	}

	_, err = aesGCMDecrypt(ciphertext, key)
	assert.ErrorIs(t, err, ErrDecryptionFailed, "tampered ciphertext should fail authentication")
}

func TestAESGCM_TooShort(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	_, err := aesGCMDecrypt([]byte{0x01, 0x02, 0x03}, key) // way too short
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

// --- Full Encrypt/Decrypt tests ---

func TestEncrypt_AccessFree(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	plaintext := []byte("free content for everyone")

	result, err := Encrypt(plaintext, nil, pubKey, AccessFree)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
	assert.Len(t, result.KeyHash, 32)
}

func TestEncrypt_AccessPrivate(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("private owner-only content")

	result, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
	assert.Len(t, result.KeyHash, 32)
}

func TestEncrypt_AccessPaid(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("premium paid content")

	result, err := Encrypt(plaintext, privKey, pubKey, AccessPaid)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
}

func TestDecrypt_AccessFree_RoundTrip(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	plaintext := []byte("free content round trip")

	encResult, err := Encrypt(plaintext, nil, pubKey, AccessFree)
	require.NoError(t, err)

	decResult, err := Decrypt(encResult.Ciphertext, nil, pubKey, encResult.KeyHash, AccessFree)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
	assert.Equal(t, encResult.KeyHash, decResult.KeyHash)
}

func TestDecrypt_AccessPrivate_RoundTrip(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("private content round trip")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	decResult, err := Decrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestDecrypt_AccessPaid_RoundTrip(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("paid content round trip")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPaid)
	require.NoError(t, err)

	decResult, err := Decrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPaid)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestDecrypt_WrongKeyHash(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("test content")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// Use wrong key hash
	wrongHash := bytes.Repeat([]byte{0xff}, 32)
	_, err = Decrypt(encResult.Ciphertext, privKey, pubKey, wrongHash, AccessPrivate)
	// This should fail because wrong key_hash leads to wrong AES key
	assert.Error(t, err)
}

func TestDecrypt_NilPublicKey(t *testing.T) {
	privKey, _ := generateKeyPair(t)
	_, err := Decrypt([]byte("dummy"), privKey, nil, bytes.Repeat([]byte{0x01}, 32), AccessPrivate)
	assert.ErrorIs(t, err, ErrNilPublicKey)
}

func TestDecrypt_NilPrivateKey_Private(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	_, err := Decrypt([]byte("dummy"), nil, pubKey, bytes.Repeat([]byte{0x01}, 32), AccessPrivate)
	assert.ErrorIs(t, err, ErrNilPrivateKey)
}

// --- DecryptWithCapsule tests ---

func TestDecryptWithCapsule(t *testing.T) {
	nodePriv, nodePub := generateKeyPair(t)
	buyerPriv, buyerPub := generateKeyPair(t)
	plaintext := []byte("paid content for buyer")

	// Owner encrypts with PAID mode (same key derivation as PRIVATE)
	encResult, err := Encrypt(plaintext, nodePriv, nodePub, AccessPaid)
	require.NoError(t, err)

	// Seller computes XOR-masked capsule for buyer:
	// capsule = aes_key XOR buyer_mask
	capsule, err := ComputeCapsule(nodePriv, nodePub, buyerPub, encResult.KeyHash)
	require.NoError(t, err)

	// Verify capsule hash works for HTLC
	capsuleHash := ComputeCapsuleHash(capsule)
	assert.Len(t, capsuleHash, 32)

	// Buyer verifies the capsule matches the hash
	recomputedHash := ComputeCapsuleHash(capsule)
	assert.Equal(t, capsuleHash, recomputedHash)

	// Buyer decrypts with capsule using their private key + node's public key.
	// buyer_mask = HKDF(ECDH(D_buyer, P_node).x, key_hash, "bitfs-buyer-mask")
	// aes_key = capsule XOR buyer_mask
	decResult, err := DecryptWithCapsule(encResult.Ciphertext, capsule, encResult.KeyHash, buyerPriv, nodePub)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestDecryptWithCapsule_EmptyCapsule(t *testing.T) {
	buyerPriv, _ := generateKeyPair(t)
	_, nodePub := generateKeyPair(t)
	_, err := DecryptWithCapsule([]byte("ct"), []byte{}, bytes.Repeat([]byte{0x01}, 32), buyerPriv, nodePub)
	assert.Error(t, err)
}

func TestDecryptWithCapsule_WrongCapsule(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	buyerPriv, _ := generateKeyPair(t)
	plaintext := []byte("test content")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// Use wrong capsule — buyer_mask XOR wrong_capsule != correct aes_key
	wrongCapsule := bytes.Repeat([]byte{0xab}, 32)
	_, err = DecryptWithCapsule(encResult.Ciphertext, wrongCapsule, encResult.KeyHash, buyerPriv, pubKey)
	assert.Error(t, err, "wrong capsule should fail decryption")
}

// --- ReEncrypt tests ---

func TestReEncrypt_FreeToPrivate(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("originally free content")

	// Encrypt as FREE
	freeResult, err := Encrypt(plaintext, nil, pubKey, AccessFree)
	require.NoError(t, err)

	// Re-encrypt as PRIVATE
	privResult, err := ReEncrypt(freeResult.Ciphertext, privKey, pubKey, freeResult.KeyHash, AccessFree, AccessPrivate)
	require.NoError(t, err)

	// Verify the new ciphertext can be decrypted with PRIVATE mode
	decResult, err := Decrypt(privResult.Ciphertext, privKey, pubKey, privResult.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)

	// Verify the old FREE ciphertext can still be decrypted
	decOld, err := Decrypt(freeResult.Ciphertext, nil, pubKey, freeResult.KeyHash, AccessFree)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decOld.Plaintext)
}

func TestReEncrypt_PrivateToFree(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("originally private content")

	// Encrypt as PRIVATE
	privResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// Re-encrypt as FREE
	freeResult, err := ReEncrypt(privResult.Ciphertext, privKey, pubKey, privResult.KeyHash, AccessPrivate, AccessFree)
	require.NoError(t, err)

	// Verify anyone can decrypt with FREE mode (no private key needed)
	decResult, err := Decrypt(freeResult.Ciphertext, nil, pubKey, freeResult.KeyHash, AccessFree)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestReEncrypt_NewKeyHash(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("content being re-encrypted")

	freeResult, err := Encrypt(plaintext, nil, pubKey, AccessFree)
	require.NoError(t, err)

	privResult, err := ReEncrypt(freeResult.Ciphertext, privKey, pubKey, freeResult.KeyHash, AccessFree, AccessPrivate)
	require.NoError(t, err)

	// Key hash should be the same (same plaintext content)
	assert.Equal(t, freeResult.KeyHash, privResult.KeyHash, "same content should produce same key hash")
}

// --- Access mode tests ---

func TestAccess_String(t *testing.T) {
	assert.Equal(t, "PRIVATE", AccessPrivate.String())
	assert.Equal(t, "FREE", AccessFree.String())
	assert.Equal(t, "PAID", AccessPaid.String())
	assert.Equal(t, "UNKNOWN", Access(99).String())
}

func TestEncrypt_InvalidAccess(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	_, err := Encrypt([]byte("test"), nil, pubKey, Access(99))
	assert.ErrorIs(t, err, ErrInvalidAccess)
}

// --- CapsuleHash tests ---

func TestComputeCapsuleHash(t *testing.T) {
	capsule := bytes.Repeat([]byte{0xab}, 32)
	hash := ComputeCapsuleHash(capsule)
	assert.Len(t, hash, 32)

	// Should be standard SHA256
	expected := sha256.Sum256(capsule)
	assert.Equal(t, expected[:], hash)
}

func TestComputeCapsuleHash_Deterministic(t *testing.T) {
	capsule := []byte("test capsule data")
	hash1 := ComputeCapsuleHash(capsule)
	hash2 := ComputeCapsuleHash(capsule)
	assert.Equal(t, hash1, hash2)
}

// --- Integration: Full encryption flow ---

func TestFullEncryptionFlow_Private(t *testing.T) {
	// Simulates the complete flow: create file -> encrypt -> store -> retrieve -> decrypt
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("This is a private document stored on the BitFS blockchain.")

	// 1. Encrypt
	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// 2. Store ciphertext and key_hash (would go to storage and Metanet tx)
	storedCiphertext := encResult.Ciphertext
	storedKeyHash := encResult.KeyHash

	// 3. Later: Retrieve and decrypt
	decResult, err := Decrypt(storedCiphertext, privKey, pubKey, storedKeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestFullEncryptionFlow_FreeThenBuy(t *testing.T) {
	// Simulates: owner creates paid file -> buyer purchases via HTLC
	ownerPriv, ownerPub := generateKeyPair(t)
	buyerPriv, buyerPub := generateKeyPair(t)

	plaintext := []byte("Premium article about blockchain technology.")

	// 1. Owner encrypts as PRIVATE (will sell)
	encResult, err := Encrypt(plaintext, ownerPriv, ownerPub, AccessPrivate)
	require.NoError(t, err)

	// 2. Buyer initiates purchase. Seller computes XOR-masked capsule:
	// capsule = aes_key XOR buyer_mask
	capsule, err := ComputeCapsule(ownerPriv, ownerPub, buyerPub, encResult.KeyHash)
	require.NoError(t, err)

	// 3. Seller provides capsule_hash for HTLC
	capsuleHash := ComputeCapsuleHash(capsule)
	assert.Len(t, capsuleHash, 32)

	// 4. After HTLC is resolved, buyer gets capsule
	// 5. Buyer decrypts with capsule using their private key
	decResult, err := DecryptWithCapsule(encResult.Ciphertext, capsule, encResult.KeyHash, buyerPriv, ownerPub)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)

	result, err := Encrypt([]byte{}, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	decResult, err := Decrypt(result.Ciphertext, privKey, pubKey, result.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Empty(t, decResult.Plaintext)
}

func TestEncrypt_LargePlaintext(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := bytes.Repeat([]byte("large content "), 10000) // ~140KB

	result, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	decResult, err := Decrypt(result.Ciphertext, privKey, pubKey, result.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

// =============================================================================
// Supplementary tests — added to close AUDIT.md coverage gaps
// =============================================================================

// --- Gap 4 (MOST CRITICAL): ErrKeyHashMismatch post-AES content integrity ---

func TestDecrypt_KeyHashMismatch_ContentIntegrity(t *testing.T) {
	// To trigger post-decryption integrity check in DecryptWithCapsule,
	// AES decryption must succeed but ComputeKeyHash(plaintext) != keyHash.
	//
	// Strategy with XOR capsule:
	//  1. Choose plaintext, compute its real keyHash.
	//  2. Choose a fake keyHash (32 bytes, different from real).
	//  3. Generate buyer/node keypairs, compute buyerMask from fakeKeyHash.
	//  4. Derive an AES key from fakeKeyHash, encrypt plaintext with it.
	//  5. Construct capsule = aesKey XOR buyerMask.
	//  6. Call DecryptWithCapsule — AES succeeds but integrity check fails.
	plaintext := []byte("content for integrity check")
	realKeyHash := ComputeKeyHash(plaintext)

	buyerPriv, buyerPub := generateKeyPair(t)
	nodePriv, nodePub := generateKeyPair(t)

	// Fabricate a fake keyHash that differs from the real one
	fakeKeyHash := bytes.Repeat([]byte{0xaa}, 32)
	require.NotEqual(t, realKeyHash, fakeKeyHash, "sanity: fake must differ from real")

	// Compute buyerMask as DecryptWithCapsule will
	sharedBuyer, err := ECDH(buyerPriv, nodePub)
	require.NoError(t, err)
	buyerMask, err := DeriveBuyerMask(sharedBuyer, fakeKeyHash)
	require.NoError(t, err)

	// Derive AES key from node's self-ECDH with fakeKeyHash
	sharedNode, err := ECDH(nodePriv, nodePub)
	require.NoError(t, err)
	aesKey, err := DeriveAESKey(sharedNode, fakeKeyHash)
	require.NoError(t, err)

	// Encrypt plaintext directly with that AES key
	ciphertext, err := aesGCMEncrypt(plaintext, aesKey)
	require.NoError(t, err)

	// Construct capsule = aesKey XOR buyerMask (what ComputeCapsule would produce)
	// Also need to use the ECDH(D_node, P_buyer) shared secret for buyerMask
	sharedNodeBuyer, err := ECDH(nodePriv, buyerPub)
	require.NoError(t, err)
	buyerMaskFromNode, err := DeriveBuyerMask(sharedNodeBuyer, fakeKeyHash)
	require.NoError(t, err)
	// ECDH symmetry: buyerMask == buyerMaskFromNode
	require.Equal(t, buyerMask, buyerMaskFromNode, "ECDH symmetry check")

	capsule := xorBytes(aesKey, buyerMask)

	// Now DecryptWithCapsule: AES will succeed (capsule XOR buyerMask = aesKey),
	// but integrity check fails because SHA256(SHA256(plaintext)) != fakeKeyHash.
	_, err = DecryptWithCapsule(ciphertext, capsule, fakeKeyHash, buyerPriv, nodePub)
	assert.ErrorIs(t, err, ErrKeyHashMismatch,
		"should return ErrKeyHashMismatch when AES succeeds but content hash differs")
}

func TestDecrypt_KeyHashMismatch_ViaDecrypt(t *testing.T) {
	// Same strategy as above but via the Decrypt function.
	// Use AccessFree so the effective private key is FreePrivateKey() (scalar 1),
	// meaning ECDH(1, P) = P.x. We can predict the shared secret.
	_, pubKey := generateKeyPair(t)
	plaintext := []byte("integrity test via Decrypt")
	realKeyHash := ComputeKeyHash(plaintext)

	// The shared secret for Free mode is just pubKey.X (32 bytes, zero-padded)
	freeKey := FreePrivateKey()
	sharedX, err := ECDH(freeKey, pubKey)
	require.NoError(t, err)

	// Fabricate a fake keyHash
	fakeKeyHash := bytes.Repeat([]byte{0xbb}, 32)
	require.NotEqual(t, realKeyHash, fakeKeyHash)

	// Derive AES key from (sharedX, fakeKeyHash) — same as Decrypt will do
	aesKey, err := DeriveAESKey(sharedX, fakeKeyHash)
	require.NoError(t, err)

	// Encrypt directly with that key
	ciphertext, err := aesGCMEncrypt(plaintext, aesKey)
	require.NoError(t, err)

	// Decrypt expects AES to succeed (because key matches), then integrity fails
	_, err = Decrypt(ciphertext, nil, pubKey, fakeKeyHash, AccessFree)
	assert.ErrorIs(t, err, ErrKeyHashMismatch,
		"should return ErrKeyHashMismatch from Decrypt when content hash diverges")
}

// --- Gap 7: ReEncrypt mode transitions Private->Paid and Paid->Free ---

func TestReEncrypt_PrivateToPaid(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("private content becoming paid")

	// Encrypt as PRIVATE
	privResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// Re-encrypt as PAID
	paidResult, err := ReEncrypt(privResult.Ciphertext, privKey, pubKey, privResult.KeyHash, AccessPrivate, AccessPaid)
	require.NoError(t, err)

	// Verify the new ciphertext decrypts in PAID mode
	decResult, err := Decrypt(paidResult.Ciphertext, privKey, pubKey, paidResult.KeyHash, AccessPaid)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)

	// Key hash should be preserved (same plaintext)
	assert.Equal(t, privResult.KeyHash, paidResult.KeyHash)
}

func TestReEncrypt_PaidToFree(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("paid content becoming free")

	// Encrypt as PAID
	paidResult, err := Encrypt(plaintext, privKey, pubKey, AccessPaid)
	require.NoError(t, err)

	// Re-encrypt as FREE
	freeResult, err := ReEncrypt(paidResult.Ciphertext, privKey, pubKey, paidResult.KeyHash, AccessPaid, AccessFree)
	require.NoError(t, err)

	// Verify anyone can decrypt with FREE mode (no private key needed)
	decResult, err := Decrypt(freeResult.Ciphertext, nil, pubKey, freeResult.KeyHash, AccessFree)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)
}

// --- Gap 1: Decrypt with invalid access mode ---

func TestDecrypt_InvalidAccess(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("test content for invalid access decrypt")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	_, err = Decrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, Access(99))
	assert.ErrorIs(t, err, ErrInvalidAccess,
		"Decrypt should return ErrInvalidAccess for unknown access mode")
}

// --- Gap 2: DecryptWithCapsule invalid keyHash length ---

func TestDecryptWithCapsule_InvalidKeyHashLength(t *testing.T) {
	tests := []struct {
		name    string
		keyHash []byte
	}{
		{"empty keyHash", []byte{}},
		{"16 bytes", bytes.Repeat([]byte{0x01}, 16)},
		{"31 bytes", bytes.Repeat([]byte{0x01}, 31)},
		{"33 bytes", bytes.Repeat([]byte{0x01}, 33)},
	}

	capsule := bytes.Repeat([]byte{0xab}, 32)
	ciphertext := bytes.Repeat([]byte{0x00}, MinCiphertextLen) // dummy ciphertext
	buyerPriv, _ := generateKeyPair(t)
	_, nodePub := generateKeyPair(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptWithCapsule(ciphertext, capsule, tt.keyHash, buyerPriv, nodePub)
			assert.ErrorIs(t, err, ErrKeyHashMismatch,
				"DecryptWithCapsule should return ErrKeyHashMismatch for non-32-byte keyHash")
		})
	}
}

// --- Gap 3: Decrypt invalid keyHash length ---

func TestDecrypt_InvalidKeyHashLength(t *testing.T) {
	tests := []struct {
		name    string
		keyHash []byte
	}{
		{"nil keyHash", nil},
		{"empty keyHash", []byte{}},
		{"16 bytes", bytes.Repeat([]byte{0x01}, 16)},
		{"31 bytes", bytes.Repeat([]byte{0x01}, 31)},
		{"33 bytes", bytes.Repeat([]byte{0x01}, 33)},
	}

	privKey, pubKey := generateKeyPair(t)
	ciphertext := bytes.Repeat([]byte{0x00}, MinCiphertextLen)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(ciphertext, privKey, pubKey, tt.keyHash, AccessPrivate)
			assert.ErrorIs(t, err, ErrKeyHashMismatch,
				"Decrypt should return ErrKeyHashMismatch for non-32-byte keyHash")
		})
	}
}

// --- Gap 8: Encrypt nil public key ---

func TestEncrypt_NilPublicKey(t *testing.T) {
	privKey, _ := generateKeyPair(t)

	tests := []struct {
		name   string
		access Access
	}{
		{"private mode", AccessPrivate},
		{"paid mode", AccessPaid},
		{"free mode", AccessFree},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encrypt([]byte("test"), privKey, nil, tt.access)
			assert.ErrorIs(t, err, ErrNilPublicKey,
				"Encrypt should return ErrNilPublicKey when publicKey is nil")
		})
	}
}

// --- Gap 9: ComputeCapsule nil arguments ---

func TestComputeCapsule_NilPrivateKey(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	_, err := ComputeCapsule(nil, pubKey, pubKey, keyHash)
	assert.Error(t, err,
		"ComputeCapsule should fail when nodePrivateKey is nil")
}

func TestComputeCapsule_NilNodePublicKey(t *testing.T) {
	privKey, _ := generateKeyPair(t)
	_, buyerPub := generateKeyPair(t)
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	_, err := ComputeCapsule(privKey, nil, buyerPub, keyHash)
	assert.Error(t, err,
		"ComputeCapsule should fail when nodePublicKey is nil")
}

func TestComputeCapsule_NilBuyerPublicKey(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	_, err := ComputeCapsule(privKey, pubKey, nil, keyHash)
	assert.Error(t, err,
		"ComputeCapsule should fail when buyerPublicKey is nil")
}

// --- Gap 11: ECDH x-coordinate always 32 bytes (zero-padding branch) ---

func TestECDH_XCoordinateAlways32Bytes(t *testing.T) {
	// Run ECDH on many random keys and verify the output is always exactly
	// 32 bytes. This is a statistical test to exercise the zero-padding path
	// at ecdh.go:36-40 (may trigger if x-coordinate < 32 bytes).
	const iterations = 200
	for i := 0; i < iterations; i++ {
		privKey, pubKey := generateKeyPair(t)
		shared, err := ECDH(privKey, pubKey)
		require.NoError(t, err)
		assert.Len(t, shared, 32, "ECDH output must always be exactly 32 bytes (iteration %d)", i)
	}
}

// --- Gap 5: ReEncrypt error propagation from decrypt phase ---

func TestReEncrypt_InvalidCiphertext(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	shortCiphertext := []byte{0x01, 0x02, 0x03} // way too short
	keyHash := bytes.Repeat([]byte{0x01}, 32)

	_, err := ReEncrypt(shortCiphertext, privKey, pubKey, keyHash, AccessPrivate, AccessFree)
	assert.Error(t, err, "ReEncrypt should propagate ErrInvalidCiphertext from Decrypt")
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

// --- Gap 6: ReEncrypt error propagation from encrypt phase (invalid toAccess) ---

func TestReEncrypt_InvalidToAccess(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("content for invalid toAccess test")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	_, err = ReEncrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPrivate, Access(99))
	assert.ErrorIs(t, err, ErrInvalidAccess,
		"ReEncrypt should return ErrInvalidAccess when toAccess is invalid")
}

func TestReEncrypt_InvalidFromAccess(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	ciphertext := bytes.Repeat([]byte{0x00}, MinCiphertextLen+10)

	_, err := ReEncrypt(ciphertext, privKey, pubKey, keyHash, Access(99), AccessFree)
	assert.ErrorIs(t, err, ErrInvalidAccess,
		"ReEncrypt should return ErrInvalidAccess when fromAccess is invalid")
}

// --- Gap 10: DeriveAESKey different shared secrets ---

func TestDeriveAESKey_DifferentSharedSecret(t *testing.T) {
	keyHash := bytes.Repeat([]byte{0x01}, 32)
	sharedX1 := bytes.Repeat([]byte{0xaa}, 32)
	sharedX2 := bytes.Repeat([]byte{0xbb}, 32)

	key1, err := DeriveAESKey(sharedX1, keyHash)
	require.NoError(t, err)

	key2, err := DeriveAESKey(sharedX2, keyHash)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2,
		"different shared secrets with same key_hash should produce different AES keys")
}

// --- Gap 12: Minimal ciphertext (empty plaintext via AES-GCM) ---

func TestAESGCM_MinimalCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)

	// Encrypt empty plaintext
	ciphertext, err := aesGCMEncrypt([]byte{}, key)
	require.NoError(t, err)

	// Ciphertext should be exactly 28 bytes: 12 (nonce) + 16 (GCM tag)
	assert.Len(t, ciphertext, MinCiphertextLen,
		"empty plaintext should produce exactly nonce+tag bytes")

	// Decrypt should succeed and return empty
	plaintext, err := aesGCMDecrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Empty(t, plaintext)
}

// --- Gap 13: DeriveAESKey HKDF info constant verification ---

func TestDeriveAESKey_HKDFInfoConstant(t *testing.T) {
	// Verify the HKDFInfo constant has the expected value
	assert.Equal(t, "bitfs-file-encryption", HKDFInfo,
		"HKDFInfo constant must equal 'bitfs-file-encryption'")
}

func TestDeriveAESKey_HKDFInfoAffectsOutput(t *testing.T) {
	// Verify that the HKDF info string is actually used in key derivation.
	// Compute a reference key using DeriveAESKey, then manually derive with
	// a different info string and show the results differ.
	sharedX := bytes.Repeat([]byte{0x42}, 32)
	keyHash := bytes.Repeat([]byte{0x24}, 32)

	derivedKey, err := DeriveAESKey(sharedX, keyHash)
	require.NoError(t, err)
	require.Len(t, derivedKey, 32)

	// Manually derive with a different info to prove the constant matters
	wrongInfoKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, sharedX, keyHash, []byte("wrong-info-string"))
	_, err = io.ReadFull(hkdfReader, wrongInfoKey)
	require.NoError(t, err)

	assert.NotEqual(t, derivedKey, wrongInfoKey,
		"DeriveAESKey output should differ when info string changes, proving HKDFInfo is used")

	// Also verify the key matches the expected output with the correct info
	correctInfoKey := make([]byte, 32)
	hkdfReader2 := hkdf.New(sha256.New, sharedX, keyHash, []byte(HKDFInfo))
	_, err = io.ReadFull(hkdfReader2, correctInfoKey)
	require.NoError(t, err)

	assert.Equal(t, derivedKey, correctInfoKey,
		"DeriveAESKey output should match manual HKDF with the same info string")
}

// --- Exported constants assertions ---

func TestExportedConstants(t *testing.T) {
	assert.Equal(t, 12, NonceLen, "NonceLen must be 12")
	assert.Equal(t, 16, GCMTagLen, "GCMTagLen must be 16")
	assert.Equal(t, 28, MinCiphertextLen, "MinCiphertextLen must be NonceLen + GCMTagLen = 28")
	assert.Equal(t, 32, AESKeyLen, "AESKeyLen must be 32")
}

// --- Edge cases from AUDIT.md ---

func TestEncrypt_NilPrivateKey_PaidMode(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	_, err := Encrypt([]byte("paid content"), nil, pubKey, AccessPaid)
	assert.ErrorIs(t, err, ErrNilPrivateKey,
		"Encrypt with AccessPaid and nil privateKey should return ErrNilPrivateKey")
}

func TestEncrypt_NilPrivateKey_PrivateMode(t *testing.T) {
	_, pubKey := generateKeyPair(t)
	_, err := Encrypt([]byte("private content"), nil, pubKey, AccessPrivate)
	assert.ErrorIs(t, err, ErrNilPrivateKey,
		"Encrypt with AccessPrivate and nil privateKey should return ErrNilPrivateKey")
}

func TestComputeKeyHash_NilPlaintext(t *testing.T) {
	// nil plaintext should work (sha256.Sum256 handles nil)
	hash := ComputeKeyHash(nil)
	assert.Len(t, hash, 32, "nil plaintext should produce a 32-byte hash")

	// Verify it matches SHA256(SHA256(nil)) which is same as SHA256(SHA256([]byte{}))
	emptyHash := ComputeKeyHash([]byte{})
	assert.Equal(t, emptyHash, hash,
		"nil and empty plaintext should produce the same key hash")
}

func TestEncrypt_NilPlaintext(t *testing.T) {
	privKey, pubKey := generateKeyPair(t)

	// Encrypt nil plaintext
	result, err := Encrypt(nil, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Ciphertext)
	assert.Len(t, result.KeyHash, 32)

	// Decrypt should succeed and return empty (nil normalized to empty)
	decResult, err := Decrypt(result.Ciphertext, privKey, pubKey, result.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Empty(t, decResult.Plaintext)
}

func TestReEncrypt_NonceUniqueness(t *testing.T) {
	// Verify that re-encrypting the same content produces different ciphertexts
	// due to fresh random nonces (Spec Security Consideration #1).
	privKey, pubKey := generateKeyPair(t)
	plaintext := []byte("content for nonce uniqueness test")

	encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
	require.NoError(t, err)

	// Re-encrypt same content in same mode
	reResult1, err := ReEncrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPrivate, AccessPrivate)
	require.NoError(t, err)

	reResult2, err := ReEncrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPrivate, AccessPrivate)
	require.NoError(t, err)

	// Ciphertexts should differ (random nonce)
	assert.NotEqual(t, reResult1.Ciphertext, reResult2.Ciphertext,
		"re-encryptions should produce different ciphertexts due to fresh nonces")

	// But both should decrypt to the same plaintext
	dec1, err := Decrypt(reResult1.Ciphertext, privKey, pubKey, reResult1.KeyHash, AccessPrivate)
	require.NoError(t, err)
	dec2, err := Decrypt(reResult2.Ciphertext, privKey, pubKey, reResult2.KeyHash, AccessPrivate)
	require.NoError(t, err)
	assert.Equal(t, dec1.Plaintext, dec2.Plaintext)
	assert.Equal(t, plaintext, dec1.Plaintext)
}

func TestComputeCapsuleHash_EmptyCapsule(t *testing.T) {
	hash := ComputeCapsuleHash([]byte{})
	assert.Len(t, hash, 32, "ComputeCapsuleHash of empty input should return 32-byte hash")

	// Should be standard SHA256 of empty
	expected := sha256.Sum256([]byte{})
	assert.Equal(t, expected[:], hash)
}

// =============================================================================
// Benchmarks
// =============================================================================

// benchKeyPair generates a key pair for benchmarks (does not use testing.B.Helper).
func benchKeyPair(b *testing.B) (*ec.PrivateKey, *ec.PublicKey) {
	b.Helper()
	privKey, err := ec.NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	return privKey, privKey.PubKey()
}

func BenchmarkEncrypt(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			privKey, pubKey := benchKeyPair(b)
			plaintext := bytes.Repeat([]byte("x"), sz.size)
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			privKey, pubKey := benchKeyPair(b)
			plaintext := bytes.Repeat([]byte("x"), sz.size)
			encResult, err := Encrypt(plaintext, privKey, pubKey, AccessPrivate)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := Decrypt(encResult.Ciphertext, privKey, pubKey, encResult.KeyHash, AccessPrivate)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncryptFree(b *testing.B) {
	_, pubKey := benchKeyPair(b)
	plaintext := bytes.Repeat([]byte("x"), 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(plaintext, nil, pubKey, AccessFree)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDH(b *testing.B) {
	privKey, pubKey := benchKeyPair(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ECDH(privKey, pubKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveAESKey(b *testing.B) {
	sharedX := bytes.Repeat([]byte{0xab}, 32)
	keyHash := bytes.Repeat([]byte{0xcd}, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeriveAESKey(sharedX, keyHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeKeyHash(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("x"), sz.size)
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ComputeKeyHash(data)
			}
		})
	}
}
