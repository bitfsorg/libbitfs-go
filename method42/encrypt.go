package method42

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const (
	// NonceLen is the length of the AES-GCM nonce in bytes.
	NonceLen = 12

	// GCMTagLen is the length of the GCM authentication tag in bytes.
	GCMTagLen = 16

	// MinCiphertextLen is the minimum valid ciphertext length (nonce + tag).
	MinCiphertextLen = NonceLen + GCMTagLen
)

// EncryptResult holds the output of an encryption operation.
type EncryptResult struct {
	// Ciphertext is nonce(12B) || AES-256-GCM(plaintext, aes_key) || tag(16B).
	Ciphertext []byte

	// KeyHash is SHA256(SHA256(plaintext)), 32 bytes.
	// Serves as both KDF salt and content commitment.
	KeyHash []byte
}

// DecryptResult holds the output of a decryption operation.
type DecryptResult struct {
	// Plaintext is the decrypted content.
	Plaintext []byte

	// KeyHash is the recomputed SHA256(SHA256(plaintext)) for verification.
	KeyHash []byte
}

// Encrypt encrypts plaintext using Method 42.
//
// Process:
//  1. Computes key_hash = SHA256(SHA256(plaintext))
//  2. Performs ECDH(D_node, P_node) to get shared secret
//  3. Derives AES key via HKDF-SHA256
//  4. Encrypts with AES-256-GCM (random 12-byte nonce)
//
// For AccessFree: D_node is scalar 1 (anyone can reproduce).
// For AccessPrivate/AccessPaid: D_node is the BIP32-derived private key.
func Encrypt(plaintext []byte, privateKey *ec.PrivateKey, publicKey *ec.PublicKey, access Access) (*EncryptResult, error) {
	if publicKey == nil {
		return nil, ErrNilPublicKey
	}

	// Step 1: Compute key_hash = SHA256(SHA256(plaintext))
	keyHash := ComputeKeyHash(plaintext)

	// Step 2: Get effective private key based on access mode
	effKey, err := effectivePrivateKey(access, privateKey)
	if err != nil {
		return nil, err
	}

	// Step 3: ECDH to get shared secret x-coordinate
	sharedX, err := ECDH(effKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: ECDH failed: %w", err)
	}

	// Step 4: Derive AES key via HKDF-SHA256
	aesKey, err := DeriveAESKey(sharedX, keyHash)
	if err != nil {
		return nil, err
	}

	// Step 5: Encrypt with AES-256-GCM
	ciphertext, err := aesGCMEncrypt(plaintext, aesKey)
	if err != nil {
		return nil, err
	}

	return &EncryptResult{
		Ciphertext: ciphertext,
		KeyHash:    keyHash,
	}, nil
}

// Decrypt decrypts ciphertext using Method 42.
//
// Process:
//  1. Performs ECDH to recover shared secret
//  2. Derives AES key using provided key_hash
//  3. Decrypts with AES-256-GCM
//  4. Verifies SHA256(SHA256(plaintext)) == key_hash
func Decrypt(ciphertext []byte, privateKey *ec.PrivateKey, publicKey *ec.PublicKey, keyHash []byte, access Access) (*DecryptResult, error) {
	if publicKey == nil {
		return nil, ErrNilPublicKey
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes", ErrKeyHashMismatch)
	}

	// Get effective private key based on access mode
	effKey, err := effectivePrivateKey(access, privateKey)
	if err != nil {
		return nil, err
	}

	// ECDH to get shared secret x-coordinate
	sharedX, err := ECDH(effKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: ECDH failed: %w", err)
	}

	// Derive AES key via HKDF-SHA256
	aesKey, err := DeriveAESKey(sharedX, keyHash)
	if err != nil {
		return nil, err
	}

	// Decrypt with AES-256-GCM
	plaintext, err := aesGCMDecrypt(ciphertext, aesKey)
	if err != nil {
		return nil, err
	}

	// Verify content integrity: SHA256(SHA256(plaintext)) == keyHash
	computedHash := ComputeKeyHash(plaintext)
	if !bytes.Equal(computedHash, keyHash) {
		return nil, ErrKeyHashMismatch
	}

	return &DecryptResult{
		Plaintext: plaintext,
		KeyHash:   computedHash,
	}, nil
}

// DecryptWithCapsule decrypts using an XOR-masked capsule obtained via HTLC.
// Used by buyers who obtained the capsule via HTLC atomic swap.
//
// The buyer recovers the AES key as:
//
//	buyer_mask = HKDF(ECDH(D_buyer, P_node).x, key_hash, "bitfs-buyer-mask")
//	aes_key    = capsule XOR buyer_mask
//
// This works because the seller computed:
//
//	capsule = aes_key XOR HKDF(ECDH(D_node, P_buyer).x, key_hash, "bitfs-buyer-mask")
//
// and ECDH(D_buyer, P_node) == ECDH(D_node, P_buyer) by ECDH symmetry.
func DecryptWithCapsule(ciphertext []byte, capsule []byte, keyHash []byte,
	buyerPrivateKey *ec.PrivateKey, nodePublicKey *ec.PublicKey) (*DecryptResult, error) {
	if buyerPrivateKey == nil {
		return nil, ErrNilPrivateKey
	}
	if nodePublicKey == nil {
		return nil, ErrNilPublicKey
	}
	if len(capsule) == 0 {
		return nil, fmt.Errorf("method42: capsule is empty")
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes", ErrKeyHashMismatch)
	}

	// 1. sharedBuyer = ECDH(D_buyer, P_node)
	sharedBuyer, err := ECDH(buyerPrivateKey, nodePublicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: capsule ECDH failed: %w", err)
	}

	// 2. buyerMask = DeriveBuyerMask(sharedBuyer, keyHash)
	buyerMask, err := DeriveBuyerMask(sharedBuyer, keyHash)
	if err != nil {
		return nil, err
	}

	// 3. aesKey = capsule XOR buyerMask
	aesKey := xorBytes(capsule, buyerMask)

	// 4. Decrypt with AES-256-GCM
	plaintext, err := aesGCMDecrypt(ciphertext, aesKey)
	if err != nil {
		return nil, err
	}

	// 5. Verify content integrity: SHA256(SHA256(plaintext)) == keyHash
	computedHash := ComputeKeyHash(plaintext)
	if !bytes.Equal(computedHash, keyHash) {
		return nil, ErrKeyHashMismatch
	}

	return &DecryptResult{
		Plaintext: plaintext,
		KeyHash:   computedHash,
	}, nil
}

// ReEncrypt re-encrypts content from one access mode to another.
// Decrypts with fromAccess parameters, then encrypts with toAccess parameters.
// Returns new ciphertext and new key_hash.
//
// Supported conversions:
//   - FREE -> PRIVATE (encrypt command)
//   - PRIVATE -> FREE (decrypt command)
func ReEncrypt(ciphertext []byte, privateKey *ec.PrivateKey, publicKey *ec.PublicKey, keyHash []byte, fromAccess, toAccess Access) (*EncryptResult, error) {
	// Decrypt with old access mode
	result, err := Decrypt(ciphertext, privateKey, publicKey, keyHash, fromAccess)
	if err != nil {
		return nil, fmt.Errorf("method42: re-encrypt decrypt failed: %w", err)
	}

	// Encrypt with new access mode
	return Encrypt(result.Plaintext, privateKey, publicKey, toAccess)
}

// aesGCMEncrypt encrypts plaintext with AES-256-GCM.
// Returns nonce(12B) || ciphertext || tag(16B).
func aesGCMEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: AES cipher creation failed: %w", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM creation failed: %w", ErrDecryptionFailed, err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("method42: random nonce generation failed: %w", err)
	}

	// Output format: nonce(12B) || ciphertext || GCM tag(16B)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// aesGCMDecrypt decrypts AES-256-GCM ciphertext.
// Input format: nonce(12B) || ciphertext || tag(16B).
func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < MinCiphertextLen {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: AES cipher creation failed: %w", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM creation failed: %w", ErrDecryptionFailed, err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Normalize nil to empty slice for consistency.
	if plaintext == nil {
		plaintext = []byte{}
	}

	return plaintext, nil
}
