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

	// AESKey is the derived AES-256 key, 32 bytes.
	// Caller may discard this after encryption; it can be re-derived.
	AESKey []byte
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
		AESKey:     aesKey,
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

// DecryptWithCapsule decrypts using a pre-computed ECDH shared secret (capsule).
// Used by buyers who obtained the capsule via HTLC atomic swap.
//
// The capsule IS the ECDH shared secret x-coordinate:
//
//	capsule = ECDH(D_node, P_buyer).x
//
// So the AES key is derived as:
//
//	aes_key = HKDF-SHA256(capsule, key_hash, "bitfs-file-encryption")
func DecryptWithCapsule(ciphertext []byte, capsule []byte, keyHash []byte) (*DecryptResult, error) {
	if len(capsule) == 0 {
		return nil, fmt.Errorf("method42: capsule is empty")
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes", ErrKeyHashMismatch)
	}

	// Derive AES key from capsule (which IS the shared secret x-coordinate)
	aesKey, err := DeriveAESKey(capsule, keyHash)
	if err != nil {
		return nil, err
	}

	// Decrypt with AES-256-GCM
	plaintext, err := aesGCMDecrypt(ciphertext, aesKey)
	if err != nil {
		return nil, err
	}

	// Verify content integrity
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
		return nil, fmt.Errorf("%w: AES cipher creation failed: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM creation failed: %v", ErrDecryptionFailed, err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("method42: random nonce generation failed: %w", err)
	}

	// Encrypt: result = nonce || ciphertext || tag
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
		return nil, fmt.Errorf("%w: AES cipher creation failed: %v", ErrDecryptionFailed, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM creation failed: %v", ErrDecryptionFailed, err)
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
