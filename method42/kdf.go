// Package method42 implements the Method 42 ECDH encryption engine for BitFS.
//
// Key derivation formula:
//
//	aes_key = HKDF-SHA256(ECDH(D_node, P_node).x, key_hash, "bitfs-file-encryption")
//
// where key_hash = SHA256(SHA256(plaintext)) serves dual purpose as KDF salt
// and content commitment.
package method42

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// HKDFInfo is the constant info string used in HKDF-SHA256 key derivation.
	HKDFInfo = "bitfs-file-encryption"

	// HKDFBuyerMaskInfo is the info string for buyer mask derivation in paid content flow.
	HKDFBuyerMaskInfo = "bitfs-buyer-mask"

	// AESKeyLen is the length of the derived AES-256 key in bytes.
	AESKeyLen = 32
)

// ComputeKeyHash computes the double-SHA256 content commitment.
// Returns SHA256(SHA256(plaintext)), 32 bytes.
// This value serves dual purpose:
//  1. Salt parameter for HKDF key derivation
//  2. Content integrity commitment (verified after decryption)
func ComputeKeyHash(plaintext []byte) []byte {
	first := sha256.Sum256(plaintext)
	second := sha256.Sum256(first[:])
	return second[:]
}

// DeriveAESKey derives a 32-byte AES-256 key using HKDF-SHA256.
//
// Parameters:
//   - sharedSecretX: ECDH shared secret x-coordinate (32 bytes)
//   - keyHash: SHA256(SHA256(plaintext)), 32 bytes
//
// The HKDF parameters are:
//   - IKM  = sharedSecretX
//   - Salt = keyHash
//   - Info = "bitfs-file-encryption"
//   - Len  = 32 (AES-256)
func DeriveAESKey(sharedSecretX []byte, keyHash []byte) ([]byte, error) {
	if len(sharedSecretX) == 0 {
		return nil, fmt.Errorf("%w: shared secret is empty", ErrHKDFFailure)
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes, got %d", ErrHKDFFailure, len(keyHash))
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecretX, keyHash, []byte(HKDFInfo))
	key := make([]byte, AESKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHKDFFailure, err)
	}
	return key, nil
}

// DeriveBuyerMask derives a 32-byte buyer mask using HKDF-SHA256.
// Used in the paid content flow: capsule = aes_key XOR buyer_mask.
//
// Parameters:
//   - sharedSecretX: ECDH(D_node, P_buyer).x (or equivalently ECDH(D_buyer, P_node).x)
//   - keyHash: SHA256(SHA256(plaintext)), 32 bytes
//
// The HKDF parameters are:
//   - IKM  = sharedSecretX
//   - Salt = keyHash
//   - Info = "bitfs-buyer-mask"
//   - Len  = 32 (AES-256)
func DeriveBuyerMask(sharedSecretX []byte, keyHash []byte) ([]byte, error) {
	if len(sharedSecretX) == 0 {
		return nil, fmt.Errorf("%w: shared secret is empty", ErrHKDFFailure)
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes, got %d", ErrHKDFFailure, len(keyHash))
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecretX, keyHash, []byte(HKDFBuyerMaskInfo))
	mask := make([]byte, AESKeyLen)
	if _, err := io.ReadFull(hkdfReader, mask); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHKDFFailure, err)
	}
	return mask, nil
}
