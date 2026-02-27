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
// The derivation is DETERMINISTIC: the same (sharedSecretX, keyHash) pair always
// produces the same AES key. This is by design -- it allows any party with the
// correct ECDH shared secret and key_hash to independently derive the decryption
// key without additional key exchange.
//
// Nonce safety implication: because the AES key is deterministic, every call to
// Encrypt with the same (D_node, P_node, key_hash) triple reuses the same AES
// key. AES-256-GCM nonce safety therefore depends on the uniqueness of the random
// 12-byte nonce generated per Encrypt call. The conservative bound is 2^32
// encryptions per key (NIST SP 800-38D). In practice, key_hash varies with file
// content and D_node varies with Metanet path, so key reuse across different
// files or paths does not occur. See the Nonce Safety Model documentation on the
// Encrypt function for a full analysis.
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

// SECURITY NOTE — Future metadata encryption (PRIVATE mode envelope):
//
// The design spec (5-TransactionSpec.zh.md §4.3) specifies a third HKDF derivation
// for PRIVATE mode TLV payload encryption:
//
//   metadata_key = HKDF(ECDH(D_node, P_node).x, SHA256(P_node), "bitfs-metadata-encryption")
//
// This design uses SHA256(P_node) as salt, which is WEAK because P_node is always
// public (present in OP_RETURN cleartext). A public salt degrades the HKDF security
// margin. When implementing DeriveMetadataKey, use one of these alternatives:
//
//   Option A: salt = random 16 bytes, stored as prefix of EncPayload ciphertext
//   Option B: salt = ECDH(D_node, P_node).y (the y-coordinate, not directly public)
//
// The design docs must be updated to match whichever option is chosen.
// See: architecture review §3.2 (2026-02-27).

// DeriveBuyerMask derives a 32-byte buyer mask using HKDF-SHA256.
// Used in the paid content flow: capsule = aes_key XOR buyer_mask.
//
// This is the legacy deterministic version. For per-purchase unlinkability,
// use DeriveBuyerMaskWithNonce instead.
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
	return DeriveBuyerMaskWithNonce(sharedSecretX, keyHash, nil)
}

// DeriveBuyerMaskWithNonce derives a 32-byte buyer mask using HKDF-SHA256,
// with an optional per-invoice nonce for capsule unlinkability.
//
// When nonce is non-nil, it is appended to the HKDF salt (keyHash || nonce),
// making each capsule unique even for repeat purchases of the same file by the
// same buyer. This prevents on-chain linkability: an observer who sees two HTLC
// claim transactions cannot correlate them to the same (buyer, file) pair based
// on the capsule preimage.
//
// When nonce is nil or empty, this is equivalent to DeriveBuyerMask (legacy
// deterministic behavior for backward compatibility).
//
// Security model:
//   - Without nonce: capsule is deterministic for (D_node, P_buyer, key_hash).
//     The buyer already knows aes_key after decryption, so no key material leaks.
//     However, identical capsules on-chain enable purchase linkability.
//   - With nonce: capsule is unique per (D_node, P_buyer, key_hash, nonce).
//     The nonce should be a random or unique value (e.g., invoice ID bytes).
//     The buyer must receive the same nonce to derive their mask for decryption.
//
// Parameters:
//   - sharedSecretX: ECDH(D_node, P_buyer).x (or equivalently ECDH(D_buyer, P_node).x)
//   - keyHash: SHA256(SHA256(plaintext)), 32 bytes
//   - nonce: optional per-invoice randomizer (nil = legacy behavior)
//
// The HKDF parameters are:
//   - IKM  = sharedSecretX
//   - Salt = keyHash (if nonce is nil) or keyHash || nonce
//   - Info = "bitfs-buyer-mask"
//   - Len  = 32 (AES-256)
func DeriveBuyerMaskWithNonce(sharedSecretX []byte, keyHash []byte, nonce []byte) ([]byte, error) {
	if len(sharedSecretX) == 0 {
		return nil, fmt.Errorf("%w: shared secret is empty", ErrHKDFFailure)
	}
	if len(keyHash) != 32 {
		return nil, fmt.Errorf("%w: key hash must be 32 bytes, got %d", ErrHKDFFailure, len(keyHash))
	}

	// Build HKDF salt: keyHash alone (legacy) or keyHash || nonce (unlinkable).
	salt := keyHash
	if len(nonce) > 0 {
		salt = make([]byte, len(keyHash)+len(nonce))
		copy(salt, keyHash)
		copy(salt[len(keyHash):], nonce)
	}

	hkdfReader := hkdf.New(sha256.New, sharedSecretX, salt, []byte(HKDFBuyerMaskInfo))
	mask := make([]byte, AESKeyLen)
	if _, err := io.ReadFull(hkdfReader, mask); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHKDFFailure, err)
	}
	return mask, nil
}
