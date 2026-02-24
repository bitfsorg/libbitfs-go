package method42

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ECDH computes the shared secret between a private key scalar and a public key
// point on the secp256k1 curve.
//
// Returns the x-coordinate of the shared point (32 bytes, zero-padded).
// For AccessFree mode, pass the result of FreePrivateKey() as privateKey.
//
// Mathematical operation: shared_point = privateKey.D * publicKey.Point
// Result: shared_point.X serialized as 32 bytes (big-endian, zero-padded).
func ECDH(privateKey *ec.PrivateKey, publicKey *ec.PublicKey) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrNilPrivateKey
	}
	if publicKey == nil {
		return nil, ErrNilPublicKey
	}

	// Use the go-sdk's DeriveSharedSecret method which performs
	// scalar multiplication: shared_point = D * P
	sharedPoint, err := privateKey.DeriveSharedSecret(publicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: ECDH failed: %w", err)
	}

	// Serialize x-coordinate as 32 bytes (zero-padded big-endian)
	xBytes := sharedPoint.X.Bytes()
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		return padded, nil
	}
	return xBytes[:32], nil
}

// FreePrivateKey returns a private key with scalar value 1.
// Used for AccessFree mode where ECDH(1, P_node) = P_node.
//
// When D_node = 1:
//
//	shared_point = 1 * P_node = P_node
//	shared_x = P_node.X
//
// Since P_node is public (via DNSLink), anyone can compute this,
// making the content effectively "encrypted at rest but publicly readable".
func FreePrivateKey() *ec.PrivateKey {
	one := big.NewInt(1)
	privKey, _ := ec.PrivateKeyFromBytes(one.Bytes())
	return privKey
}

// ComputeCapsule computes the XOR-masked capsule for a buyer.
//
//	capsule = aes_key XOR buyer_mask
//
// where:
//
//	aes_key    = HKDF(ECDH(D_node, P_node).x, key_hash, "bitfs-file-encryption")
//	buyer_mask = HKDF(ECDH(D_node, P_buyer).x, key_hash, "bitfs-buyer-mask")
//
// The buyer recovers aes_key by computing buyer_mask from ECDH(D_buyer, P_node)
// (equivalent by ECDH symmetry) and XORing with the capsule.
// The capsule is the preimage that the seller reveals to claim HTLC payment.
func ComputeCapsule(nodePrivateKey *ec.PrivateKey, nodePublicKey *ec.PublicKey,
	buyerPublicKey *ec.PublicKey, keyHash []byte) ([]byte, error) {
	// 1. sharedNode = ECDH(D_node, P_node)
	sharedNode, err := ECDH(nodePrivateKey, nodePublicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: capsule ECDH(node,node) failed: %w", err)
	}

	// 2. aesKey = DeriveAESKey(sharedNode, keyHash)
	aesKey, err := DeriveAESKey(sharedNode, keyHash)
	if err != nil {
		return nil, fmt.Errorf("method42: capsule key derivation failed: %w", err)
	}

	// 3. sharedBuyer = ECDH(D_node, P_buyer)
	sharedBuyer, err := ECDH(nodePrivateKey, buyerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("method42: capsule ECDH(node,buyer) failed: %w", err)
	}

	// 4. buyerMask = DeriveBuyerMask(sharedBuyer, keyHash)
	buyerMask, err := DeriveBuyerMask(sharedBuyer, keyHash)
	if err != nil {
		return nil, fmt.Errorf("method42: capsule buyer mask derivation failed: %w", err)
	}

	// 5. capsule = xorBytes(aesKey, buyerMask)
	return xorBytes(aesKey, buyerMask), nil
}

// xorBytes XORs two byte slices of equal length.
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// ComputeCapsuleHash computes SHA256(capsule) for the HTLC hash lock.
//
//	capsule_hash = SHA256(capsule)
//
// The buyer creates an HTLC locked to this hash. The seller reveals
// the capsule (preimage) to claim the payment, and the buyer can then
// use the capsule to derive the decryption key.
func ComputeCapsuleHash(capsule []byte) []byte {
	h := sha256.Sum256(capsule)
	return h[:]
}
