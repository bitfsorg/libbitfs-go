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

// ComputeCapsule computes the ECDH capsule for a buyer.
//
//	capsule = ECDH(D_node, P_buyer).x
//
// Used by the seller during the HTLC atomic swap flow.
// The capsule is the preimage that the seller reveals to claim payment.
func ComputeCapsule(nodePrivateKey *ec.PrivateKey, buyerPublicKey *ec.PublicKey) ([]byte, error) {
	return ECDH(nodePrivateKey, buyerPublicKey)
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
