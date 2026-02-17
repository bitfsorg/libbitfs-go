package method42

import ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

// Access represents the three access control modes for encrypted content.
type Access int

const (
	// AccessPrivate means only the owner can decrypt (ECDH with BIP32 D_node).
	AccessPrivate Access = 0

	// AccessFree means anyone can decrypt. Uses D_node = scalar 1, so
	// aes_key = KDF(ECDH(1, P_node), key_hash) = KDF(P_node.x, key_hash).
	// Since P_node is public, anyone can compute this key.
	AccessFree Access = 1

	// AccessPaid means buyer decrypts via HTLC-obtained capsule.
	// Same key derivation as Private, but the capsule (shared secret)
	// is obtained through the HTLC atomic swap process.
	AccessPaid Access = 2
)

// String returns the string representation of an Access mode.
func (a Access) String() string {
	switch a {
	case AccessPrivate:
		return "PRIVATE"
	case AccessFree:
		return "FREE"
	case AccessPaid:
		return "PAID"
	default:
		return "UNKNOWN"
	}
}

// effectivePrivateKey returns the private key to use for ECDH based on access mode.
// For AccessFree, returns FreePrivateKey() (scalar 1).
// For AccessPrivate and AccessPaid, returns the provided nodePrivateKey.
func effectivePrivateKey(access Access, nodePrivateKey *ec.PrivateKey) (*ec.PrivateKey, error) {
	switch access {
	case AccessFree:
		return FreePrivateKey(), nil
	case AccessPrivate, AccessPaid:
		if nodePrivateKey == nil {
			return nil, ErrNilPrivateKey
		}
		return nodePrivateKey, nil
	default:
		return nil, ErrInvalidAccess
	}
}
