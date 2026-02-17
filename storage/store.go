package storage

// KeyHashSize is the required length of a key hash (SHA256 output = 32 bytes).
const KeyHashSize = 32

// Store provides content-addressed storage for encrypted file data.
// Keys are SHA256(SHA256(plaintext)) hashes (32 bytes), values are opaque ciphertext.
type Store interface {
	// Put stores encrypted content indexed by key_hash.
	// key_hash = SHA256(SHA256(plaintext)), must be exactly 32 bytes.
	Put(keyHash []byte, ciphertext []byte) error

	// Get retrieves encrypted content by key_hash.
	Get(keyHash []byte) ([]byte, error)

	// Has checks if content exists for the given key_hash.
	Has(keyHash []byte) (bool, error)

	// Delete removes content by key_hash.
	Delete(keyHash []byte) error

	// Size returns the size in bytes of stored content for key_hash.
	Size(keyHash []byte) (int64, error)

	// List returns all stored key hashes (for backup/export).
	List() ([][]byte, error)
}
