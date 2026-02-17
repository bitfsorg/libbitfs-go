package method42

import "errors"

var (
	// ErrNilPrivateKey indicates a nil private key was provided.
	ErrNilPrivateKey = errors.New("method42: private key is nil")

	// ErrNilPublicKey indicates a nil public key was provided.
	ErrNilPublicKey = errors.New("method42: public key is nil")

	// ErrInvalidCiphertext indicates the ciphertext is too short or malformed.
	// Minimum length: 12 (nonce) + 16 (GCM tag) = 28 bytes.
	ErrInvalidCiphertext = errors.New("method42: invalid ciphertext")

	// ErrDecryptionFailed indicates AES-GCM authentication failed during decryption.
	ErrDecryptionFailed = errors.New("method42: decryption failed")

	// ErrKeyHashMismatch indicates the decrypted content's hash does not match
	// the expected key_hash commitment.
	ErrKeyHashMismatch = errors.New("method42: key hash mismatch after decryption")

	// ErrInvalidAccess indicates an unknown access mode value.
	ErrInvalidAccess = errors.New("method42: invalid access mode")

	// ErrHKDFFailure indicates HKDF key derivation failed.
	ErrHKDFFailure = errors.New("method42: HKDF key derivation failed")
)
