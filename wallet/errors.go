package wallet

import "errors"

var (
	// ErrInvalidMnemonic indicates the mnemonic fails BIP39 validation.
	ErrInvalidMnemonic = errors.New("wallet: invalid BIP39 mnemonic")

	// ErrInvalidEntropy indicates entropy bits is not 128 or 256.
	ErrInvalidEntropy = errors.New("wallet: entropy bits must be 128 or 256")

	// ErrFileIndexOutOfRange indicates a file index exceeds BIP32 non-hardened max.
	ErrFileIndexOutOfRange = errors.New("wallet: file index exceeds maximum (2^31-1)")

	// ErrPathTooDeep indicates filesystem path exceeds maximum nesting depth.
	ErrPathTooDeep = errors.New("wallet: path exceeds maximum depth (64)")

	// ErrVaultNotFound indicates the named vault does not exist.
	ErrVaultNotFound = errors.New("wallet: vault not found")

	// ErrVaultExists indicates the vault name is already taken.
	ErrVaultExists = errors.New("wallet: vault already exists")

	// ErrDecryptionFailed indicates wrong password or corrupted wallet data.
	ErrDecryptionFailed = errors.New("wallet: seed decryption failed (wrong password or corrupted data)")

	// ErrChecksumMismatch indicates seed checksum verification failed after decryption.
	ErrChecksumMismatch = errors.New("wallet: seed checksum mismatch")

	// ErrInvalidNetwork indicates unknown network name with no custom config.
	ErrInvalidNetwork = errors.New("wallet: invalid network name")

	// ErrInvalidSeed indicates the seed is empty or invalid.
	ErrInvalidSeed = errors.New("wallet: invalid seed")

	// ErrDerivationFailed indicates BIP32 key derivation failed.
	ErrDerivationFailed = errors.New("wallet: key derivation failed")
)
