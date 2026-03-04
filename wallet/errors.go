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

	// ErrAliasExists indicates the paymail alias is already bound.
	ErrAliasExists = errors.New("wallet: paymail alias already exists")

	// ErrAliasNotFound indicates the paymail alias does not exist.
	ErrAliasNotFound = errors.New("wallet: paymail alias not found")

	// ErrInvalidAlias indicates the paymail alias format is invalid.
	ErrInvalidAlias = errors.New("wallet: invalid paymail alias format")

	// ErrVaultAlreadyBound indicates the vault already has a paymail binding.
	ErrVaultAlreadyBound = errors.New("wallet: vault already has a paymail binding")

	// ErrUnsupportedKeyFormat indicates an unsupported key export format.
	ErrUnsupportedKeyFormat = errors.New("wallet: unsupported key export format")
)
