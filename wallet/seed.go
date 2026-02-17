// Package wallet implements the HD wallet for BitFS using BIP32/BIP39.
//
// Key hierarchy: m/44'/236'/{account}'/{chain}/{index}
// where account 0 is the fee key chain and accounts 1+ are vaults.
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/compat/bip39"
	"golang.org/x/crypto/argon2"
)

const (
	// Mnemonic entropy sizes.
	Mnemonic12Words = 128 // 12-word mnemonic
	Mnemonic24Words = 256 // 24-word mnemonic

	// Argon2id parameters for seed encryption.
	Argon2Time        = 3
	Argon2Memory      = 64 * 1024 // 64 MB
	Argon2Parallelism = 4
	Argon2KeyLen      = 32

	// Encryption format sizes.
	SaltLen     = 16
	NonceLen    = 12
	ChecksumLen = 4
)

// GenerateMnemonic creates a new BIP39 mnemonic with the specified entropy bits.
// Use Mnemonic12Words (128) for 12 words or Mnemonic24Words (256) for 24 words.
func GenerateMnemonic(entropyBits int) (string, error) {
	if entropyBits != Mnemonic12Words && entropyBits != Mnemonic24Words {
		return "", ErrInvalidEntropy
	}

	entropy, err := bip39.NewEntropy(entropyBits)
	if err != nil {
		return "", fmt.Errorf("wallet: failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("wallet: failed to generate mnemonic: %w", err)
	}

	return mnemonic, nil
}

// ValidateMnemonic checks if a mnemonic string is valid BIP39.
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// SeedFromMnemonic derives a 64-byte BIP39 seed from mnemonic + optional passphrase.
//
//	seed = PBKDF2(mnemonic, "mnemonic"+passphrase, 2048, 64, SHA512)
//
// Note: passphrase can be empty string "" (still participates in derivation).
func SeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	if !ValidateMnemonic(mnemonic) {
		return nil, ErrInvalidMnemonic
	}

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, fmt.Errorf("wallet: failed to derive seed: %w", err)
	}

	return seed, nil
}

// EncryptSeed encrypts the seed with Argon2id + AES-256-GCM.
//
// Output format: salt(16B) || nonce(12B) || AES-GCM(argon2id(password,salt), nonce, seed||checksum)
//
// The checksum is SHA256(seed)[:4] for verifying correct decryption.
func EncryptSeed(seed []byte, password string) ([]byte, error) {
	if len(seed) == 0 {
		return nil, ErrInvalidSeed
	}

	// Generate random salt for Argon2id
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("wallet: failed to generate salt: %w", err)
	}

	// Derive encryption key using Argon2id
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Parallelism,
		Argon2KeyLen,
	)

	// Compute checksum: SHA256(seed)[:4]
	seedHash := sha256.Sum256(seed)
	checksum := seedHash[:ChecksumLen]

	// Prepare plaintext: seed || checksum
	plaintext := make([]byte, len(seed)+ChecksumLen)
	copy(plaintext, seed)
	copy(plaintext[len(seed):], checksum)

	// AES-256-GCM encryption
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("wallet: AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("wallet: GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("wallet: failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Output: salt(16B) || nonce(12B) || ciphertext
	result := make([]byte, 0, SaltLen+NonceLen+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptSeed decrypts the seed from the wallet.enc format.
//
// Input format: salt(16B) || nonce(12B) || ciphertext
//
// Derives key with Argon2id, decrypts with AES-256-GCM, then verifies
// the SHA256(seed)[:4] checksum to confirm correct decryption.
func DecryptSeed(encrypted []byte, password string) ([]byte, error) {
	minLen := SaltLen + NonceLen + ChecksumLen // minimum: salt + nonce + at least checksum
	if len(encrypted) < minLen {
		return nil, ErrDecryptionFailed
	}

	// Parse components
	salt := encrypted[:SaltLen]
	nonce := encrypted[SaltLen : SaltLen+NonceLen]
	ciphertext := encrypted[SaltLen+NonceLen:]

	// Derive decryption key using Argon2id with same parameters
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Parallelism,
		Argon2KeyLen,
	)

	// AES-256-GCM decryption
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if len(plaintext) < ChecksumLen {
		return nil, ErrDecryptionFailed
	}

	// Split seed and checksum
	seed := plaintext[:len(plaintext)-ChecksumLen]
	storedChecksum := plaintext[len(plaintext)-ChecksumLen:]

	// Verify checksum
	seedHash := sha256.Sum256(seed)
	expectedChecksum := seedHash[:ChecksumLen]

	for i := 0; i < ChecksumLen; i++ {
		if storedChecksum[i] != expectedChecksum[i] {
			return nil, ErrChecksumMismatch
		}
	}

	return seed, nil
}
