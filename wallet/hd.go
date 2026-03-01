package wallet

import (
	"fmt"
	"strings"

	bip32 "github.com/bsv-blockchain/go-sdk/compat/bip32"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	chaincfg "github.com/bsv-blockchain/go-sdk/transaction/chaincfg"
)

const (
	// BIP44 path constants.
	PurposeBIP44        = 44
	CoinTypeBitFS       = 236
	FeeAccount          = 0
	DefaultVaultAccount = 1

	// Chain indices.
	ExternalChain = 0 // Receive addresses
	InternalChain = 1 // Change addresses

	// BIP32 limits.
	MaxFileIndex = 1<<31 - 1 // 2^31 - 1 (non-hardened max)
	MaxPathDepth = 64        // Maximum filesystem nesting depth

	// BIP32 hardened offset.
	Hardened = 0x80000000
)

// Wallet represents an HD wallet instance for BitFS.
type Wallet struct {
	masterKey *bip32.ExtendedKey
	network   *NetworkConfig
}

// KeyPair holds a derived public/private key pair.
type KeyPair struct {
	PrivateKey *ec.PrivateKey `json:"-"`
	PublicKey  *ec.PublicKey  `json:"public_key"`
	Path       string         `json:"path"` // Human-readable derivation path
}

// NewWallet creates a new Wallet from a BIP39 seed.
func NewWallet(seed []byte, network *NetworkConfig) (*Wallet, error) {
	if len(seed) == 0 {
		return nil, ErrInvalidSeed
	}
	if network == nil {
		network = &MainNet
	}

	// Map our NetworkConfig to go-sdk chaincfg.Params for BIP32.
	var net *chaincfg.Params
	switch network.Name {
	case "mainnet":
		net = &chaincfg.MainNet
	default:
		net = &chaincfg.TestNet
	}

	masterKey, err := bip32.NewMaster(seed, net)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDerivationFailed, err)
	}

	return &Wallet{
		masterKey: masterKey,
		network:   network,
	}, nil
}

// Network returns the wallet's network configuration.
func (w *Wallet) Network() *NetworkConfig {
	return w.network
}

// deriveAccount derives the account-level key: m/44'/236'/account'
func (w *Wallet) deriveAccount(account uint32) (*bip32.ExtendedKey, error) {
	// m/44'
	purpose, err := w.masterKey.Child(PurposeBIP44 + Hardened)
	if err != nil {
		return nil, fmt.Errorf("%w: purpose derivation: %w", ErrDerivationFailed, err)
	}

	// m/44'/236'
	coinType, err := purpose.Child(CoinTypeBitFS + Hardened)
	if err != nil {
		return nil, fmt.Errorf("%w: coin type derivation: %w", ErrDerivationFailed, err)
	}

	// m/44'/236'/account'
	accountKey, err := coinType.Child(account + Hardened)
	if err != nil {
		return nil, fmt.Errorf("%w: account derivation: %w", ErrDerivationFailed, err)
	}

	return accountKey, nil
}

// DeriveFeeKey derives a key pair from the fee key chain.
//
//	chain: ExternalChain (0) for receive, InternalChain (1) for change
//	index: address index
//	Path: m/44'/236'/0'/chain/index
func (w *Wallet) DeriveFeeKey(chain, index uint32) (*KeyPair, error) {
	accountKey, err := w.deriveAccount(FeeAccount)
	if err != nil {
		return nil, err
	}

	// m/44'/236'/0'/chain
	chainKey, err := accountKey.Child(chain)
	if err != nil {
		return nil, fmt.Errorf("%w: chain derivation: %w", ErrDerivationFailed, err)
	}

	// m/44'/236'/0'/chain/index
	childKey, err := chainKey.Child(index)
	if err != nil {
		return nil, fmt.Errorf("%w: index derivation: %w", ErrDerivationFailed, err)
	}

	return extKeyToKeyPair(childKey, fmt.Sprintf("m/44'/236'/0'/%d/%d", chain, index))
}

// DeriveVaultRootKey derives the root key pair for a vault.
//
//	Path: m/44'/236'/(vaultIndex+1)'/0/0
func (w *Wallet) DeriveVaultRootKey(vaultIndex uint32) (*KeyPair, error) {
	return w.DeriveNodeKey(vaultIndex, nil, nil)
}

// DeriveNodeKey derives a key pair for a filesystem node.
//
//	vaultIndex: 0-based vault number
//	filePath: sequence of child indices from root, e.g. [3, 1, 7]
//	hardened: whether each index uses hardened derivation (nil = all hardened, per design decision #82)
//	Path: m/44'/236'/(vaultIndex+1)'/0/0[/filePath...]
func (w *Wallet) DeriveNodeKey(vaultIndex uint32, filePath []uint32, hardened []bool) (*KeyPair, error) {
	if len(filePath) > MaxPathDepth {
		return nil, ErrPathTooDeep
	}

	// Validate file indices
	for _, idx := range filePath {
		if idx > uint32(MaxFileIndex) {
			return nil, ErrFileIndexOutOfRange
		}
	}

	// Guard: accountIndex = vaultIndex + DefaultVaultAccount must be < Hardened (0x80000000),
	// since deriveAccount adds Hardened offset for hardened derivation.
	if vaultIndex >= Hardened-DefaultVaultAccount {
		return nil, fmt.Errorf("%w: vault index %d exceeds BIP32 hardened boundary", ErrFileIndexOutOfRange, vaultIndex)
	}

	accountIndex := vaultIndex + DefaultVaultAccount
	accountKey, err := w.deriveAccount(accountIndex)
	if err != nil {
		return nil, err
	}

	// m/44'/236'/(V+1)'/0 (external chain)
	chainKey, err := accountKey.Child(ExternalChain)
	if err != nil {
		return nil, fmt.Errorf("%w: chain derivation: %w", ErrDerivationFailed, err)
	}

	// m/44'/236'/(V+1)'/0/0 (root directory)
	current, err := chainKey.Child(0)
	if err != nil {
		return nil, fmt.Errorf("%w: root derivation: %w", ErrDerivationFailed, err)
	}

	// Build human-readable path
	var pathBuilder strings.Builder
	fmt.Fprintf(&pathBuilder, "m/44'/236'/%d'/0/0", accountIndex)

	// Derive each level of the filesystem path
	for i, idx := range filePath {
		isHardened := true // Default: hardened (design decision #82)
		if hardened != nil && i < len(hardened) {
			isHardened = hardened[i]
		}

		childIdx := idx
		if isHardened {
			childIdx += Hardened
			fmt.Fprintf(&pathBuilder, "/%d'", idx)
		} else {
			fmt.Fprintf(&pathBuilder, "/%d", idx)
		}

		current, err = current.Child(childIdx)
		if err != nil {
			return nil, fmt.Errorf("%w: path derivation at depth %d: %w", ErrDerivationFailed, i, err)
		}
	}

	return extKeyToKeyPair(current, pathBuilder.String())
}

// DeriveNodePubKey derives only the public key for a filesystem node.
// Equivalent to DeriveNodeKey but returns only the public key component.
func (w *Wallet) DeriveNodePubKey(vaultIndex uint32, filePath []uint32, hardened []bool) (*ec.PublicKey, error) {
	kp, err := w.DeriveNodeKey(vaultIndex, filePath, hardened)
	if err != nil {
		return nil, err
	}
	return kp.PublicKey, nil
}

// extKeyToKeyPair converts a BIP32 extended key to a KeyPair.
func extKeyToKeyPair(extKey *bip32.ExtendedKey, path string) (*KeyPair, error) {
	privKey, err := extKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to extract EC private key: %w", ErrDerivationFailed, err)
	}

	pubKey := privKey.PubKey()
	if pubKey == nil {
		return nil, fmt.Errorf("%w: failed to derive public key", ErrDerivationFailed)
	}

	return &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Path:       path,
	}, nil
}
