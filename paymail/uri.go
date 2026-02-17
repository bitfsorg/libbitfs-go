// Package paymail provides Paymail identity resolution for BitFS.
//
// It parses bitfs:// URIs, discovers Paymail capabilities via
// .well-known/bsvalias, and resolves aliases to Metanet root public keys.
// Three addressing modes are supported: Paymail (@), DNSLink (domain),
// and bare public key (hex).
package paymail

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// AddressType represents the three BitFS addressing modes.
type AddressType int

const (
	// AddressPaymail indicates a Paymail address: bitfs://alias@domain/path
	AddressPaymail AddressType = iota
	// AddressDNSLink indicates a DNSLink address: bitfs://domain/path
	AddressDNSLink
	// AddressPubKey indicates a direct public key: bitfs://02abcdef.../path
	AddressPubKey
)

// String returns the human-readable name of an AddressType.
func (a AddressType) String() string {
	switch a {
	case AddressPaymail:
		return "Paymail"
	case AddressDNSLink:
		return "DNSLink"
	case AddressPubKey:
		return "PubKey"
	default:
		return "Unknown"
	}
}

// ParsedURI holds a parsed bitfs:// URI.
type ParsedURI struct {
	Type   AddressType
	Alias  string // Paymail alias (empty for non-Paymail)
	Domain string // Domain name (empty for PubKey)
	PubKey []byte // Raw public key bytes (only for AddressPubKey)
	Path   string // Path component after authority
	RawURI string // Original URI string
}

// compressedPubKeyHexLen is the hex-encoded length of a compressed public key (33 bytes = 66 hex chars).
const compressedPubKeyHexLen = 66

// ParseURI parses a bitfs:// URI into its components.
// Detects address type based on:
//   - Contains '@' in authority -> Paymail
//   - Authority starts with hex pubkey prefix (02/03) and is 66 hex chars -> PubKey
//   - Otherwise -> DNSLink
func ParseURI(uri string) (*ParsedURI, error) {
	if uri == "" {
		return nil, fmt.Errorf("%w: empty URI", ErrInvalidURI)
	}

	// Must start with bitfs://
	if !strings.HasPrefix(uri, "bitfs://") {
		return nil, fmt.Errorf("%w: scheme must be bitfs://", ErrInvalidURI)
	}

	// Parse manually since url.Parse doesn't handle non-standard schemes well.
	rest := uri[len("bitfs://"):]
	if rest == "" {
		return nil, fmt.Errorf("%w: empty authority", ErrInvalidURI)
	}

	// Split authority from path
	authority := rest
	path := ""
	if idx := strings.Index(rest, "/"); idx >= 0 {
		authority = rest[:idx]
		path = rest[idx:] // Keep leading slash
	}

	if authority == "" {
		return nil, fmt.Errorf("%w: empty authority", ErrInvalidURI)
	}

	result := &ParsedURI{
		RawURI: uri,
		Path:   path,
	}

	// Detect address type
	if strings.Contains(authority, "@") {
		// Paymail: alias@domain
		parts := strings.SplitN(authority, "@", 2)
		if parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("%w: invalid Paymail address %q", ErrInvalidURI, authority)
		}
		result.Type = AddressPaymail
		result.Alias = parts[0]
		result.Domain = parts[1]
	} else if isPubKeyHex(authority) {
		// PubKey: 02/03 + 64 hex chars = 66 hex chars total
		pubKeyBytes, err := hex.DecodeString(authority)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid public key hex: %v", ErrInvalidURI, err)
		}
		result.Type = AddressPubKey
		result.PubKey = pubKeyBytes
	} else {
		// DNSLink: plain domain
		result.Type = AddressDNSLink
		result.Domain = authority
	}

	return result, nil
}

// isPubKeyHex returns true if s looks like a compressed secp256k1 public key in hex:
// starts with "02" or "03" and is exactly 66 hex characters (33 bytes).
func isPubKeyHex(s string) bool {
	if len(s) != compressedPubKeyHexLen {
		return false
	}
	if !strings.HasPrefix(s, "02") && !strings.HasPrefix(s, "03") {
		return false
	}
	// Verify all characters are valid hex
	_, err := hex.DecodeString(s)
	return err == nil
}

// validateCompressedPubKey checks that raw bytes represent a valid compressed public key.
// A compressed secp256k1 public key is exactly 33 bytes with prefix 0x02 or 0x03.
func validateCompressedPubKey(pub []byte) error {
	if len(pub) != 33 {
		return fmt.Errorf("%w: expected 33 bytes, got %d", ErrInvalidPubKey, len(pub))
	}
	if pub[0] != 0x02 && pub[0] != 0x03 {
		return fmt.Errorf("%w: invalid prefix byte 0x%02x", ErrInvalidPubKey, pub[0])
	}
	return nil
}
