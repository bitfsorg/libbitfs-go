package paymail

import "errors"

var (
	// ErrInvalidURI indicates the URI does not match bitfs:// scheme or is malformed.
	ErrInvalidURI = errors.New("paymail: invalid bitfs:// URI")

	// ErrDNSLookupFailed indicates a DNS SRV/TXT lookup failed.
	ErrDNSLookupFailed = errors.New("paymail: DNS lookup failed")

	// ErrPaymailDiscovery indicates .well-known/bsvalias fetch failed.
	ErrPaymailDiscovery = errors.New("paymail: capability discovery failed")

	// ErrPKIResolution indicates the Paymail PKI endpoint returned an error.
	ErrPKIResolution = errors.New("paymail: PKI resolution failed")

	// ErrNoEndpoints indicates no SRV records were found for the domain.
	ErrNoEndpoints = errors.New("paymail: no endpoints found")

	// ErrInvalidPubKey indicates a public key is not a valid compressed secp256k1 key.
	ErrInvalidPubKey = errors.New("paymail: invalid compressed public key")

	// ErrAddressResolution indicates the P2P payment destination resolution failed.
	ErrAddressResolution = errors.New("paymail: address resolution failed")
)
