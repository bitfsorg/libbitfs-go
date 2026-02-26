package revshare

import "errors"

var (
	// ErrInvalidRegistryData indicates the registry UTXO data is malformed.
	ErrInvalidRegistryData = errors.New("revshare: invalid registry data")

	// ErrInvalidShareData indicates the share UTXO data is malformed.
	ErrInvalidShareData = errors.New("revshare: invalid share data")

	// ErrInvalidISOPoolData indicates the ISO pool UTXO data is malformed.
	ErrInvalidISOPoolData = errors.New("revshare: invalid ISO pool data")

	// ErrShareConservationViolation indicates shares were created or destroyed.
	ErrShareConservationViolation = errors.New("revshare: share conservation violated")

	// ErrInsufficientPayment indicates the payment is too small to distribute.
	ErrInsufficientPayment = errors.New("revshare: insufficient payment for distribution")

	// ErrNoEntries indicates the registry has no shareholders.
	ErrNoEntries = errors.New("revshare: no shareholder entries")

	// ErrZeroShares indicates a share amount of zero.
	ErrZeroShares = errors.New("revshare: zero share amount")

	// ErrZeroTotalShares indicates total shares is zero.
	ErrZeroTotalShares = errors.New("revshare: zero total shares")

	// ErrEntryNotFound indicates the address was not found in the registry.
	ErrEntryNotFound = errors.New("revshare: entry not found")

	// ErrRegistryLocked indicates share transfers are locked.
	ErrRegistryLocked = errors.New("revshare: registry is locked")
)
