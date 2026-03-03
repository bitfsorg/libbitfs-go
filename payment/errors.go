package payment

import "errors"

var (
	// ErrInvoiceExpired indicates the invoice has passed its expiry time.
	ErrInvoiceExpired = errors.New("payment: invoice expired")

	// ErrInsufficientPayment indicates the transaction output amount is less than the invoice price.
	ErrInsufficientPayment = errors.New("payment: insufficient payment amount")

	// ErrPaymentAddrMismatch indicates the transaction output address does not match the invoice address.
	ErrPaymentAddrMismatch = errors.New("payment: payment address mismatch")

	// ErrInvalidTx indicates the raw transaction cannot be deserialized.
	ErrInvalidTx = errors.New("payment: invalid transaction")

	// ErrHTLCBuildFailed indicates HTLC script construction failed.
	ErrHTLCBuildFailed = errors.New("payment: HTLC script build failed")

	// ErrNoMatchingOutput indicates no transaction output matches the invoice requirements.
	ErrNoMatchingOutput = errors.New("payment: no matching output found")

	// ErrInvalidParams indicates one or more parameters are invalid.
	ErrInvalidParams = errors.New("payment: invalid parameters")

	// ErrInvalidPreimage indicates the HTLC preimage could not be extracted.
	ErrInvalidPreimage = errors.New("payment: invalid HTLC preimage")

	// ErrMissingHeaders indicates required payment headers are missing.
	ErrMissingHeaders = errors.New("payment: missing payment headers")

	// ErrPriceOverflow indicates that the price calculation overflowed uint64.
	ErrPriceOverflow = errors.New("payment: price calculation overflow")
)
