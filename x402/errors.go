package x402

import "errors"

var (
	// ErrInvoiceExpired indicates the invoice has passed its expiry time.
	ErrInvoiceExpired = errors.New("x402: invoice expired")

	// ErrInsufficientPayment indicates the transaction output amount is less than the invoice price.
	ErrInsufficientPayment = errors.New("x402: insufficient payment amount")

	// ErrPaymentAddrMismatch indicates the transaction output address does not match the invoice address.
	ErrPaymentAddrMismatch = errors.New("x402: payment address mismatch")

	// ErrInvalidTx indicates the raw transaction cannot be deserialized.
	ErrInvalidTx = errors.New("x402: invalid transaction")

	// ErrHTLCBuildFailed indicates HTLC script construction failed.
	ErrHTLCBuildFailed = errors.New("x402: HTLC script build failed")

	// ErrNoMatchingOutput indicates no transaction output matches the invoice requirements.
	ErrNoMatchingOutput = errors.New("x402: no matching output found")

	// ErrInvalidParams indicates one or more parameters are invalid.
	ErrInvalidParams = errors.New("x402: invalid parameters")

	// ErrInvalidPreimage indicates the HTLC preimage could not be extracted.
	ErrInvalidPreimage = errors.New("x402: invalid HTLC preimage")

	// ErrMissingHeaders indicates required x402 payment headers are missing.
	ErrMissingHeaders = errors.New("x402: missing payment headers")

	// ErrFundingMismatch indicates the pre-signed refund tx references a different
	// HTLC funding UTXO than the buyer expected.
	ErrFundingMismatch = errors.New("x402: funding UTXO mismatch")
)
