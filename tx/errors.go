package tx

import "errors"

var (
	// ErrNilParam indicates a required parameter is nil.
	ErrNilParam = errors.New("tx: required parameter is nil")

	// ErrInsufficientFunds indicates the fee UTXO cannot cover fees and dust outputs.
	ErrInsufficientFunds = errors.New("tx: insufficient funds")

	// ErrInvalidPayload indicates the payload is empty or exceeds limits.
	ErrInvalidPayload = errors.New("tx: invalid payload")

	// ErrInvalidParentTxID indicates parent TxID is not 32 bytes.
	ErrInvalidParentTxID = errors.New("tx: parent TxID must be 32 bytes")

	// ErrSigningFailed indicates transaction signing failed.
	ErrSigningFailed = errors.New("tx: signing failed")

	// ErrScriptBuild indicates script construction failed.
	ErrScriptBuild = errors.New("tx: script build failed")

	// ErrInvalidOPReturn indicates the OP_RETURN script is malformed.
	ErrInvalidOPReturn = errors.New("tx: invalid OP_RETURN format")

	// ErrNotMetanetTx indicates the transaction is not a valid Metanet transaction.
	ErrNotMetanetTx = errors.New("tx: not a Metanet transaction")

	// ErrInvalidParams indicates invalid parameters were provided.
	ErrInvalidParams = errors.New("tx: invalid parameters")
)
