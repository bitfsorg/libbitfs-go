package spv

import "errors"

var (
	// ErrMerkleProofInvalid indicates the computed Merkle root does not match the expected root.
	ErrMerkleProofInvalid = errors.New("spv: merkle proof invalid")

	// ErrHeaderNotFound indicates the block header was not found in the local store.
	ErrHeaderNotFound = errors.New("spv: header not found")

	// ErrTxNotFound indicates the transaction was not found in the local store.
	ErrTxNotFound = errors.New("spv: transaction not found")

	// ErrUnconfirmed indicates the transaction has no Merkle proof (unconfirmed).
	ErrUnconfirmed = errors.New("spv: transaction is unconfirmed")

	// ErrChainBroken indicates headers do not form a valid chain.
	ErrChainBroken = errors.New("spv: header chain broken")

	// ErrInvalidHeader indicates the header fails deserialization or hash check.
	ErrInvalidHeader = errors.New("spv: invalid header")

	// ErrNilParam indicates a required parameter is nil.
	ErrNilParam = errors.New("spv: required parameter is nil")

	// ErrInvalidTxID indicates the transaction ID is not 32 bytes.
	ErrInvalidTxID = errors.New("spv: invalid transaction ID")

	// ErrDuplicateHeader indicates a header with this hash already exists.
	ErrDuplicateHeader = errors.New("spv: duplicate header")

	// ErrDuplicateTx indicates a transaction with this TxID already exists.
	ErrDuplicateTx = errors.New("spv: duplicate transaction")

	// ErrEmptyProofNodes indicates the merkle proof has no branch nodes.
	ErrEmptyProofNodes = errors.New("spv: empty proof nodes")

	// ErrInsufficientPoW indicates the header hash does not meet the target difficulty.
	ErrInsufficientPoW = errors.New("spv: insufficient proof of work")
)
