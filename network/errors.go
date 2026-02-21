package network

import "errors"

var (
	// ErrConnectionFailed indicates the client could not connect to the node.
	ErrConnectionFailed = errors.New("network: connection failed")

	// ErrAuthFailed indicates authentication (e.g., RPC credentials) was rejected.
	ErrAuthFailed = errors.New("network: authentication failed")

	// ErrTxNotFound indicates the requested transaction does not exist.
	ErrTxNotFound = errors.New("network: transaction not found")

	// ErrBroadcastRejected indicates the node rejected the broadcast transaction.
	ErrBroadcastRejected = errors.New("network: broadcast rejected")

	// ErrInvalidResponse indicates the node returned a malformed or unexpected response.
	ErrInvalidResponse = errors.New("network: invalid response")
)
