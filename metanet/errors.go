package metanet

import "errors"

var (
	// ErrNotDirectory indicates an operation requires a directory but the node is not one.
	ErrNotDirectory = errors.New("metanet: node is not a directory")

	// ErrNotFile indicates an operation requires a file but the node is not one.
	ErrNotFile = errors.New("metanet: node is not a file")

	// ErrNotLink indicates an operation requires a link but the node is not one.
	ErrNotLink = errors.New("metanet: node is not a link")

	// ErrChildNotFound indicates the named child does not exist in the directory.
	ErrChildNotFound = errors.New("metanet: child not found")

	// ErrChildExists indicates a child with the given name already exists.
	ErrChildExists = errors.New("metanet: child already exists")

	// ErrLinkDepthExceeded indicates soft link chain exceeds the maximum follow depth.
	ErrLinkDepthExceeded = errors.New("metanet: link depth exceeded")

	// ErrRemoteLinkNotSupported indicates a remote soft link requires external resolution.
	ErrRemoteLinkNotSupported = errors.New("metanet: remote link not supported")

	// ErrInvalidPath indicates the path is empty or contains invalid characters.
	ErrInvalidPath = errors.New("metanet: invalid path")

	// ErrNodeNotFound indicates no node was found for the given P_node or TxID.
	ErrNodeNotFound = errors.New("metanet: node not found")

	// ErrInvalidPayload indicates the payload cannot be deserialized.
	ErrInvalidPayload = errors.New("metanet: invalid payload")

	// ErrHardLinkToDirectory indicates an attempt to create a hard link to a directory.
	ErrHardLinkToDirectory = errors.New("metanet: hard links to directories not allowed")

	// ErrNilParam indicates a required parameter is nil.
	ErrNilParam = errors.New("metanet: required parameter is nil")

	// ErrInvalidName indicates a child name is empty or contains path separators.
	ErrInvalidName = errors.New("metanet: invalid name")

	// ErrAboveRoot indicates a ".." navigation attempted to go above the root.
	ErrAboveRoot = errors.New("metanet: cannot navigate above root")

	// ErrInvalidPubKey indicates a public key is not 33 bytes (compressed).
	ErrInvalidPubKey = errors.New("metanet: invalid public key length")

	// ErrInvalidOPReturn indicates the OP_RETURN data is malformed.
	ErrInvalidOPReturn = errors.New("metanet: invalid OP_RETURN data")
)
