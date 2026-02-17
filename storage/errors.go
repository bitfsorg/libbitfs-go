package storage

import "errors"

var (
	// ErrNotFound indicates no content exists for the given key hash.
	ErrNotFound = errors.New("storage: content not found")

	// ErrInvalidKeyHash indicates the key hash is not exactly 32 bytes.
	ErrInvalidKeyHash = errors.New("storage: key hash must be 32 bytes")

	// ErrStoreFull indicates disk space is exhausted.
	ErrStoreFull = errors.New("storage: disk space exhausted")

	// ErrIOFailure indicates a file read/write error.
	ErrIOFailure = errors.New("storage: I/O failure")

	// ErrEmptyContent indicates an attempt to store empty content.
	ErrEmptyContent = errors.New("storage: content is empty")

	// ErrInvalidBaseDir indicates the base directory path is invalid.
	ErrInvalidBaseDir = errors.New("storage: invalid base directory")
)
