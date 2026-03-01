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

	// ErrUnsupportedCompression indicates an unsupported compression scheme.
	ErrUnsupportedCompression = errors.New("storage: unsupported compression scheme")

	// ErrRecombinationHashMismatch indicates chunk recombination hash verification failed.
	ErrRecombinationHashMismatch = errors.New("storage: recombination hash mismatch")

	// ErrDecompressedTooLarge indicates decompressed data exceeds the safety limit.
	ErrDecompressedTooLarge = errors.New("storage: decompressed data exceeds maximum size")

	// ErrInvalidChunkSize indicates the chunk size is not a positive integer.
	ErrInvalidChunkSize = errors.New("storage: chunk size must be positive")
)
