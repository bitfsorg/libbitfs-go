package storage

import (
	"bytes"
	"crypto/sha256"
)

// DefaultChunkSize is the default chunk size for content splitting (1MB).
const DefaultChunkSize = 1 << 20

// SplitIntoChunks splits data into fixed-size chunks.
// The last chunk may be smaller than chunkSize.
// Returns an error if chunkSize is not positive.
func SplitIntoChunks(data []byte, chunkSize int) ([][]byte, error) {
	if chunkSize <= 0 {
		return nil, ErrInvalidChunkSize
	}
	if len(data) == 0 {
		return nil, nil
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end-i)
		copy(chunk, data[i:end])
		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

// ComputeRecombinationHash computes SHA256(chunk0 || chunk1 || ...).
func ComputeRecombinationHash(chunks [][]byte) []byte {
	h := sha256.New()
	for _, chunk := range chunks {
		h.Write(chunk)
	}
	sum := h.Sum(nil)
	return sum
}

// RecombineChunks concatenates chunks and verifies the recombination hash.
func RecombineChunks(chunks [][]byte, expectedHash []byte) ([]byte, error) {
	var buf bytes.Buffer
	h := sha256.New()
	for _, chunk := range chunks {
		buf.Write(chunk)
		h.Write(chunk)
	}
	actualHash := h.Sum(nil)
	if !bytes.Equal(actualHash, expectedHash) {
		return nil, ErrRecombinationHashMismatch
	}
	return buf.Bytes(), nil
}
