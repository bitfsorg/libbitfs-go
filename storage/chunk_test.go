package storage

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitIntoChunks(t *testing.T) {
	tests := []struct {
		name       string
		dataSize   int
		chunkSize  int
		wantChunks int
	}{
		{"single chunk", 100, 1024, 1},
		{"exact multiple", 3000, 1000, 3},
		{"non-exact", 2500, 1000, 3},
		{"chunk size 1", 5, 1, 5},
		{"data equals chunk", 1000, 1000, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0xAB}, tt.dataSize)
			chunks, err := SplitIntoChunks(data, tt.chunkSize)
			require.NoError(t, err)
			assert.Len(t, chunks, tt.wantChunks)

			// Recombine and verify
			var combined []byte
			for _, chunk := range chunks {
				combined = append(combined, chunk...)
			}
			assert.Equal(t, data, combined)
		})
	}
}

func TestComputeRecombinationHash(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte{0x01}, 100),
		bytes.Repeat([]byte{0x02}, 100),
		bytes.Repeat([]byte{0x03}, 100),
	}

	hash := ComputeRecombinationHash(chunks)
	assert.Len(t, hash, 32)

	// Verify it's SHA256 of concatenation
	var combined []byte
	for _, c := range chunks {
		combined = append(combined, c...)
	}
	expected := sha256.Sum256(combined)
	assert.Equal(t, expected[:], hash)
}

func TestRecombineChunks_Valid(t *testing.T) {
	data := bytes.Repeat([]byte{0xAA}, 2500)
	chunks, err := SplitIntoChunks(data, 1000)
	require.NoError(t, err)
	hash := ComputeRecombinationHash(chunks)

	result, err := RecombineChunks(chunks, hash)
	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestRecombineChunks_HashMismatch(t *testing.T) {
	chunks := [][]byte{{0x01}, {0x02}}
	badHash := bytes.Repeat([]byte{0xFF}, 32)

	_, err := RecombineChunks(chunks, badHash)
	assert.ErrorIs(t, err, ErrRecombinationHashMismatch)
}

func TestRecombineChunks_EmptyChunks(t *testing.T) {
	hash := ComputeRecombinationHash(nil)
	result, err := RecombineChunks(nil, hash)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestSplitIntoChunks_EmptyData(t *testing.T) {
	chunks, err := SplitIntoChunks(nil, 1024)
	require.NoError(t, err)
	assert.Empty(t, chunks)
}

func TestSplitIntoChunks_InvalidChunkSize(t *testing.T) {
	data := []byte("test data")
	_, err := SplitIntoChunks(data, 0)
	assert.ErrorIs(t, err, ErrInvalidChunkSize)

	_, err = SplitIntoChunks(data, -1)
	assert.ErrorIs(t, err, ErrInvalidChunkSize)
}
