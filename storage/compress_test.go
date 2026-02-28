package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bitfsorg/libbitfs-go/metanet"
)

func TestCompress_RoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("Hello, BitFS! This is test data for compression. "), 100)

	tests := []struct {
		name   string
		scheme int32
	}{
		{"none", metanet.CompressNone},
		{"lzw", metanet.CompressLZW},
		{"gzip", metanet.CompressGZIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(data, tt.scheme)
			require.NoError(t, err)

			decompressed, err := Decompress(compressed, tt.scheme)
			require.NoError(t, err)

			assert.Equal(t, data, decompressed)
		})
	}
}

func TestCompress_None_Identity(t *testing.T) {
	data := []byte("unchanged data")
	compressed, err := Compress(data, metanet.CompressNone)
	require.NoError(t, err)
	assert.Equal(t, data, compressed)
}

func TestCompress_Empty(t *testing.T) {
	for _, scheme := range []int32{metanet.CompressNone, metanet.CompressLZW, metanet.CompressGZIP} {
		compressed, err := Compress([]byte{}, scheme)
		require.NoError(t, err)

		decompressed, err := Decompress(compressed, scheme)
		require.NoError(t, err)
		assert.Empty(t, decompressed)
	}
}

func TestCompress_GZIP_SmallerThanOriginal(t *testing.T) {
	data := bytes.Repeat([]byte("AAAA"), 1000)
	compressed, err := Compress(data, metanet.CompressGZIP)
	require.NoError(t, err)
	assert.Less(t, len(compressed), len(data))
}

func TestCompress_UnsupportedScheme(t *testing.T) {
	_, err := Compress([]byte("data"), metanet.CompressZSTD)
	assert.ErrorIs(t, err, ErrUnsupportedCompression)
}

func TestDecompress_UnsupportedScheme(t *testing.T) {
	_, err := Decompress([]byte("data"), metanet.CompressZSTD)
	assert.ErrorIs(t, err, ErrUnsupportedCompression)
}
