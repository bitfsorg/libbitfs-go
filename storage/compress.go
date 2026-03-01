package storage

import (
	"bytes"
	"compress/gzip"
	"compress/lzw"
	"fmt"
	"io"

	"github.com/bitfsorg/libbitfs-go/metanet"
)

// MaxDecompressedSize is the maximum allowed decompressed data size (256 MB).
// Prevents zip-bomb attacks where a small compressed payload expands to exhaust memory.
const MaxDecompressedSize = 256 << 20

// Compress compresses data using the specified scheme.
func Compress(data []byte, scheme int32) ([]byte, error) {
	switch scheme {
	case metanet.CompressNone:
		return data, nil
	case metanet.CompressLZW:
		return compressLZW(data)
	case metanet.CompressGZIP:
		return compressGZIP(data)
	default:
		return nil, ErrUnsupportedCompression
	}
}

// Decompress decompresses data using the specified scheme.
func Decompress(data []byte, scheme int32) ([]byte, error) {
	switch scheme {
	case metanet.CompressNone:
		return data, nil
	case metanet.CompressLZW:
		return decompressLZW(data)
	case metanet.CompressGZIP:
		return decompressGZIP(data)
	default:
		return nil, ErrUnsupportedCompression
	}
}

func compressLZW(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := lzw.NewWriter(&buf, lzw.LSB, 8)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressLZW(data []byte) ([]byte, error) {
	r := lzw.NewReader(bytes.NewReader(data), lzw.LSB, 8)
	limited := io.LimitReader(r, MaxDecompressedSize+1)
	result, err := io.ReadAll(limited)
	if closeErr := r.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if len(result) > MaxDecompressedSize {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrDecompressedTooLarge, MaxDecompressedSize)
	}
	return result, nil
}

func compressGZIP(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressGZIP(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	limited := io.LimitReader(r, MaxDecompressedSize+1)
	result, readErr := io.ReadAll(limited)
	if closeErr := r.Close(); closeErr != nil && readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		return nil, readErr
	}
	if len(result) > MaxDecompressedSize {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrDecompressedTooLarge, MaxDecompressedSize)
	}
	return result, nil
}
