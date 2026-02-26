package storage

import (
	"bytes"
	"compress/gzip"
	"compress/lzw"
	"io"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
)

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
	defer r.Close()
	return io.ReadAll(r)
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
	defer r.Close()
	return io.ReadAll(r)
}
