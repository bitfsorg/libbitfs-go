package spv

import (
	"encoding/binary"
	"fmt"
)

const (
	// BlockHeaderSize is the size of a serialized BSV block header in bytes.
	BlockHeaderSize = 80

	// HashSize is the size of a SHA256 hash in bytes.
	HashSize = 32
)

// BlockHeader represents a BSV block header (80 bytes serialized).
type BlockHeader struct {
	Version    int32  // 4 bytes, little-endian
	PrevBlock  []byte // 32 bytes
	MerkleRoot []byte // 32 bytes
	Timestamp  uint32 // 4 bytes, little-endian (Unix timestamp)
	Bits       uint32 // 4 bytes, little-endian (compact target)
	Nonce      uint32 // 4 bytes, little-endian
	Height     uint32 // Not in raw header; tracked separately
	Hash       []byte // Computed: double-SHA256 of 80-byte header
}

// SerializeHeader serializes a BlockHeader to 80 bytes in BSV wire format.
//
// Layout: version(4) | prevBlock(32) | merkleRoot(32) | timestamp(4) | bits(4) | nonce(4)
func SerializeHeader(h *BlockHeader) []byte {
	if h == nil {
		return nil
	}

	buf := make([]byte, BlockHeaderSize)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(h.Version))
	copy(buf[4:36], h.PrevBlock)
	copy(buf[36:68], h.MerkleRoot)
	binary.LittleEndian.PutUint32(buf[68:72], h.Timestamp)
	binary.LittleEndian.PutUint32(buf[72:76], h.Bits)
	binary.LittleEndian.PutUint32(buf[76:80], h.Nonce)

	return buf
}

// DeserializeHeader deserializes 80 bytes into a BlockHeader.
// The Hash field is computed from the serialized data.
func DeserializeHeader(data []byte) (*BlockHeader, error) {
	if len(data) != BlockHeaderSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidHeader, BlockHeaderSize, len(data))
	}

	h := &BlockHeader{
		Version:    int32(binary.LittleEndian.Uint32(data[0:4])),
		PrevBlock:  make([]byte, HashSize),
		MerkleRoot: make([]byte, HashSize),
		Timestamp:  binary.LittleEndian.Uint32(data[68:72]),
		Bits:       binary.LittleEndian.Uint32(data[72:76]),
		Nonce:      binary.LittleEndian.Uint32(data[76:80]),
	}

	copy(h.PrevBlock, data[4:36])
	copy(h.MerkleRoot, data[36:68])

	// Compute header hash
	h.Hash = DoubleHash(data)

	return h, nil
}

// ComputeHeaderHash computes and returns the double-SHA256 hash of a block header.
func ComputeHeaderHash(h *BlockHeader) []byte {
	raw := SerializeHeader(h)
	if raw == nil {
		return nil
	}
	return DoubleHash(raw)
}

// VerifyHeaderChain checks that a sequence of headers forms a valid chain.
// Each header's PrevBlock must match the previous header's Hash.
// Headers must be provided in ascending order (index 0 is earliest).
func VerifyHeaderChain(headers []*BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}
	if len(headers) == 1 {
		return nil
	}

	for i := 1; i < len(headers); i++ {
		prev := headers[i-1]
		curr := headers[i]

		if prev == nil || curr == nil {
			return fmt.Errorf("%w: nil header at index %d", ErrNilParam, i)
		}

		// Compute prev hash if not set
		prevHash := prev.Hash
		if len(prevHash) == 0 {
			prevHash = ComputeHeaderHash(prev)
		}

		if len(curr.PrevBlock) != HashSize {
			return fmt.Errorf("%w: header at index %d has invalid PrevBlock length", ErrInvalidHeader, i)
		}

		if len(prevHash) != HashSize {
			return fmt.Errorf("%w: header at index %d has invalid hash", ErrInvalidHeader, i-1)
		}

		for j := 0; j < HashSize; j++ {
			if curr.PrevBlock[j] != prevHash[j] {
				return fmt.Errorf("%w: header %d PrevBlock does not match header %d hash", ErrChainBroken, i, i-1)
			}
		}
	}

	return nil
}
