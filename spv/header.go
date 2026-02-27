package spv

import (
	"encoding/binary"
	"fmt"
	"math/big"
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

// CompactToTarget converts a Bitcoin "compact" (nBits) representation to a 32-byte
// big-endian target value. Format: 0xEEMMMMMM where EE=exponent, MMMMMM=mantissa.
func CompactToTarget(bits uint32) []byte {
	exponent := bits >> 24
	mantissa := bits & 0x007fffff
	// Negative flag (bit 23 of mantissa) — treat as zero target.
	if bits&0x00800000 != 0 {
		mantissa = 0
	}

	target := make([]byte, 32)
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		target[31] = byte(mantissa)
		target[30] = byte(mantissa >> 8)
		target[29] = byte(mantissa >> 16)
	} else {
		pos := 32 - int(exponent)
		if pos >= 0 && pos < 32 {
			target[pos] = byte(mantissa >> 16)
		}
		if pos+1 >= 0 && pos+1 < 32 {
			target[pos+1] = byte(mantissa >> 8)
		}
		if pos+2 >= 0 && pos+2 < 32 {
			target[pos+2] = byte(mantissa)
		}
	}
	return target
}

// VerifyPoW checks that a block header's hash meets its stated difficulty target.
// The header hash (double-SHA256 output, big-endian as 256-bit integer) must be
// numerically <= the target derived from Bits.
func VerifyPoW(h *BlockHeader) error {
	if h == nil {
		return fmt.Errorf("%w: header", ErrNilParam)
	}
	hash := h.Hash
	if len(hash) == 0 {
		hash = ComputeHeaderHash(h)
	}
	target := CompactToTarget(h.Bits)

	// Compare hash vs target byte-by-byte in big-endian order (MSB first).
	// SHA256 output is naturally big-endian.
	for i := 0; i < 32; i++ {
		if hash[i] < target[i] {
			return nil // hash < target → valid
		}
		if hash[i] > target[i] {
			return fmt.Errorf("%w: hash exceeds target", ErrInsufficientPoW)
		}
	}
	return nil // hash == target → valid
}

// Network identifies the BSV network for difficulty validation.
type Network int

const (
	// Mainnet is the BSV production network.
	Mainnet Network = iota
	// Testnet is the BSV test network.
	Testnet
	// Regtest is the BSV regression test network.
	Regtest
)

// Minimum difficulty (nBits) for each network. These represent the easiest
// allowed target — the genesis-block difficulty for mainnet, and the
// well-known defaults for testnet and regtest.
const (
	// MainnetMinBits is the genesis difficulty: 0x1d00ffff.
	MainnetMinBits uint32 = 0x1d00ffff
	// TestnetMinBits mirrors mainnet genesis difficulty.
	TestnetMinBits uint32 = 0x1d00ffff
	// RegtestMinBits is the standard regtest minimum: 0x207fffff.
	RegtestMinBits uint32 = 0x207fffff
)

// maxDifficultyAdjustmentFactor is the maximum factor by which nBits can
// change between two consecutive headers (4x up or down). This is a
// simplified bound check suitable for a light client — full nodes use
// the exact DAA calculation.
const maxDifficultyAdjustmentFactor = 4

// MinBitsForNetwork returns the minimum nBits (easiest target) for the given network.
func MinBitsForNetwork(net Network) uint32 {
	switch net {
	case Testnet:
		return TestnetMinBits
	case Regtest:
		return RegtestMinBits
	default:
		return MainnetMinBits
	}
}

// two256 is the constant 2^256, precomputed for work calculations.
var two256 *big.Int

func init() {
	two256 = new(big.Int).Lsh(big.NewInt(1), 256)
}

// CompactToBig converts a Bitcoin compact (nBits) representation to a big.Int target value.
func CompactToBig(bits uint32) *big.Int {
	exponent := bits >> 24
	mantissa := int64(bits & 0x007fffff)
	if bits&0x00800000 != 0 {
		mantissa = 0 // negative flag — treat as zero target
	}

	target := big.NewInt(mantissa)
	if exponent <= 3 {
		target.Rsh(target, uint(8*(3-exponent)))
	} else {
		target.Lsh(target, uint(8*(exponent-3)))
	}
	return target
}

// WorkForTarget computes the expected number of hashes to find a block
// at the given compact difficulty: work = 2^256 / (target + 1).
// Returns zero work for a zero or negative target.
func WorkForTarget(bits uint32) *big.Int {
	target := CompactToBig(bits)
	if target.Sign() <= 0 {
		return new(big.Int)
	}

	// work = 2^256 / (target + 1)
	denominator := new(big.Int).Add(target, big.NewInt(1))
	return new(big.Int).Div(two256, denominator)
}

// CumulativeWork computes the total chain work for a sequence of headers.
// Each header contributes WorkForTarget(header.Bits) to the sum.
func CumulativeWork(headers []*BlockHeader) *big.Int {
	total := new(big.Int)
	for _, h := range headers {
		if h == nil {
			continue
		}
		total.Add(total, WorkForTarget(h.Bits))
	}
	return total
}

// ChainVerificationResult holds the output of VerifyHeaderChainWithWork.
type ChainVerificationResult struct {
	// CumulativeWork is the total chain work across all verified headers.
	CumulativeWork *big.Int
}

// ValidateMinDifficulty checks that a header's nBits meets the minimum
// difficulty for the given network. The minimum difficulty is the easiest
// target allowed — a higher nBits target value means less work.
func ValidateMinDifficulty(header *BlockHeader, net Network) error {
	if header == nil {
		return fmt.Errorf("%w: header", ErrNilParam)
	}

	minBits := MinBitsForNetwork(net)
	minTarget := CompactToBig(minBits)
	headerTarget := CompactToBig(header.Bits)

	// A header's target must not exceed the network minimum target.
	// Higher target = easier mining = less security.
	if headerTarget.Cmp(minTarget) > 0 {
		return fmt.Errorf("%w: bits 0x%08x exceeds minimum 0x%08x for network",
			ErrDifficultyTooLow, header.Bits, minBits)
	}

	return nil
}

// ValidateDifficultyTransition checks that the difficulty change between two
// consecutive headers does not exceed the allowed bounds (factor of 4).
// This is a simplified check for a light client — it catches grossly invalid
// difficulty transitions without implementing the full DAA algorithm.
func ValidateDifficultyTransition(prev, curr *BlockHeader) error {
	if prev == nil || curr == nil {
		return fmt.Errorf("%w: header", ErrNilParam)
	}

	prevTarget := CompactToBig(prev.Bits)
	currTarget := CompactToBig(curr.Bits)

	// Skip the check if either target is zero (degenerate case).
	if prevTarget.Sign() <= 0 || currTarget.Sign() <= 0 {
		return nil
	}

	// Check: currTarget <= prevTarget * maxFactor
	// AND:   currTarget >= prevTarget / maxFactor
	factor := big.NewInt(maxDifficultyAdjustmentFactor)

	maxTarget := new(big.Int).Mul(prevTarget, factor)
	if currTarget.Cmp(maxTarget) > 0 {
		return fmt.Errorf("%w: target increased by more than %dx", ErrDifficultyChange, maxDifficultyAdjustmentFactor)
	}

	minTarget := new(big.Int).Div(prevTarget, factor)
	if currTarget.Cmp(minTarget) < 0 {
		return fmt.Errorf("%w: target decreased by more than %dx", ErrDifficultyChange, maxDifficultyAdjustmentFactor)
	}

	return nil
}

// VerifyHeaderChainWithWork verifies a header chain (PoW + linkage + difficulty)
// and returns the cumulative work. The network parameter controls the minimum
// difficulty check. Pass Regtest for test environments.
func VerifyHeaderChainWithWork(headers []*BlockHeader, net Network) (*ChainVerificationResult, error) {
	if len(headers) == 0 {
		return &ChainVerificationResult{CumulativeWork: new(big.Int)}, nil
	}

	result := &ChainVerificationResult{
		CumulativeWork: new(big.Int),
	}

	// Validate first header.
	if headers[0] == nil {
		return nil, fmt.Errorf("%w: nil header at index 0", ErrNilParam)
	}
	if err := VerifyPoW(headers[0]); err != nil {
		return nil, fmt.Errorf("header 0: %w", err)
	}
	if err := ValidateMinDifficulty(headers[0], net); err != nil {
		return nil, fmt.Errorf("header 0: %w", err)
	}
	result.CumulativeWork.Add(result.CumulativeWork, WorkForTarget(headers[0].Bits))

	for i := 1; i < len(headers); i++ {
		prev := headers[i-1]
		curr := headers[i]

		if prev == nil || curr == nil {
			return nil, fmt.Errorf("%w: nil header at index %d", ErrNilParam, i)
		}

		// Compute prev hash if not set.
		prevHash := prev.Hash
		if len(prevHash) == 0 {
			prevHash = ComputeHeaderHash(prev)
		}

		if len(curr.PrevBlock) != HashSize {
			return nil, fmt.Errorf("%w: header at index %d has invalid PrevBlock length", ErrInvalidHeader, i)
		}

		if len(prevHash) != HashSize {
			return nil, fmt.Errorf("%w: header at index %d has invalid hash", ErrInvalidHeader, i-1)
		}

		for j := 0; j < HashSize; j++ {
			if curr.PrevBlock[j] != prevHash[j] {
				return nil, fmt.Errorf("%w: header %d PrevBlock does not match header %d hash", ErrChainBroken, i, i-1)
			}
		}

		// Validate PoW.
		if err := VerifyPoW(curr); err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}

		// Validate minimum difficulty.
		if err := ValidateMinDifficulty(curr, net); err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}

		// Validate difficulty transition.
		if err := ValidateDifficultyTransition(prev, curr); err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}

		// Accumulate work.
		result.CumulativeWork.Add(result.CumulativeWork, WorkForTarget(curr.Bits))
	}

	return result, nil
}

// VerifyHeaderChain checks that a sequence of headers forms a valid chain.
// Each header's PrevBlock must match the previous header's Hash.
// Headers must be provided in ascending order (index 0 is earliest).
func VerifyHeaderChain(headers []*BlockHeader) error {
	if len(headers) == 0 {
		return nil
	}

	// Validate PoW for the first header.
	if headers[0] == nil {
		return fmt.Errorf("%w: nil header at index 0", ErrNilParam)
	}
	if err := VerifyPoW(headers[0]); err != nil {
		return fmt.Errorf("header 0: %w", err)
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

		// Validate PoW for each subsequent header.
		if err := VerifyPoW(curr); err != nil {
			return fmt.Errorf("header %d: %w", i, err)
		}
	}

	return nil
}
