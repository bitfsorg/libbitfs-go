package metanet

import (
	"github.com/tongxiaofeng/libbitfs/spv"
)

// ComputeChildLeafHash computes the Merkle leaf hash for a single ChildEntry.
// The leaf hash is DoubleHash(serialize(entry)), reusing the existing
// ChildEntry binary format and Bitcoin's double-SHA256.
func ComputeChildLeafHash(entry *ChildEntry) []byte {
	serialized := serializeChildEntry(entry)
	return spv.DoubleHash(serialized)
}

// ComputeDirectoryMerkleRoot computes the Merkle root from a directory's
// children list. Returns nil for empty or nil children slice.
//
// Algorithm (identical to Bitcoin block Merkle tree):
//  1. Compute leaf hashes: leaf[i] = DoubleHash(serialize(child[i]))
//  2. If odd count, duplicate last leaf
//  3. Pair adjacent and hash: parent = DoubleHash(left || right)
//  4. Repeat until one root remains
func ComputeDirectoryMerkleRoot(children []ChildEntry) []byte {
	if len(children) == 0 {
		return nil
	}

	// Compute leaf hashes
	leafHashes := make([][]byte, len(children))
	for i := range children {
		leafHashes[i] = ComputeChildLeafHash(&children[i])
	}

	// Build Merkle tree (same algorithm as spv.BuildMerkleTree)
	level := leafHashes
	for len(level) > 1 {
		if len(level)%2 != 0 {
			dup := make([]byte, 32)
			copy(dup, level[len(level)-1])
			level = append(level, dup)
		}

		nextLevel := make([][]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			combined := make([]byte, 64)
			copy(combined[:32], level[i])
			copy(combined[32:], level[i+1])
			nextLevel[i/2] = spv.DoubleHash(combined)
		}
		level = nextLevel
	}

	return level[0]
}
