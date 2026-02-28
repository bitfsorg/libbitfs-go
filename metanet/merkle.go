package metanet

import (
	"fmt"

	"github.com/bitfsorg/libbitfs-go/spv"
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

// BuildDirectoryMerkleProof builds a Merkle proof for a child at the given
// position index. Returns the sibling hashes needed to recompute the root.
// For a single child, returns an empty proof (the leaf IS the root).
func BuildDirectoryMerkleProof(children []ChildEntry, childIndex int) ([][]byte, error) {
	if len(children) == 0 {
		return nil, fmt.Errorf("metanet: cannot build proof for empty children")
	}
	if childIndex < 0 || childIndex >= len(children) {
		return nil, fmt.Errorf("metanet: child index %d out of range [0, %d)", childIndex, len(children))
	}

	// Single child: no proof needed (leaf is root)
	if len(children) == 1 {
		return nil, nil
	}

	// Compute all leaf hashes
	level := make([][]byte, len(children))
	for i := range children {
		level[i] = ComputeChildLeafHash(&children[i])
	}

	var proof [][]byte
	idx := childIndex

	for len(level) > 1 {
		// Pad if odd
		if len(level)%2 != 0 {
			dup := make([]byte, 32)
			copy(dup, level[len(level)-1])
			level = append(level, dup)
		}

		// Collect sibling
		if idx%2 == 0 {
			sibling := make([]byte, 32)
			copy(sibling, level[idx+1])
			proof = append(proof, sibling)
		} else {
			sibling := make([]byte, 32)
			copy(sibling, level[idx-1])
			proof = append(proof, sibling)
		}

		// Build next level
		nextLevel := make([][]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			combined := make([]byte, 64)
			copy(combined[:32], level[i])
			copy(combined[32:], level[i+1])
			nextLevel[i/2] = spv.DoubleHash(combined)
		}
		level = nextLevel
		idx /= 2
	}

	return proof, nil
}

// VerifyChildMembership verifies that a ChildEntry belongs to a directory
// with the given MerkleRoot, using the provided proof path and position index.
func VerifyChildMembership(entry *ChildEntry, proof [][]byte, index int, merkleRoot []byte) bool {
	if entry == nil || len(merkleRoot) != 32 {
		return false
	}

	leafHash := ComputeChildLeafHash(entry)

	// Use spv.ComputeMerkleRoot to walk the proof
	computed := spv.ComputeMerkleRoot(leafHash, uint32(index), proof)
	if computed == nil {
		// Single child case: no proof nodes, leaf is root
		if len(proof) == 0 && index == 0 {
			for i := 0; i < 32; i++ {
				if leafHash[i] != merkleRoot[i] {
					return false
				}
			}
			return true
		}
		return false
	}

	for i := 0; i < 32; i++ {
		if computed[i] != merkleRoot[i] {
			return false
		}
	}
	return true
}
