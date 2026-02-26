package spv

import (
	"crypto/sha256"
	"fmt"
)

// DoubleHash computes SHA256(SHA256(data)), matching Bitcoin's hash function.
func DoubleHash(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// ComputeMerkleRoot computes the Merkle root from a transaction hash,
// its index position in the block, and the proof branch nodes (bottom-up).
//
// Algorithm:
//
//	hash = txHash
//	for i, node in proofNodes:
//	    if bit i of index is 0:  hash = DoubleHash(hash || node)
//	    else:                     hash = DoubleHash(node || hash)
func ComputeMerkleRoot(txHash []byte, index uint32, proofNodes [][]byte) []byte {
	if len(txHash) != 32 {
		return nil
	}

	hash := make([]byte, 32)
	copy(hash, txHash)

	for i, node := range proofNodes {
		if len(node) != 32 {
			return nil
		}
		combined := make([]byte, 64)
		if (index>>uint(i))&1 == 0 {
			// Current hash is on the left
			copy(combined[:32], hash)
			copy(combined[32:], node)
		} else {
			// Current hash is on the right
			copy(combined[:32], node)
			copy(combined[32:], hash)
		}
		hash = DoubleHash(combined)
	}

	return hash
}

// VerifyMerkleProof verifies that a transaction is included in a block.
// It recomputes the Merkle path from TxID + proof nodes and checks against
// the expected Merkle root from the block header.
func VerifyMerkleProof(proof *MerkleProof, expectedMerkleRoot []byte) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("%w: proof", ErrNilParam)
	}
	if len(proof.TxID) != 32 {
		return false, fmt.Errorf("%w: TxID must be 32 bytes", ErrInvalidTxID)
	}
	if len(expectedMerkleRoot) != 32 {
		return false, fmt.Errorf("%w: expected merkle root must be 32 bytes", ErrInvalidHeader)
	}
	computedRoot := ComputeMerkleRoot(proof.TxID, proof.Index, proof.Nodes)
	if computedRoot == nil {
		return false, fmt.Errorf("%w: failed to compute merkle root", ErrMerkleProofInvalid)
	}

	for i := 0; i < 32; i++ {
		if computedRoot[i] != expectedMerkleRoot[i] {
			return false, ErrMerkleProofInvalid
		}
	}

	return true, nil
}

// BuildMerkleTree builds a full Merkle tree from a list of transaction hashes.
// Returns all tree levels, where level 0 is leaves and the last level is the root.
// Each level is padded by duplicating the last element if odd.
func BuildMerkleTree(txHashes [][]byte) [][]byte {
	if len(txHashes) == 0 {
		return nil
	}

	// Copy leaves
	level := make([][]byte, len(txHashes))
	for i, h := range txHashes {
		level[i] = make([]byte, 32)
		copy(level[i], h)
	}

	// Build tree levels until we reach the root
	for len(level) > 1 {
		// If odd number, duplicate last element
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
			nextLevel[i/2] = DoubleHash(combined)
		}
		level = nextLevel
	}

	return level
}

// ComputeMerkleRootFromTxList computes the Merkle root from a list of transaction IDs.
// This is used when you have all transactions in a block and want to verify
// the block header's Merkle root.
func ComputeMerkleRootFromTxList(txIDs [][]byte) []byte {
	tree := BuildMerkleTree(txIDs)
	if tree == nil {
		return nil
	}
	// BuildMerkleTree returns a single-element slice at the root level
	return tree[0]
}
