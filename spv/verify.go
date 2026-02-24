package spv

import (
	"bytes"
	"fmt"
)

// MerkleProof represents a Merkle inclusion proof for a transaction.
type MerkleProof struct {
	TxID      []byte   // Transaction hash (32 bytes)
	Index     uint32   // Position in the block's transaction list
	Nodes     [][]byte // Merkle branch hashes, bottom-up
	BlockHash []byte   // Block header hash this proof is for
}

// StoredTx represents a transaction stored with its Merkle proof.
type StoredTx struct {
	TxID        []byte       // 32 bytes
	RawTx       []byte       // Full serialized transaction
	Proof       *MerkleProof // Merkle proof (nil = unconfirmed)
	BlockHeight uint32       // 0 = unconfirmed
	Timestamp   uint64       // Time added to store
}

// VerifyTransaction performs the full SPV verification chain:
//  1. Transaction integrity: TxID is valid (32 bytes, non-zero)
//  2. Merkle proof: tx is included in a block (via VerifyMerkleProof)
//  3. Block header: Merkle root matches the stored block header
//  4. Chain verification: block header exists in the header store
func VerifyTransaction(tx *StoredTx, headers HeaderStore) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if headers == nil {
		return fmt.Errorf("%w: header store", ErrNilParam)
	}

	// Step 1: Transaction integrity - TxID must be valid
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	// Verify RawTx integrity: DoubleSHA256(RawTx) must match TxID.
	if len(tx.RawTx) > 0 {
		computed := DoubleHash(tx.RawTx)
		if !bytes.Equal(computed, tx.TxID) {
			return fmt.Errorf("%w: RawTx hash does not match TxID", ErrInvalidTxID)
		}
	}

	// Step 2: Must have a Merkle proof (confirmed transaction)
	if tx.Proof == nil {
		return ErrUnconfirmed
	}

	// Verify proof TxID matches stored TxID
	if !bytes.Equal(tx.TxID, tx.Proof.TxID) {
		return fmt.Errorf("%w: stored TxID does not match proof TxID", ErrMerkleProofInvalid)
	}

	// Step 3: Look up the block header
	if len(tx.Proof.BlockHash) != HashSize {
		return fmt.Errorf("%w: proof block hash must be %d bytes", ErrInvalidHeader, HashSize)
	}

	header, err := headers.GetHeader(tx.Proof.BlockHash)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHeaderNotFound, err)
	}
	if header == nil {
		return ErrHeaderNotFound
	}

	// Step 4: Verify the Merkle proof against the header's Merkle root
	valid, err := VerifyMerkleProof(tx.Proof, header.MerkleRoot)
	if err != nil {
		return err
	}
	if !valid {
		return ErrMerkleProofInvalid
	}

	return nil
}
