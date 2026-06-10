package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/bitfsorg/libbitfs-go/spv"
)

// VerifyResult holds the result of an SPV verification.
type VerifyResult struct {
	Confirmed   bool
	BlockHash   string
	BlockHeight uint64
}

// SPVClient bridges the network layer with libbitfs/spv verification.
type SPVClient struct {
	chain   BlockchainService
	headers spv.HeaderStore

	// getBlockHash fetches block hash by height.
	// Auto-detected from BlockHashProvider interface; can also be set explicitly
	// via SetBlockHashFunc for testing or custom implementations.
	getBlockHash func(ctx context.Context, height uint64) (string, error)

	// syncMu serializes SyncHeaders calls to prevent redundant concurrent syncs. [Audit fix H-10]
	syncMu sync.Mutex
}

// NewSPVClient creates an SPV client backed by a blockchain service and header store.
// If chain implements BlockHashProvider, getBlockHash is automatically configured
// for SyncHeaders support.
func NewSPVClient(chain BlockchainService, headers spv.HeaderStore) *SPVClient {
	s := &SPVClient{
		chain:   chain,
		headers: headers,
	}
	// Auto-detect BlockHashProvider (satisfied by RPCClient and any custom implementation).
	if bhp, ok := chain.(BlockHashProvider); ok {
		s.getBlockHash = bhp.GetBlockHash
	}
	return s
}

// SetBlockHashFunc explicitly sets the function used by SyncHeaders to look up
// block hashes by height. This overrides the auto-detected BlockHashProvider.
// Useful for testing or custom blockchain service implementations.
func (s *SPVClient) SetBlockHashFunc(fn func(ctx context.Context, height uint64) (string, error)) {
	s.getBlockHash = fn
}

// VerifyTx performs SPV verification of a transaction:
//  1. Check confirmation status
//  2. For confirmed tx: fetch Merkle proof, verify against stored header
func (s *SPVClient) VerifyTx(ctx context.Context, txid string) (*VerifyResult, error) {
	status, err := s.chain.GetTxStatus(ctx, txid)
	if err != nil {
		return nil, fmt.Errorf("network: get tx status: %w", err)
	}

	if !status.Confirmed {
		return &VerifyResult{Confirmed: false}, nil
	}

	// Ensure we have the block header.
	// Block hash from RPC is in display hex (big-endian); convert to internal
	// byte order for header store lookup (which keys by DoubleHash output).
	blockHashDisplay, err := hex.DecodeString(status.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("network: invalid block hash: %w", err)
	}
	blockHashInternal := reverseBytesCopy(blockHashDisplay)

	header, err := s.headers.GetHeader(blockHashInternal)
	if err != nil {
		// Header not in store — fetch and store it.
		rawHeader, fetchErr := s.chain.GetBlockHeader(ctx, status.BlockHash)
		if fetchErr != nil {
			return nil, fmt.Errorf("network: fetch block header: %w", fetchErr)
		}
		header, err = spv.DeserializeHeader(rawHeader)
		if err != nil {
			return nil, fmt.Errorf("network: deserialize header: %w", err)
		}
		header.Height = uint32(status.BlockHeight)
		header.Hash = spv.ComputeHeaderHash(header)
		if storeErr := s.headers.PutHeader(header); storeErr != nil {
			// Treat ErrDuplicateHeader as non-fatal: another goroutine stored it first. [Audit fix H-10]
			if !errors.Is(storeErr, spv.ErrDuplicateHeader) {
				return nil, fmt.Errorf("network: store header: %w", storeErr)
			}
		}
	}

	// Fetch and verify Merkle proof.
	proof, err := s.chain.GetMerkleProof(ctx, txid)
	if err != nil {
		return nil, fmt.Errorf("network: fetch merkle proof: %w", err)
	}

	txidDisplayBytes, err := hex.DecodeString(proof.TxID)
	if err != nil {
		return nil, fmt.Errorf("network: invalid txid: %w", err)
	}
	// Convert display txid (big-endian) to internal byte order for Merkle verification.
	txidInternal := reverseBytesCopy(txidDisplayBytes)

	// Shape validation: when the block's transaction count is known, the
	// branch count must equal the Merkle tree depth (CVE-2012-2459 defense).
	if proof.TotalTxs > 0 {
		if len(proof.Branches) != merkleTreeDepth(proof.TotalTxs) {
			return nil, fmt.Errorf("network: merkle proof shape invalid for tx %s: %d branches, expected %d for %d txs",
				txid, len(proof.Branches), merkleTreeDepth(proof.TotalTxs), proof.TotalTxs)
		}
	}

	// Single-tx block: txHash IS the Merkle root, no branches needed.
	if len(proof.Branches) == 0 && proof.Index == 0 {
		if !bytes.Equal(txidInternal, header.MerkleRoot) {
			return nil, fmt.Errorf("network: merkle proof verification failed for tx %s", txid)
		}
	} else {
		spvProof := &spv.MerkleProof{
			TxID:      txidInternal,
			Index:     uint32(proof.Index),
			Nodes:     proof.Branches,
			BlockHash: blockHashInternal,
		}

		ok, verifyErr := spv.VerifyMerkleProof(spvProof, header.MerkleRoot)
		if verifyErr != nil {
			return nil, fmt.Errorf("network: verify merkle proof: %w", verifyErr)
		}
		if !ok {
			return nil, fmt.Errorf("network: merkle proof verification failed for tx %s", txid)
		}
	}

	return &VerifyResult{
		Confirmed:   true,
		BlockHash:   status.BlockHash,
		BlockHeight: status.BlockHeight,
	}, nil
}

// SyncHeaders fetches block headers from the network and stores them locally.
// Syncs from current tip to the latest block.
// Serialized via syncMu to prevent redundant concurrent syncs. [Audit fix H-10]
func (s *SPVClient) SyncHeaders(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	if s.getBlockHash == nil {
		return fmt.Errorf("network: getBlockHash not configured")
	}

	bestHeight, err := s.chain.GetBestBlockHeight(ctx)
	if err != nil {
		return fmt.Errorf("network: get best block height: %w", err)
	}

	// Determine local tip.
	var startHeight uint64
	tip, err := s.headers.GetTip()
	if err == nil && tip != nil {
		startHeight = uint64(tip.Height) + 1
	}

	for h := startHeight; h <= bestHeight; h++ {
		hash, hashErr := s.getBlockHash(ctx, h)
		if hashErr != nil {
			return fmt.Errorf("network: get block hash at %d: %w", h, hashErr)
		}

		rawHeader, hdrErr := s.chain.GetBlockHeader(ctx, hash)
		if hdrErr != nil {
			return fmt.Errorf("network: get header at %d: %w", h, hdrErr)
		}

		header, dsErr := spv.DeserializeHeader(rawHeader)
		if dsErr != nil {
			return fmt.Errorf("network: deserialize header at %d: %w", h, dsErr)
		}
		header.Height = uint32(h)
		header.Hash = spv.ComputeHeaderHash(header)

		// Validate chain continuity: header.PrevBlock must match previous header's hash.
		if h == 0 {
			// Genesis block: PrevBlock should be all zeros.
			if !bytes.Equal(header.PrevBlock, make([]byte, 32)) {
				return fmt.Errorf("network: genesis block has non-zero PrevBlock")
			}
		} else {
			prevHeader, prevErr := s.headers.GetHeaderByHeight(uint32(h - 1))
			if prevErr != nil {
				return fmt.Errorf("network: previous header at %d not found: %w", h-1, prevErr)
			}
			if !bytes.Equal(header.PrevBlock, prevHeader.Hash) {
				return fmt.Errorf("network: chain break at height %d: PrevBlock does not match header at %d", h, h-1)
			}
		}

		if putErr := s.headers.PutHeader(header); putErr != nil {
			// Treat ErrDuplicateHeader as non-fatal (concurrent sync race). [Audit fix H-10]
			if !errors.Is(putErr, spv.ErrDuplicateHeader) {
				return fmt.Errorf("network: store header at %d: %w", h, putErr)
			}
		}
	}

	return nil
}

// merkleTreeDepth returns the depth (number of branch levels above the
// leaves) of a Bitcoin Merkle tree with n transactions. Odd-width rows are
// padded by duplicating the last hash, so each level halves rounding up.
func merkleTreeDepth(n uint32) int {
	depth := 0
	for w := n; w > 1; w = (w + 1) / 2 {
		depth++
	}
	return depth
}
