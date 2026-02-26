package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/tongxiaofeng/libbitfs-go/spv"
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
	// Injected in tests; for RPCClient, set automatically.
	getBlockHash func(ctx context.Context, height uint64) (string, error)
}

// NewSPVClient creates an SPV client backed by a blockchain service and header store.
func NewSPVClient(chain BlockchainService, headers spv.HeaderStore) *SPVClient {
	s := &SPVClient{
		chain:   chain,
		headers: headers,
	}
	// If chain is an RPCClient, wire up getBlockHash via RPC.
	if rpc, ok := chain.(*RPCClient); ok {
		s.getBlockHash = func(ctx context.Context, height uint64) (string, error) {
			var hash string
			err := rpc.Call(ctx, "getblockhash", []interface{}{height}, &hash)
			return hash, err
		}
	}
	return s
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
			return nil, fmt.Errorf("network: store header: %w", storeErr)
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

	// Single-tx block: txHash IS the Merkle root, no branches needed.
	if len(proof.Branches) == 0 && proof.Index == 0 {
		if !bytesEqual(txidInternal, header.MerkleRoot) {
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
func (s *SPVClient) SyncHeaders(ctx context.Context) error {
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
			return fmt.Errorf("network: store header at %d: %w", h, putErr)
		}
	}

	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
