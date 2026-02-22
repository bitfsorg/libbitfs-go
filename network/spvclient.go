package network

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/tongxiaofeng/libbitfs/spv"
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
	blockHashBytes, err := hex.DecodeString(status.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("network: invalid block hash: %w", err)
	}

	header, err := s.headers.GetHeader(blockHashBytes)
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

	txidBytes, err := hex.DecodeString(proof.TxID)
	if err != nil {
		return nil, fmt.Errorf("network: invalid txid: %w", err)
	}

	// Single-tx block: txHash IS the Merkle root, no branches needed.
	if len(proof.Branches) == 0 && proof.Index == 0 {
		if !bytesEqual(txidBytes, header.MerkleRoot) {
			return nil, fmt.Errorf("network: merkle proof verification failed for tx %s", txid)
		}
	} else {
		spvProof := &spv.MerkleProof{
			TxID:      txidBytes,
			Index:     uint32(proof.Index),
			Nodes:     proof.Branches,
			BlockHash: blockHashBytes,
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
