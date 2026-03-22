package network

import (
	"context"
	"fmt"
)

// Compile-time interface checks.
var (
	_ BlockchainService = (*WoCARCClient)(nil)
	_ BlockHashProvider = (*WoCARCClient)(nil)
)

// WoCARCClient combines WoC (queries) and ARC (broadcast) into a single BlockchainService.
type WoCARCClient struct {
	woc *WoCClient
	arc *ARCClient
}

// WoCARCConfig holds configuration for the composite client.
type WoCARCConfig struct {
	WoC WoCConfig
	ARC ARCConfig
}

// NewWoCARCClient creates a composite BlockchainService using WoC for queries and ARC for broadcast.
func NewWoCARCClient(cfg WoCARCConfig) *WoCARCClient {
	return &WoCARCClient{
		woc: NewWoCClient(cfg.WoC),
		arc: NewARCClient(cfg.ARC),
	}
}

// DefaultWoCARCEndpoints returns default WoC and ARC base URLs for the given network.
func DefaultWoCARCEndpoints(network string) (wocBase, arcBase string, err error) {
	switch network {
	case "mainnet":
		return "https://api.whatsonchain.com/v1/bsv/main", "https://arc.taal.com/v1", nil
	case "testnet":
		return "https://api.whatsonchain.com/v1/bsv/test", "https://arc.taal.com/v1", nil
	default:
		return "", "", fmt.Errorf("network: WoC+ARC not available for %q (use RPC)", network)
	}
}

// ---------- BlockchainService implementation (queries → WoC) ----------

// ListUnspent returns all unspent transaction outputs for the given address.
func (c *WoCARCClient) ListUnspent(ctx context.Context, address string) ([]*UTXO, error) {
	return c.woc.ListUnspent(ctx, address)
}

// GetUTXO returns a specific unspent transaction output by txid and output index.
func (c *WoCARCClient) GetUTXO(ctx context.Context, txid string, vout uint32) (*UTXO, error) {
	return c.woc.GetUTXO(ctx, txid, vout)
}

// GetRawTx returns the raw transaction bytes for the given txid.
func (c *WoCARCClient) GetRawTx(ctx context.Context, txid string) ([]byte, error) {
	return c.woc.GetRawTx(ctx, txid)
}

// GetTxStatus returns the confirmation status of a transaction.
func (c *WoCARCClient) GetTxStatus(ctx context.Context, txid string) (*TxStatus, error) {
	return c.woc.GetTxStatus(ctx, txid)
}

// GetBlockHeader returns the raw 80-byte block header for the given block hash.
func (c *WoCARCClient) GetBlockHeader(ctx context.Context, blockHash string) ([]byte, error) {
	return c.woc.GetBlockHeader(ctx, blockHash)
}

// GetMerkleProof returns a Merkle inclusion proof for a confirmed transaction.
func (c *WoCARCClient) GetMerkleProof(ctx context.Context, txid string) (*MerkleProof, error) {
	return c.woc.GetMerkleProof(ctx, txid)
}

// GetBestBlockHeight returns the height of the current chain tip.
func (c *WoCARCClient) GetBestBlockHeight(ctx context.Context) (uint64, error) {
	return c.woc.GetBestBlockHeight(ctx)
}

// ImportAddress is a no-op for WoC. WhatsOnChain indexes all addresses automatically.
func (c *WoCARCClient) ImportAddress(ctx context.Context, address string) error {
	return c.woc.ImportAddress(ctx, address)
}

// ---------- Broadcast → ARC ----------

// BroadcastTx submits a raw transaction hex via ARC. No WoC fallback on failure.
func (c *WoCARCClient) BroadcastTx(ctx context.Context, rawTxHex string) (string, error) {
	return c.arc.BroadcastTx(ctx, rawTxHex)
}

// ---------- BlockHashProvider implementation → WoC ----------

// GetBlockHash returns the block hash at the given height.
func (c *WoCARCClient) GetBlockHash(ctx context.Context, height uint64) (string, error) {
	return c.woc.GetBlockHash(ctx, height)
}
