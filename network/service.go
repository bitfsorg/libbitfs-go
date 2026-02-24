package network

import "context"

// BlockchainService is the primary interface for blockchain interaction.
// Both BitFS and Metanet products import and use this interface.
type BlockchainService interface {
	// ListUnspent returns all unspent transaction outputs for the given address.
	ListUnspent(ctx context.Context, address string) ([]*UTXO, error)

	// GetUTXO returns a specific unspent transaction output by txid and output index.
	GetUTXO(ctx context.Context, txid string, vout uint32) (*UTXO, error)

	// BroadcastTx submits a raw transaction hex to the network and returns the txid.
	BroadcastTx(ctx context.Context, rawTxHex string) (string, error)

	// GetRawTx returns the raw transaction bytes for the given txid.
	GetRawTx(ctx context.Context, txid string) ([]byte, error)

	// GetTxStatus returns the confirmation status of a transaction.
	GetTxStatus(ctx context.Context, txid string) (*TxStatus, error)

	// GetBlockHeader returns the raw 80-byte block header for the given block hash.
	GetBlockHeader(ctx context.Context, blockHash string) ([]byte, error)

	// GetMerkleProof returns a Merkle inclusion proof for a confirmed transaction.
	GetMerkleProof(ctx context.Context, txid string) (*MerkleProof, error)

	// GetBestBlockHeight returns the height of the current chain tip.
	GetBestBlockHeight(ctx context.Context) (uint64, error)

	// ImportAddress imports a watch-only address into the node's wallet so that
	// ListUnspent can find its UTXOs. Rescans the chain to discover existing outputs.
	// No-op if the address is already imported. Safe to call multiple times.
	ImportAddress(ctx context.Context, address string) error
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	TxID          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	Amount        uint64 `json:"amount"`
	ScriptPubKey  string `json:"script_pubkey"`
	Address       string `json:"address"`
	Confirmations int64  `json:"confirmations"`
}

// TxStatus represents the confirmation status of a transaction.
type TxStatus struct {
	Confirmed   bool   `json:"confirmed"`
	BlockHash   string `json:"block_hash"`
	BlockHeight uint64 `json:"block_height"`
	TxIndex     int    `json:"tx_index"`
}

// MerkleProof represents a Merkle inclusion proof for SPV verification.
type MerkleProof struct {
	TxID      string   `json:"txid"`
	BlockHash string   `json:"block_hash"`
	Branches  [][]byte `json:"branches"`
	Index     int      `json:"index"`
}
