package tx

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// UTXO represents an unspent transaction output tracked by the wallet.
type UTXO struct {
	TxID         []byte         `json:"txid"`          // 32 bytes
	Vout         uint32         `json:"vout"`
	Amount       uint64         `json:"amount"`        // satoshis
	ScriptPubKey []byte         `json:"script_pubkey"` // locking script bytes
	PrivateKey   *ec.PrivateKey `json:"-"`             // signing key (not serialized)
}

// MetanetTx wraps a built BSV transaction with metadata about produced UTXOs.
type MetanetTx struct {
	RawTx       []byte // Serialized transaction bytes
	TxID        []byte // Transaction hash (32 bytes)
	NodeUTXO    *UTXO  // Output 1: P_node UTXO
	ParentUTXO  *UTXO  // Output 2: P_parent refresh UTXO (nil for root/self-update)
	ChangeUTXO  *UTXO  // Last output: change UTXO (nil if dust)
}
