package network

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
)

// Compile-time interface check.
var _ BlockchainService = (*RPCClient)(nil)

// btcToSat converts a BTC float64 amount (as returned by the RPC node) to satoshis.
// It uses math.Round to avoid floating-point truncation issues.
func btcToSat(btc float64) uint64 {
	return uint64(math.Round(btc * 1e8))
}

// parseCMerkleBlock performs minimal validation of a CMerkleBlock binary blob.
// Full parsing (extracting branches, matching partial Merkle tree) is deferred
// to the SPVClient layer. For now, we only validate minimum length (80-byte
// block header + 4-byte numTransactions) and return a stub MerkleProof.
func parseCMerkleBlock(txid string, data []byte) (*MerkleProof, error) {
	if len(data) < 84 {
		return nil, fmt.Errorf("%w: CMerkleBlock too short (%d bytes)", ErrInvalidResponse, len(data))
	}
	return &MerkleProof{
		TxID:      txid,
		BlockHash: "",
		Branches:  nil,
		Index:     0,
	}, nil
}

// listUnspentResult maps the JSON fields returned by the Bitcoin RPC listunspent call.
type listUnspentResult struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	Amount        float64 `json:"amount"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	Address       string  `json:"address"`
	Confirmations int64   `json:"confirmations"`
}

// ListUnspent returns all unspent transaction outputs for the given address.
// It calls `listunspent 0 9999999 ["address"]` and converts BTC amounts to satoshis.
func (c *RPCClient) ListUnspent(ctx context.Context, address string) ([]*UTXO, error) {
	params := []interface{}{0, 9999999, []string{address}}
	var results []listUnspentResult
	if err := c.Call(ctx, "listunspent", params, &results); err != nil {
		return nil, err
	}

	utxos := make([]*UTXO, len(results))
	for i, r := range results {
		utxos[i] = &UTXO{
			TxID:          r.TxID,
			Vout:          r.Vout,
			Amount:        btcToSat(r.Amount),
			ScriptPubKey:  r.ScriptPubKey,
			Address:       r.Address,
			Confirmations: r.Confirmations,
		}
	}
	return utxos, nil
}

// gettxoutResult maps the JSON fields returned by the Bitcoin RPC gettxout call.
// The pointer type allows detecting JSON null (spent output) vs present result.
type gettxoutResult struct {
	Value         float64 `json:"value"`
	Confirmations int64   `json:"confirmations"`
	ScriptPubKey  struct {
		Hex       string   `json:"hex"`
		Addresses []string `json:"addresses"`
	} `json:"scriptPubKey"`
}

// GetUTXO returns a specific unspent transaction output by txid and output index.
// It calls `gettxout "txid" vout`. When the output is spent, gettxout returns JSON null,
// which is detected and returned as ErrTxNotFound.
func (c *RPCClient) GetUTXO(ctx context.Context, txid string, vout uint32) (*UTXO, error) {
	params := []interface{}{txid, vout}
	var result *gettxoutResult
	if err := c.Call(ctx, "gettxout", params, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("%w: output %s:%d is spent", ErrTxNotFound, txid, vout)
	}

	utxo := &UTXO{
		TxID:          txid,
		Vout:          vout,
		Amount:        btcToSat(result.Value),
		ScriptPubKey:  result.ScriptPubKey.Hex,
		Confirmations: result.Confirmations,
	}
	if len(result.ScriptPubKey.Addresses) > 0 {
		utxo.Address = result.ScriptPubKey.Addresses[0]
	}
	return utxo, nil
}

// BroadcastTx submits a raw transaction hex to the network and returns the txid.
// It calls `sendrawtransaction "hex"`. RPC errors are wrapped with ErrBroadcastRejected.
func (c *RPCClient) BroadcastTx(ctx context.Context, rawTxHex string) (string, error) {
	params := []interface{}{rawTxHex}
	var txid string
	if err := c.Call(ctx, "sendrawtransaction", params, &txid); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBroadcastRejected, err)
	}
	return txid, nil
}

// GetRawTx returns the raw transaction bytes for the given txid.
// It calls `getrawtransaction "txid" false` (non-verbose) to get the hex-encoded
// transaction and decodes it to bytes.
func (c *RPCClient) GetRawTx(ctx context.Context, txid string) ([]byte, error) {
	params := []interface{}{txid, false}
	var rawHex string
	if err := c.Call(ctx, "getrawtransaction", params, &rawHex); err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tx hex: %v", ErrInvalidResponse, err)
	}
	return data, nil
}

// verboseTxResult maps the JSON fields from getrawtransaction with verbose=true.
type verboseTxResult struct {
	Confirmations int64  `json:"confirmations"`
	BlockHash     string `json:"blockhash"`
	BlockHeight   uint64 `json:"blockheight"`
}

// GetTxStatus returns the confirmation status of a transaction.
// It calls `getrawtransaction "txid" true` (verbose mode) to get confirmation info.
func (c *RPCClient) GetTxStatus(ctx context.Context, txid string) (*TxStatus, error) {
	params := []interface{}{txid, true}
	var result verboseTxResult
	if err := c.Call(ctx, "getrawtransaction", params, &result); err != nil {
		return nil, err
	}
	return &TxStatus{
		Confirmed:   result.Confirmations > 0,
		BlockHash:   result.BlockHash,
		BlockHeight: result.BlockHeight,
	}, nil
}

// GetBlockHeader returns the raw 80-byte block header for the given block hash.
// It calls `getblockheader "hash" false` (non-verbose) to get the hex-encoded header.
func (c *RPCClient) GetBlockHeader(ctx context.Context, blockHash string) ([]byte, error) {
	params := []interface{}{blockHash, false}
	var headerHex string
	if err := c.Call(ctx, "getblockheader", params, &headerHex); err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(headerHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header hex: %v", ErrInvalidResponse, err)
	}
	return data, nil
}

// GetMerkleProof returns a Merkle inclusion proof for a confirmed transaction.
// It calls `gettxoutproof ["txid"]` which returns a hex-encoded CMerkleBlock.
// The binary data is minimally parsed; full Merkle tree extraction is handled
// by the SPVClient layer.
func (c *RPCClient) GetMerkleProof(ctx context.Context, txid string) (*MerkleProof, error) {
	params := []interface{}{[]string{txid}}
	var proofHex string
	if err := c.Call(ctx, "gettxoutproof", params, &proofHex); err != nil {
		return nil, err
	}
	data, err := hex.DecodeString(proofHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid proof hex: %v", ErrInvalidResponse, err)
	}
	return parseCMerkleBlock(txid, data)
}

// GetBestBlockHeight returns the height of the current chain tip.
// It calls `getblockcount` which returns an integer block height.
func (c *RPCClient) GetBestBlockHeight(ctx context.Context) (uint64, error) {
	params := []interface{}{}
	var raw json.RawMessage
	if err := c.Call(ctx, "getblockcount", params, &raw); err != nil {
		return 0, err
	}
	// getblockcount returns an integer, but JSON numbers are float64.
	var height float64
	if err := json.Unmarshal(raw, &height); err != nil {
		return 0, fmt.Errorf("%w: invalid block height: %v", ErrInvalidResponse, err)
	}
	return uint64(height), nil
}
