package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/tongxiaofeng/libbitfs-go/spv"
)

// Compile-time interface check.
var _ BlockchainService = (*RPCClient)(nil)

// btcToSat converts a BTC float64 amount (as returned by the RPC node) to satoshis.
// It uses math.Round to avoid floating-point truncation issues.
func btcToSat(btc float64) uint64 {
	return uint64(math.Round(btc * 1e8))
}

// parseCMerkleBlock parses a BIP37 CMerkleBlock and returns a MerkleProof.
// The txid parameter is the display-hex transaction ID (big-endian byte order).
func parseCMerkleBlock(txid string, data []byte) (*MerkleProof, error) {
	txidBytes, err := hex.DecodeString(txid)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid txid hex: %w", ErrInvalidResponse, err)
	}
	if len(txidBytes) != 32 {
		return nil, fmt.Errorf("%w: txid must be 32 bytes, got %d", ErrInvalidResponse, len(txidBytes))
	}

	// Convert display txid (big-endian) to internal byte order for tree matching.
	targetTxID := reverseBytesCopy(txidBytes)

	headerBytes, txIndex, branches, _, err := ParseBIP37MerkleBlock(data, targetTxID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	// Compute block hash in display hex (reversed double-SHA256 of header).
	blockHash := spv.DoubleHash(headerBytes)
	blockHashHex := hex.EncodeToString(reverseBytesCopy(blockHash))

	return &MerkleProof{
		TxID:      txid,
		BlockHash: blockHashHex,
		Branches:  branches,
		Index:     int(txIndex),
	}, nil
}

// ParseBIP37MerkleBlock parses a BIP37-encoded CMerkleBlock and extracts
// the Merkle branch for a target transaction.
//
// Parameters:
//   - data: raw BIP37 CMerkleBlock bytes
//   - targetTxID: transaction hash in internal byte order (raw double-SHA256)
//
// Returns:
//   - header: raw 80-byte block header
//   - txIndex: position of the target tx in the block
//   - branches: Merkle branch hashes (internal byte order, bottom-up)
//   - totalTxs: total transactions in the block
func ParseBIP37MerkleBlock(data []byte, targetTxID []byte) (header []byte, txIndex uint32, branches [][]byte, totalTxs uint32, err error) {
	if len(data) < 84 {
		return nil, 0, nil, 0, fmt.Errorf("CMerkleBlock too short: %d bytes", len(data))
	}

	header = data[:80]
	totalTxs = binary.LittleEndian.Uint32(data[80:84])
	pos := 84

	// Read varint: number of hashes.
	numHashes, bytesRead := readVarInt(data[pos:])
	if bytesRead == 0 {
		return nil, 0, nil, 0, fmt.Errorf("failed to read hash count varint")
	}
	pos += bytesRead

	// Validate hash count against remaining data to prevent OOM from malformed responses.
	remainingBytes := uint64(len(data) - pos)
	if numHashes > remainingBytes/32 {
		return nil, 0, nil, 0, fmt.Errorf("hash count %d exceeds available data (%d bytes remaining)", numHashes, remainingBytes)
	}

	// Read the hashes.
	hashes := make([][]byte, numHashes)
	for i := uint64(0); i < numHashes; i++ {
		if pos+32 > len(data) {
			return nil, 0, nil, 0, fmt.Errorf("unexpected end of data reading hash %d", i)
		}
		h := make([]byte, 32)
		copy(h, data[pos:pos+32])
		hashes[i] = h
		pos += 32
	}

	// Read varint: number of flag bytes.
	numFlagBytes, bytesRead := readVarInt(data[pos:])
	if bytesRead == 0 {
		return nil, 0, nil, 0, fmt.Errorf("failed to read flag bytes count varint")
	}
	pos += bytesRead

	if uint64(pos)+numFlagBytes > uint64(len(data)) {
		return nil, 0, nil, 0, fmt.Errorf("unexpected end of data reading flags")
	}
	flagBytes := data[pos : pos+int(numFlagBytes)]

	txIndex, branches, err = traversePartialMerkleTree(hashes, flagBytes, totalTxs, targetTxID)
	if err != nil {
		return nil, 0, nil, 0, fmt.Errorf("traverse partial merkle tree: %w", err)
	}

	return header, txIndex, branches, totalTxs, nil
}

// maxMerkleTreeTxs is the upper bound on totalTxs accepted by traversePartialMerkleTree.
// 1M transactions covers any realistic block and prevents OOM from malformed data.
const maxMerkleTreeTxs = 1 << 20

// traversePartialMerkleTree walks the BIP37 partial Merkle tree structure and
// extracts the branch nodes needed for a standard Merkle proof of the target tx.
func traversePartialMerkleTree(hashes [][]byte, flagBytes []byte, totalTxs uint32, targetTxID []byte) (txIndex uint32, branch [][]byte, err error) {
	if totalTxs == 0 {
		return 0, nil, fmt.Errorf("totalTxs is zero")
	}
	if totalTxs > maxMerkleTreeTxs {
		return 0, nil, fmt.Errorf("totalTxs %d exceeds maximum %d", totalTxs, maxMerkleTreeTxs)
	}

	height := uint32(0)
	for calcTreeWidth(totalTxs, height) > 1 {
		height++
	}

	hashIdx := 0
	bitIdx := 0

	getBit := func() bool {
		if bitIdx/8 >= len(flagBytes) {
			return false
		}
		bit := (flagBytes[bitIdx/8] >> uint(bitIdx%8)) & 1
		bitIdx++
		return bit == 1
	}

	getHash := func() []byte {
		if hashIdx >= len(hashes) {
			return nil
		}
		h := hashes[hashIdx]
		hashIdx++
		return h
	}

	type traverseResult struct {
		hash   []byte
		found  bool
		index  uint32
		branch [][]byte
	}

	var traverse func(depth, pos uint32) traverseResult
	traverse = func(depth, pos uint32) traverseResult {
		flag := getBit()

		if depth == 0 {
			h := getHash()
			isTarget := bytes.Equal(h, targetTxID)
			return traverseResult{hash: h, found: isTarget, index: pos}
		}

		if !flag {
			h := getHash()
			return traverseResult{hash: h}
		}

		left := traverse(depth-1, pos*2)
		var right traverseResult
		if pos*2+1 < calcTreeWidth(totalTxs, depth-1) {
			right = traverse(depth-1, pos*2+1)
		} else {
			right = traverseResult{hash: left.hash}
		}

		combined := make([]byte, 64)
		copy(combined[:32], left.hash)
		copy(combined[32:], right.hash)
		parentHash := spv.DoubleHash(combined)

		result := traverseResult{hash: parentHash}
		if left.found {
			result.found = true
			result.index = left.index
			branch := make([][]byte, len(left.branch)+1)
			copy(branch, left.branch)
			branch[len(left.branch)] = right.hash
			result.branch = branch
		} else if right.found {
			result.found = true
			result.index = right.index
			branch := make([][]byte, len(right.branch)+1)
			copy(branch, right.branch)
			branch[len(right.branch)] = left.hash
			result.branch = branch
		}

		return result
	}

	result := traverse(height, 0)
	if !result.found {
		return 0, nil, fmt.Errorf("target tx not found in partial merkle tree")
	}

	return result.index, result.branch, nil
}

// calcTreeWidth computes the number of nodes at a given depth in a Merkle tree.
func calcTreeWidth(totalLeaves, depth uint32) uint32 {
	return (totalLeaves + (1 << depth) - 1) >> depth
}

// readVarInt reads a Bitcoin-style variable-length integer from data.
// Returns the value and the number of bytes consumed.
func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := data[0]
	switch {
	case first < 0xFD:
		return uint64(first), 1
	case first == 0xFD:
		if len(data) < 3 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	case first == 0xFE:
		if len(data) < 5 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	default: // 0xFF
		if len(data) < 9 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9
	}
}

// reverseBytesCopy returns a reversed copy of a byte slice.
func reverseBytesCopy(b []byte) []byte {
	c := make([]byte, len(b))
	for i, v := range b {
		c[len(b)-1-i] = v
	}
	return c
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

// ImportAddress imports a watch-only address into the node's wallet so that
// ListUnspent can find its UTXOs. Calls `importaddress "address" "" true`.
// The rescan parameter is true so the node discovers any existing outputs.
// Safe to call multiple times; the node returns success if already imported.
func (c *RPCClient) ImportAddress(ctx context.Context, address string) error {
	// params: address, label (empty), rescan (true)
	params := []interface{}{address, "", true}
	var result interface{}
	if err := c.Call(ctx, "importaddress", params, &result); err != nil {
		return fmt.Errorf("importaddress: %w", err)
	}
	return nil
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
