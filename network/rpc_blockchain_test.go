package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tongxiaofeng/libbitfs-go/spv"
)

// rpcTestServer creates a mock JSON-RPC server for testing RPCClient methods.
// handlers maps RPC method names to handler functions that receive the request params
// and return either a result or an rpcError.
func rpcTestServer(t *testing.T, handlers map[string]func(params []interface{}) (interface{}, *rpcError)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		handler, ok := handlers[req.Method]
		if !ok {
			t.Fatalf("unexpected RPC method: %s", req.Method)
		}
		result, rpcErr := handler(req.Params)
		resp := rpcResponse{ID: req.ID}
		if rpcErr != nil {
			resp.Error = rpcErr
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			resp.Result, _ = json.Marshal(result)
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestListUnspent(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"listunspent": func(params []interface{}) (interface{}, *rpcError) {
			// Verify params: minconf=0, maxconf=9999999, ["address"]
			require.Len(t, params, 3)
			assert.Equal(t, float64(0), params[0])
			assert.Equal(t, float64(9999999), params[1])
			addrs, ok := params[2].([]interface{})
			require.True(t, ok)
			assert.Equal(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", addrs[0])

			return []map[string]interface{}{
				{
					"txid":          "abc123def456",
					"vout":          0,
					"amount":        0.001,
					"scriptPubKey":  "76a914deadbeef88ac",
					"address":       "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
					"confirmations": 6,
				},
				{
					"txid":          "fff000aaa111",
					"vout":          1,
					"amount":        1.5,
					"scriptPubKey":  "76a914cafebabe88ac",
					"address":       "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
					"confirmations": 0,
				},
			}, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	utxos, err := client.ListUnspent(context.Background(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	// Verify BTC -> satoshi conversion: 0.001 BTC = 100000 sat
	assert.Equal(t, "abc123def456", utxos[0].TxID)
	assert.Equal(t, uint32(0), utxos[0].Vout)
	assert.Equal(t, uint64(100000), utxos[0].Amount)
	assert.Equal(t, "76a914deadbeef88ac", utxos[0].ScriptPubKey)
	assert.Equal(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", utxos[0].Address)
	assert.Equal(t, int64(6), utxos[0].Confirmations)

	// Verify 1.5 BTC = 150000000 sat
	assert.Equal(t, "fff000aaa111", utxos[1].TxID)
	assert.Equal(t, uint32(1), utxos[1].Vout)
	assert.Equal(t, uint64(150000000), utxos[1].Amount)
	assert.Equal(t, int64(0), utxos[1].Confirmations)
}

func TestBroadcastTx(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"sendrawtransaction": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 1)
			assert.Equal(t, "0100000001abcdef", params[0])
			return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	txid, err := client.BroadcastTx(context.Background(), "0100000001abcdef")
	require.NoError(t, err)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", txid)
}

func TestBroadcastTxRejected(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"sendrawtransaction": func(params []interface{}) (interface{}, *rpcError) {
			return nil, &rpcError{Code: -26, Message: "mandatory-script-verify-flag-failed"}
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	txid, err := client.BroadcastTx(context.Background(), "bad-hex")
	assert.Empty(t, txid)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBroadcastRejected)
	assert.Contains(t, err.Error(), "mandatory-script-verify-flag-failed")
}

func TestGetRawTx(t *testing.T) {
	// Return hex-encoded raw transaction bytes
	rawHex := "0100000001abcdef"
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"getrawtransaction": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 2)
			assert.Equal(t, "txid123", params[0])
			assert.Equal(t, false, params[1]) // verbose=false
			return rawHex, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	rawBytes, err := client.GetRawTx(context.Background(), "txid123")
	require.NoError(t, err)

	expected, _ := hex.DecodeString(rawHex)
	assert.Equal(t, expected, rawBytes)
}

func TestGetTxStatus(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"getrawtransaction": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 2)
			assert.Equal(t, "txid456", params[0])
			assert.Equal(t, true, params[1]) // verbose=true
			return map[string]interface{}{
				"confirmations": 10,
				"blockhash":     "00000000000000000abcdef",
				"blockheight":   800000,
			}, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	status, err := client.GetTxStatus(context.Background(), "txid456")
	require.NoError(t, err)
	assert.True(t, status.Confirmed)
	assert.Equal(t, "00000000000000000abcdef", status.BlockHash)
	assert.Equal(t, uint64(800000), status.BlockHeight)
}

func TestGetTxStatusUnconfirmed(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"getrawtransaction": func(params []interface{}) (interface{}, *rpcError) {
			return map[string]interface{}{
				"confirmations": 0,
			}, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	status, err := client.GetTxStatus(context.Background(), "txid789")
	require.NoError(t, err)
	assert.False(t, status.Confirmed)
	assert.Empty(t, status.BlockHash)
	assert.Equal(t, uint64(0), status.BlockHeight)
}

func TestGetBlockHeader(t *testing.T) {
	// 80-byte block header as hex (160 hex chars)
	headerHex := "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"getblockheader": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 2)
			assert.Equal(t, "blockhash000", params[0])
			assert.Equal(t, false, params[1]) // verbose=false (hex)
			return headerHex, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	header, err := client.GetBlockHeader(context.Background(), "blockhash000")
	require.NoError(t, err)
	assert.Len(t, header, 80)
}

// buildTestBIP37 constructs a BIP37-encoded CMerkleBlock for testing.
// It takes tx hashes (internal byte order), builds the Merkle tree, and encodes
// a partial Merkle tree for the matched tx at matchedIndex.
func buildTestBIP37(t *testing.T, txHashes [][]byte, matchedIndex int) (merkleBlock []byte, merkleRoot []byte) {
	t.Helper()
	totalTxs := uint32(len(txHashes))

	// Calculate tree height.
	treeHeight := 0
	for calcTreeWidth(totalTxs, uint32(treeHeight)) > 1 {
		treeHeight++
	}

	type nodeInfo struct {
		hash    []byte
		matched bool
	}

	// Build all levels: levels[0]=leaves, levels[treeHeight]=root.
	levels := make([][]nodeInfo, treeHeight+1)
	levels[0] = make([]nodeInfo, len(txHashes))
	for i, h := range txHashes {
		levels[0][i] = nodeInfo{hash: h, matched: i == matchedIndex}
	}
	for l := 1; l <= treeHeight; l++ {
		width := int(calcTreeWidth(totalTxs, uint32(l)))
		childWidth := int(calcTreeWidth(totalTxs, uint32(l-1)))
		levels[l] = make([]nodeInfo, width)
		for p := 0; p < width; p++ {
			left := levels[l-1][p*2]
			var right nodeInfo
			if p*2+1 < childWidth {
				right = levels[l-1][p*2+1]
			} else {
				right = left // duplicate last for odd count
			}
			combined := make([]byte, 64)
			copy(combined[:32], left.hash)
			copy(combined[32:], right.hash)
			levels[l][p] = nodeInfo{
				hash:    spv.DoubleHash(combined),
				matched: left.matched || right.matched,
			}
		}
	}

	merkleRoot = levels[treeHeight][0].hash

	// Build block header with this Merkle root.
	headerBytes := make([]byte, 80)
	headerBytes[0] = 0x01
	copy(headerBytes[36:68], merkleRoot)

	// BIP37 encode: depth-first traversal from root.
	// level=0 is leaves, level=treeHeight is root.
	var hashes [][]byte
	var flagBits []bool

	var encode func(level, pos int)
	encode = func(level, pos int) {
		node := levels[level][pos]

		if level == 0 {
			flagBits = append(flagBits, node.matched)
			hashes = append(hashes, node.hash)
			return
		}

		if !node.matched {
			flagBits = append(flagBits, false)
			hashes = append(hashes, node.hash)
			return
		}

		// Ancestor of match: descend.
		flagBits = append(flagBits, true)
		encode(level-1, pos*2)
		childWidth := int(calcTreeWidth(totalTxs, uint32(level-1)))
		if pos*2+1 < childWidth {
			encode(level-1, pos*2+1)
		}
	}
	encode(treeHeight, 0)

	// Pack flag bits into bytes.
	numFlagBytes := (len(flagBits) + 7) / 8
	flagByteSlice := make([]byte, numFlagBytes)
	for i, bit := range flagBits {
		if bit {
			flagByteSlice[i/8] |= 1 << uint(i%8)
		}
	}

	// Assemble the CMerkleBlock.
	var buf bytes.Buffer
	buf.Write(headerBytes)
	binary.Write(&buf, binary.LittleEndian, totalTxs)
	buf.WriteByte(byte(len(hashes)))
	for _, h := range hashes {
		buf.Write(h)
	}
	buf.WriteByte(byte(numFlagBytes))
	buf.Write(flagByteSlice)

	return buf.Bytes(), merkleRoot
}

func TestGetMerkleProof(t *testing.T) {
	// Create a single-tx block.
	tx0 := spv.DoubleHash([]byte("test coinbase tx"))
	merkleBlock, _ := buildTestBIP37(t, [][]byte{tx0}, 0)
	proofHex := hex.EncodeToString(merkleBlock)
	txidDisplay := hex.EncodeToString(reverseBytesCopy(tx0))

	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"gettxoutproof": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 1)
			txids, ok := params[0].([]interface{})
			require.True(t, ok)
			assert.Equal(t, txidDisplay, txids[0])
			return proofHex, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	proof, err := client.GetMerkleProof(context.Background(), txidDisplay)
	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Equal(t, txidDisplay, proof.TxID)
	assert.Equal(t, 0, proof.Index)
	assert.Empty(t, proof.Branches)
}

func TestParseBIP37MerkleBlock_SingleTx(t *testing.T) {
	tx0 := spv.DoubleHash([]byte("single tx"))
	merkleBlock, merkleRoot := buildTestBIP37(t, [][]byte{tx0}, 0)

	header, txIndex, branches, totalTxs, err := ParseBIP37MerkleBlock(merkleBlock, tx0)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), txIndex)
	assert.Empty(t, branches)
	assert.Equal(t, uint32(1), totalTxs)
	assert.Len(t, header, 80)

	// Verify merkle root in header matches.
	parsedMerkleRoot := header[36:68]
	assert.Equal(t, merkleRoot, parsedMerkleRoot)
}

func TestParseBIP37MerkleBlock_TwoTxs(t *testing.T) {
	tx0 := spv.DoubleHash([]byte("coinbase"))
	tx1 := spv.DoubleHash([]byte("our target"))

	merkleBlock, merkleRoot := buildTestBIP37(t, [][]byte{tx0, tx1}, 1)

	header, txIndex, branches, totalTxs, err := ParseBIP37MerkleBlock(merkleBlock, tx1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), txIndex)
	assert.Equal(t, uint32(2), totalTxs)
	require.Len(t, branches, 1)
	assert.Equal(t, tx0, branches[0], "branch should be the sibling tx hash")

	// Verify the proof produces the correct Merkle root.
	computedRoot := spv.ComputeMerkleRoot(tx1, txIndex, branches)
	assert.Equal(t, merkleRoot, computedRoot)

	// Verify merkle root in header.
	assert.Equal(t, merkleRoot, header[36:68])
}

func TestParseBIP37MerkleBlock_FourTxs(t *testing.T) {
	txHashes := make([][]byte, 4)
	for i := range txHashes {
		txHashes[i] = spv.DoubleHash([]byte(fmt.Sprintf("tx-%d", i)))
	}

	// Test matching each tx in the block.
	for targetIdx := 0; targetIdx < 4; targetIdx++ {
		t.Run(fmt.Sprintf("target_index_%d", targetIdx), func(t *testing.T) {
			merkleBlock, merkleRoot := buildTestBIP37(t, txHashes, targetIdx)

			_, txIndex, branches, totalTxs, err := ParseBIP37MerkleBlock(merkleBlock, txHashes[targetIdx])
			require.NoError(t, err)
			assert.Equal(t, uint32(targetIdx), txIndex)
			assert.Equal(t, uint32(4), totalTxs)
			require.Len(t, branches, 2, "4-tx tree needs 2 branch nodes")

			computedRoot := spv.ComputeMerkleRoot(txHashes[targetIdx], txIndex, branches)
			assert.Equal(t, merkleRoot, computedRoot)
		})
	}
}

func TestParseBIP37MerkleBlock_OddTxCount(t *testing.T) {
	// 3 txs: tree pads the last tx.
	txHashes := make([][]byte, 3)
	for i := range txHashes {
		txHashes[i] = spv.DoubleHash([]byte(fmt.Sprintf("odd-tx-%d", i)))
	}

	merkleBlock, merkleRoot := buildTestBIP37(t, txHashes, 2)

	_, txIndex, branches, totalTxs, err := ParseBIP37MerkleBlock(merkleBlock, txHashes[2])
	require.NoError(t, err)
	assert.Equal(t, uint32(2), txIndex)
	assert.Equal(t, uint32(3), totalTxs)
	require.NotEmpty(t, branches)

	computedRoot := spv.ComputeMerkleRoot(txHashes[2], txIndex, branches)
	assert.Equal(t, merkleRoot, computedRoot)
}

func TestParseBIP37MerkleBlock_TxNotFound(t *testing.T) {
	tx0 := spv.DoubleHash([]byte("known tx"))
	merkleBlock, _ := buildTestBIP37(t, [][]byte{tx0}, 0)

	unknownTx := spv.DoubleHash([]byte("unknown tx"))
	_, _, _, _, err := ParseBIP37MerkleBlock(merkleBlock, unknownTx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target tx not found")
}

func TestParseBIP37MerkleBlock_TooShort(t *testing.T) {
	_, _, _, _, err := ParseBIP37MerkleBlock(make([]byte, 83), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseCMerkleBlock_DisplayHexConversion(t *testing.T) {
	// Verify that parseCMerkleBlock correctly converts display hex txid
	// and produces a MerkleProof with display hex block hash.
	tx0 := spv.DoubleHash([]byte("coinbase"))
	tx1 := spv.DoubleHash([]byte("target"))

	merkleBlock, merkleRoot := buildTestBIP37(t, [][]byte{tx0, tx1}, 1)
	txidDisplay := hex.EncodeToString(reverseBytesCopy(tx1))

	proof, err := parseCMerkleBlock(txidDisplay, merkleBlock)
	require.NoError(t, err)
	assert.Equal(t, txidDisplay, proof.TxID)
	assert.Equal(t, 1, proof.Index)
	require.Len(t, proof.Branches, 1)

	// Verify block hash is display hex (reversed hash of header).
	expectedBlockHash := spv.DoubleHash(merkleBlock[:80])
	expectedBlockHashHex := hex.EncodeToString(reverseBytesCopy(expectedBlockHash))
	assert.Equal(t, expectedBlockHashHex, proof.BlockHash)

	// Verify the branches produce the correct merkle root.
	computedRoot := spv.ComputeMerkleRoot(tx1, uint32(proof.Index), proof.Branches)
	assert.Equal(t, merkleRoot, computedRoot)
}

func TestGetBestBlockHeight(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"getblockcount": func(params []interface{}) (interface{}, *rpcError) {
			return 850000, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	height, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(850000), height)
}

func TestGetUTXO(t *testing.T) {
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"gettxout": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 2)
			assert.Equal(t, "txid_utxo", params[0])
			assert.Equal(t, float64(2), params[1])
			return map[string]interface{}{
				"value":         0.005,
				"confirmations": 3,
				"scriptPubKey": map[string]interface{}{
					"hex":       "76a914aabbccdd88ac",
					"addresses": []string{"1TestAddress"},
				},
			}, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	utxo, err := client.GetUTXO(context.Background(), "txid_utxo", 2)
	require.NoError(t, err)
	assert.Equal(t, "txid_utxo", utxo.TxID)
	assert.Equal(t, uint32(2), utxo.Vout)
	assert.Equal(t, uint64(500000), utxo.Amount) // 0.005 BTC = 500000 sat
	assert.Equal(t, "76a914aabbccdd88ac", utxo.ScriptPubKey)
	assert.Equal(t, "1TestAddress", utxo.Address)
	assert.Equal(t, int64(3), utxo.Confirmations)
}

func TestGetUTXOSpent(t *testing.T) {
	// gettxout returns null for spent outputs
	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"gettxout": func(params []interface{}) (interface{}, *rpcError) {
			return nil, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	utxo, err := client.GetUTXO(context.Background(), "spent_txid", 0)
	assert.Nil(t, utxo)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestTraversePartialMerkleTree_HugeTotalTxs(t *testing.T) {
	// totalTxs = MaxUint32 should be rejected to prevent OOM.
	hashes := [][]byte{make([]byte, 32)}
	flags := []byte{0xFF}
	target := make([]byte, 32)

	_, _, err := traversePartialMerkleTree(hashes, flags, 0xFFFFFFFF, target)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestTraversePartialMerkleTree_ZeroTotalTxs(t *testing.T) {
	hashes := [][]byte{make([]byte, 32)}
	flags := []byte{0xFF}
	target := make([]byte, 32)

	_, _, err := traversePartialMerkleTree(hashes, flags, 0, target)
	assert.Error(t, err)
}

func TestTraversePartialMerkleTree_ExhaustedHashes(t *testing.T) {
	target := make([]byte, 32)
	target[0] = 0x42

	// Claim 4 txs but only provide 1 hash — traversal needs more.
	hashes := [][]byte{target}
	flags := []byte{0xFF} // All interior nodes flagged

	_, _, err := traversePartialMerkleTree(hashes, flags, 4, target)
	assert.Error(t, err, "should fail when hash pool is exhausted")
}

func TestRPCClientImplementsBlockchainService(t *testing.T) {
	// Compile-time interface check
	var _ BlockchainService = (*RPCClient)(nil)
}
