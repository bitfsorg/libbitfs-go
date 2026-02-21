package network

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestGetMerkleProof(t *testing.T) {
	// gettxoutproof returns a hex-encoded CMerkleBlock.
	// We need at least 84 bytes (168 hex chars). Build a minimal valid one:
	// 80 bytes block header + 4 bytes numTransactions.
	headerBytes := make([]byte, 84)
	headerBytes[0] = 0x01 // version
	proofHex := hex.EncodeToString(headerBytes)

	server := rpcTestServer(t, map[string]func(params []interface{}) (interface{}, *rpcError){
		"gettxoutproof": func(params []interface{}) (interface{}, *rpcError) {
			require.Len(t, params, 1)
			txids, ok := params[0].([]interface{})
			require.True(t, ok)
			assert.Equal(t, "txid_proof", txids[0])
			return proofHex, nil
		},
	})
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	proof, err := client.GetMerkleProof(context.Background(), "txid_proof")
	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.Equal(t, "txid_proof", proof.TxID)
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

func TestRPCClientImplementsBlockchainService(t *testing.T) {
	// Compile-time interface check
	var _ BlockchainService = (*RPCClient)(nil)
}
