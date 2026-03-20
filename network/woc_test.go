package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestWoC creates a WoCClient pointing at the given httptest server.
func newTestWoC(ts *httptest.Server) *WoCClient {
	return &WoCClient{
		baseURL: ts.URL,
		client:  ts.Client(),
	}
}

func TestWoCClient_ListUnspent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa/unspent/all", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[
			{"height": 100, "tx_pos": 0, "tx_hash": "aabb", "value": 50000},
			{"height": 101, "tx_pos": 1, "tx_hash": "ccdd", "value": 25000}
		]`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	utxos, err := client.ListUnspent(context.Background(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	assert.Equal(t, "aabb", utxos[0].TxID)
	assert.Equal(t, uint32(0), utxos[0].Vout)
	assert.Equal(t, uint64(50000), utxos[0].Amount)
	assert.Equal(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", utxos[0].Address)
	assert.Equal(t, int64(1), utxos[0].Confirmations)

	assert.Equal(t, "ccdd", utxos[1].TxID)
	assert.Equal(t, uint32(1), utxos[1].Vout)
	assert.Equal(t, uint64(25000), utxos[1].Amount)
}

func TestWoCClient_ListUnspent_Empty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[]`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	utxos, err := client.ListUnspent(context.Background(), "1EmptyAddr")
	require.NoError(t, err)
	assert.Empty(t, utxos)
}

func TestWoCClient_ListUnspent_404ReturnsEmpty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	utxos, err := client.ListUnspent(context.Background(), "1NoUTXOs")
	require.NoError(t, err)
	assert.Empty(t, utxos)
}

func TestWoCClient_GetRawTx(t *testing.T) {
	rawHex := "0100000001000000000000000000000000000000000000000000000000000000000000000000000000"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tx/abc123/hex", r.URL.Path)
		fmt.Fprint(w, rawHex)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	data, err := client.GetRawTx(context.Background(), "abc123")
	require.NoError(t, err)

	expected, _ := hex.DecodeString(rawHex)
	assert.Equal(t, expected, data)
}

func TestWoCClient_GetRawTx_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	_, err := client.GetRawTx(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestWoCClient_GetTxStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tx/abc123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"txid": "abc123",
			"confirmations": 42,
			"blockhash": "00000000000000000abcdef",
			"blockheight": 800000
		}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	status, err := client.GetTxStatus(context.Background(), "abc123")
	require.NoError(t, err)
	assert.True(t, status.Confirmed)
	assert.Equal(t, "00000000000000000abcdef", status.BlockHash)
	assert.Equal(t, uint64(800000), status.BlockHeight)
}

func TestWoCClient_GetTxStatus_Unconfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"txid": "mempool_tx", "confirmations": 0}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	status, err := client.GetTxStatus(context.Background(), "mempool_tx")
	require.NoError(t, err)
	assert.False(t, status.Confirmed)
	assert.Empty(t, status.BlockHash)
}

func TestWoCClient_GetMerkleProof(t *testing.T) {
	nodeHash := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/tx/abc123/proof/tsc", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"index": 3,
			"txOrId": "abc123",
			"target": "00000000000000000abc",
			"nodes": ["%s", "*"]
		}`, nodeHash)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	proof, err := client.GetMerkleProof(context.Background(), "abc123")
	require.NoError(t, err)
	assert.Equal(t, "abc123", proof.TxID)
	assert.Equal(t, "00000000000000000abc", proof.BlockHash)
	assert.Equal(t, 3, proof.Index)
	require.Len(t, proof.Branches, 2)

	expectedBytes, _ := hex.DecodeString(nodeHash)
	assert.Equal(t, expectedBytes, proof.Branches[0])
	assert.Nil(t, proof.Branches[1]) // "*" -> nil sentinel
}

func TestWoCClient_GetBlockHeader(t *testing.T) {
	// Use realistic 64-char hex strings for 32-byte hash fields.
	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"
	merkleRoot := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"version": 1,
			"previousblockhash": "%s",
			"merkleroot": "%s",
			"time": 1231006505,
			"bits": "1d00ffff",
			"nonce": 2083236893
		}`, prevHash, merkleRoot)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	header, err := client.GetBlockHeader(context.Background(), "somehash")
	require.NoError(t, err)
	require.Len(t, header, 80)

	// Verify version (1 in LE).
	assert.Equal(t, byte(1), header[0])
	assert.Equal(t, byte(0), header[1])
	assert.Equal(t, byte(0), header[2])
	assert.Equal(t, byte(0), header[3])

	// Verify prevHash is all zeros (reversed zero is still zero).
	for i := 4; i < 36; i++ {
		assert.Equal(t, byte(0), header[i], "prevHash byte %d", i)
	}

	// Verify merkleRoot is the reversed decode of the hex string.
	mrBytes, _ := hex.DecodeString(merkleRoot)
	mrWire := reverseBytesCopy(mrBytes)
	assert.Equal(t, mrWire, header[36:68])
}

func TestWoCClient_GetBestBlockHeight(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/chain/info", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"blocks": 850000, "headers": 850000, "bestblockhash": "abc"}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	height, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(850000), height)
}

func TestWoCClient_GetBlockHash(t *testing.T) {
	hash := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/block/height/0", r.URL.Path)
		fmt.Fprint(w, hash)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	result, err := client.GetBlockHash(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, hash, result)
}

func TestWoCClient_GetBlockHash_JSONResponse(t *testing.T) {
	hash := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"hash": "%s"}`, hash)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	result, err := client.GetBlockHash(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, hash, result)
}

func TestWoCClient_GetUTXO(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"txid": "abc123",
			"confirmations": 10,
			"vout": [
				{"value": 0.0005, "n": 0, "scriptPubKey": {"hex": "76a914aabb88", "addresses": ["1Addr"]}},
				{"value": 0.001, "n": 1, "scriptPubKey": {"hex": "76a914ccdd99", "addresses": ["1Addr2"]}}
			]
		}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	utxo, err := client.GetUTXO(context.Background(), "abc123", 1)
	require.NoError(t, err)
	assert.Equal(t, "abc123", utxo.TxID)
	assert.Equal(t, uint32(1), utxo.Vout)
	assert.Equal(t, uint64(100000), utxo.Amount) // 0.001 BTC = 100000 sat
	assert.Equal(t, "76a914ccdd99", utxo.ScriptPubKey)
	assert.Equal(t, "1Addr2", utxo.Address)
	assert.Equal(t, int64(10), utxo.Confirmations)
}

func TestWoCClient_GetUTXO_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"txid": "abc123", "confirmations": 1, "vout": [{"value": 0.001, "n": 0, "scriptPubKey": {"hex": "aa"}}]}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	_, err := client.GetUTXO(context.Background(), "abc123", 5)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestWoCClient_BroadcastTx_ReturnsError(t *testing.T) {
	client := NewWoCClient(WoCConfig{BaseURL: "http://unused"})
	_, err := client.BroadcastTx(context.Background(), "deadbeef")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBroadcastRejected)
	assert.Contains(t, err.Error(), "use ARC")
}

func TestWoCClient_ImportAddress_NoOp(t *testing.T) {
	client := NewWoCClient(WoCConfig{BaseURL: "http://unused"})
	err := client.ImportAddress(context.Background(), "1Addr")
	require.NoError(t, err)
}

func TestWoCClient_RetryOn429(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "rate limited")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"blocks": 999}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	// Override the client timeout to be generous for the test.
	client.client.Timeout = 30 * time.Second

	height, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(999), height)
	assert.Equal(t, int32(3), attempts.Load())
}

func TestWoCClient_RetryOn5xx(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "service unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"blocks": 42}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	height, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(42), height)
	assert.Equal(t, int32(2), attempts.Load())
}

func TestWoCClient_RetryExhausted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "rate limited")
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	_, err := client.GetBestBlockHeight(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.Contains(t, err.Error(), "retries exhausted")
}

func TestWoCClient_APIKeyHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "my-secret-key", r.Header.Get("woc-api-key"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"blocks": 1}`)
	}))
	defer ts.Close()

	client := &WoCClient{
		baseURL: ts.URL,
		apiKey:  "my-secret-key",
		client:  ts.Client(),
	}
	_, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
}

func TestWoCClient_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, `{"blocks": 1}`)
	}))
	defer ts.Close()

	client := newTestWoC(ts)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.GetBestBlockHeight(ctx)
	require.Error(t, err)
}

func TestSerializeBlockHeader(t *testing.T) {
	hdr := wocBlockHeader{
		Version:       536870912, // 0x20000000
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		MerkleRoot:    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
		Time:          1231006505,
		Bits:          "1d00ffff",
		Nonce:         2083236893,
	}

	data, err := serializeBlockHeader(hdr)
	require.NoError(t, err)
	require.Len(t, data, 80)

	// Verify it round-trips: version.
	assert.Equal(t, uint32(536870912), uint32(data[0])|uint32(data[1])<<8|uint32(data[2])<<16|uint32(data[3])<<24)
}
