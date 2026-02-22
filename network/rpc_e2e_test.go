//go:build e2e

package network

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func regtestClient() *RPCClient {
	return NewRPCClient(RPCConfig{
		URL: "http://localhost:18332", User: "bitfs", Password: "bitfs",
	})
}

func skipIfUnavailable(t *testing.T, client *RPCClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var height uint64
	if err := client.Call(ctx, "getblockcount", nil, &height); err != nil {
		t.Skip("regtest node unavailable:", err)
	}
}

func TestE2E_GetBestBlockHeight(t *testing.T) {
	client := regtestClient()
	skipIfUnavailable(t, client)

	height, err := client.GetBestBlockHeight(context.Background())
	require.NoError(t, err)
	assert.Greater(t, height, uint64(0))
}

func TestE2E_ListUnspent(t *testing.T) {
	client := regtestClient()
	skipIfUnavailable(t, client)

	ctx := context.Background()

	// Generate address and fund it.
	var addr string
	require.NoError(t, client.Call(ctx, "getnewaddress", nil, &addr))

	var blockHashes []string
	require.NoError(t, client.Call(ctx, "generatetoaddress", []interface{}{101, addr}, &blockHashes))

	// List UTXOs.
	utxos, err := client.ListUnspent(ctx, addr)
	require.NoError(t, err)
	assert.NotEmpty(t, utxos)
	assert.Greater(t, utxos[0].Amount, uint64(0))
}

func TestE2E_GetBlockHeader(t *testing.T) {
	client := regtestClient()
	skipIfUnavailable(t, client)

	ctx := context.Background()

	var bestHash string
	require.NoError(t, client.Call(ctx, "getbestblockhash", nil, &bestHash))

	header, err := client.GetBlockHeader(ctx, bestHash)
	require.NoError(t, err)
	assert.Len(t, header, 80)
}

func TestE2E_GetRawTxAndStatus(t *testing.T) {
	client := regtestClient()
	skipIfUnavailable(t, client)

	ctx := context.Background()

	// Generate a block with a coinbase tx.
	var addr string
	require.NoError(t, client.Call(ctx, "getnewaddress", nil, &addr))
	var blockHashes []string
	require.NoError(t, client.Call(ctx, "generatetoaddress", []interface{}{1, addr}, &blockHashes))

	// Get coinbase tx from the block.
	var block struct {
		Tx []string `json:"tx"`
	}
	require.NoError(t, client.Call(ctx, "getblock", []interface{}{blockHashes[0]}, &block))
	require.NotEmpty(t, block.Tx)
	txid := block.Tx[0]

	// GetRawTx.
	raw, err := client.GetRawTx(ctx, txid)
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	// GetTxStatus.
	status, err := client.GetTxStatus(ctx, txid)
	require.NoError(t, err)
	assert.True(t, status.Confirmed)
	assert.Equal(t, blockHashes[0], status.BlockHash)
}
