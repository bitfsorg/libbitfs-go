package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/network"
)

func TestEngineBroadcastTx(t *testing.T) {
	var broadcastedHex string
	mock := &network.MockBlockchainService{
		BroadcastTxFn: func(ctx context.Context, rawTxHex string) (string, error) {
			broadcastedHex = rawTxHex
			return "returned_txid", nil
		},
	}

	eng := &Vault{Chain: mock}
	txid, err := eng.BroadcastTx(context.Background(), "signed_hex_data")
	require.NoError(t, err)
	assert.Equal(t, "returned_txid", txid)
	assert.Equal(t, "signed_hex_data", broadcastedHex)
}

func TestEngineBroadcastTxNilChain(t *testing.T) {
	eng := &Vault{} // no Chain set
	_, err := eng.BroadcastTx(context.Background(), "hex")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no blockchain service")
}

func TestEngineRefreshFeeUTXOs(t *testing.T) {
	mock := &network.MockBlockchainService{
		ListUnspentFn: func(ctx context.Context, address string) ([]*network.UTXO, error) {
			return []*network.UTXO{
				{TxID: "aabb", Vout: 0, Amount: 50000, ScriptPubKey: "76a914aa"},
				{TxID: "ccdd", Vout: 1, Amount: 100000, ScriptPubKey: "76a914bb"},
			}, nil
		},
	}

	state := NewLocalState("")
	eng := &Vault{
		Chain: mock,
		State: state,
	}
	err := eng.RefreshFeeUTXOs(context.Background(), "1A1zP1", "pubkeyhex", 0, 0)
	require.NoError(t, err)

	// Should have added 2 UTXOs.
	count := 0
	for _, u := range eng.State.UTXOs {
		if u.Type == "fee" && !u.Spent {
			count++
		}
	}
	assert.Equal(t, 2, count)
}

func TestEngineRefreshFeeUTXOsDedup(t *testing.T) {
	mock := &network.MockBlockchainService{
		ListUnspentFn: func(ctx context.Context, address string) ([]*network.UTXO, error) {
			return []*network.UTXO{
				{TxID: "aabb", Vout: 0, Amount: 50000, ScriptPubKey: "76a914aa"},
			}, nil
		},
	}

	state := NewLocalState("")
	// Pre-add one UTXO that matches.
	state.AddUTXO(&UTXOState{TxID: "aabb", Vout: 0, Amount: 50000, Type: "fee"})

	eng := &Vault{Chain: mock, State: state}
	err := eng.RefreshFeeUTXOs(context.Background(), "1A1zP1", "pubkeyhex", 0, 0)
	require.NoError(t, err)

	// Should NOT duplicate.
	count := 0
	for _, u := range eng.State.UTXOs {
		if u.TxID == "aabb" && u.Vout == 0 {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestEngineRefreshFeeUTXOsNilChain(t *testing.T) {
	eng := &Vault{}
	err := eng.RefreshFeeUTXOs(context.Background(), "addr", "pub", 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no blockchain service")
}

func TestEngineIsOnline(t *testing.T) {
	eng := &Vault{Chain: &network.MockBlockchainService{}}
	assert.True(t, eng.IsOnline())
}

func TestEngineIsOffline(t *testing.T) {
	eng := &Vault{}
	assert.False(t, eng.IsOnline())
}
