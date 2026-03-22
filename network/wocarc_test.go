package network

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWoCARCClient_QueriesRouteToWoC(t *testing.T) {
	wocSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/address/1Addr/unspent/all":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `[{"height":100,"tx_pos":0,"tx_hash":"aabb","value":50000}]`)
		case "/chain/info":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"blocks":850000}`)
		case "/block/height/0":
			fmt.Fprint(w, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer wocSrv.Close()

	arcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("ARC should not be called for query methods")
	}))
	defer arcSrv.Close()

	client := &WoCARCClient{
		woc: newTestWoC(wocSrv),
		arc: NewARCClient(ARCConfig{BaseURL: arcSrv.URL}),
	}

	ctx := context.Background()

	// ListUnspent → WoC
	utxos, err := client.ListUnspent(ctx, "1Addr")
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	assert.Equal(t, "aabb", utxos[0].TxID)

	// GetBestBlockHeight → WoC
	height, err := client.GetBestBlockHeight(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(850000), height)

	// GetBlockHash → WoC (BlockHashProvider)
	hash, err := client.GetBlockHash(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", hash)

	// ImportAddress → WoC (no-op)
	err = client.ImportAddress(ctx, "1Addr")
	require.NoError(t, err)
}

func TestWoCARCClient_BroadcastRoutesToARC(t *testing.T) {
	wocSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("WoC should not be called for broadcast")
	}))
	defer wocSrv.Close()

	arcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/tx", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"txid":"broadcast123","txStatus":"SEEN_ON_NETWORK"}`)
	}))
	defer arcSrv.Close()

	client := &WoCARCClient{
		woc: newTestWoC(wocSrv),
		arc: NewARCClient(ARCConfig{BaseURL: arcSrv.URL + "/v1"}),
	}

	txid, err := client.BroadcastTx(context.Background(), "0100000001...")
	require.NoError(t, err)
	assert.Equal(t, "broadcast123", txid)
}

func TestWoCARCClient_BroadcastNoWoCFallback(t *testing.T) {
	wocCalled := false
	wocSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wocCalled = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `"woc-txid"`)
	}))
	defer wocSrv.Close()

	arcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"detail":"internal error"}`)
	}))
	defer arcSrv.Close()

	client := &WoCARCClient{
		woc: newTestWoC(wocSrv),
		arc: NewARCClient(ARCConfig{BaseURL: arcSrv.URL + "/v1"}),
	}

	_, err := client.BroadcastTx(context.Background(), "0100000001...")
	require.Error(t, err, "ARC failure should return error, not fall back to WoC")
	assert.False(t, wocCalled, "WoC should not be called when ARC fails")
}

func TestDefaultWoCARCEndpoints(t *testing.T) {
	tests := []struct {
		network string
		wantWoC string
		wantARC string
		wantErr bool
	}{
		{"mainnet", "https://api.whatsonchain.com/v1/bsv/main", "https://arc.taal.com/v1", false},
		{"testnet", "https://api.whatsonchain.com/v1/bsv/test", "https://arc.taal.com/v1", false},
		{"regtest", "", "", true},
		{"unknown", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			woc, arc, err := DefaultWoCARCEndpoints(tt.network)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.network)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantWoC, woc)
			assert.Equal(t, tt.wantARC, arc)
		})
	}
}
