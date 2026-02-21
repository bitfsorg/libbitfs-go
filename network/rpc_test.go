package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRPCClientCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "testuser", user)
		assert.Equal(t, "testpass", pass)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req rpcRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "getblockcount", req.Method)

		resp := rpcResponse{ID: req.ID, Result: json.RawMessage(`100`)}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL, User: "testuser", Password: "testpass"})
	var height int
	err := client.Call(context.Background(), "getblockcount", nil, &height)
	require.NoError(t, err)
	assert.Equal(t, 100, height)
}

func TestRPCClientRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		resp := rpcResponse{
			Error: &rpcError{Code: -5, Message: "No such mempool or blockchain transaction"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	var result json.RawMessage
	err := client.Call(context.Background(), "getrawtransaction", []interface{}{"badtxid"}, &result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "No such mempool")
}

func TestRPCClientConnectionError(t *testing.T) {
	client := NewRPCClient(RPCConfig{URL: "http://localhost:1"})
	var result int
	err := client.Call(context.Background(), "getblockcount", nil, &result)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
}

func TestRPCClientContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var result int
	err := client.Call(ctx, "getblockcount", nil, &result)
	require.Error(t, err)
}

func TestRPCClientSequentialIDs(t *testing.T) {
	var ids []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		ids = append(ids, req.ID)
		resp := rpcResponse{ID: req.ID, Result: json.RawMessage(`0`)}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	for i := 0; i < 3; i++ {
		var n int
		client.Call(context.Background(), "getblockcount", nil, &n)
	}
	assert.Equal(t, int64(1), ids[0])
	assert.Equal(t, int64(2), ids[1])
	assert.Equal(t, int64(3), ids[2])
}

func TestRPCClientNilResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		json.NewDecoder(r.Body).Decode(&req)
		resp := rpcResponse{ID: req.ID, Result: json.RawMessage(`"txid123"`)}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewRPCClient(RPCConfig{URL: server.URL})
	err := client.Call(context.Background(), "sendrawtransaction", []interface{}{"hex"}, nil)
	require.NoError(t, err)
}
