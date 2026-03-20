package network

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestARCBroadcastTx_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/tx", r.URL.Path)
		assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"txid":"abc123def456","txStatus":"SEEN_ON_NETWORK","extraInfo":""}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	txid, err := client.BroadcastTx(context.Background(), "0100000001...")

	require.NoError(t, err)
	assert.Equal(t, "abc123def456", txid)
}

func TestARCBroadcastTx_WithAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-key-123", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"txid":"abc123","txStatus":"SEEN_ON_NETWORK"}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1", APIKey: "test-key-123"})
	txid, err := client.BroadcastTx(context.Background(), "0100000001...")

	require.NoError(t, err)
	assert.Equal(t, "abc123", txid)
}

func TestARCBroadcastTx_400Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"status":400,"title":"Bad Request","detail":"malformed transaction"}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	txid, err := client.BroadcastTx(context.Background(), "invalid-hex")

	assert.Empty(t, txid)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBroadcastRejected)
	assert.Contains(t, err.Error(), "malformed transaction")
}

func TestARCBroadcastTx_429Retry(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"status":429,"title":"Too Many Requests","detail":"rate limited"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"txid":"retry-success","txStatus":"SEEN_ON_NETWORK"}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	// Override backoff base for faster tests (not possible via public API,
	// so we accept the default timing — the test server responds fast enough).
	txid, err := client.BroadcastTx(context.Background(), "0100000001...")

	require.NoError(t, err)
	assert.Equal(t, "retry-success", txid)
	assert.Equal(t, int32(3), attempts.Load())
}

func TestARCBroadcastTx_465FeeTooLow(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(465)
		fmt.Fprint(w, `{"status":465,"title":"Fee Too Low","detail":"transaction fee is below minimum"}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	txid, err := client.BroadcastTx(context.Background(), "0100000001...")

	assert.Empty(t, txid)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBroadcastRejected)
	assert.Contains(t, err.Error(), "transaction fee is below minimum")
	// Must NOT retry on 465.
	assert.Equal(t, int32(1), attempts.Load())
}

func TestARCBroadcastTx_5xxRetryExhausted(t *testing.T) {
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"status":500,"title":"Internal Server Error","detail":"server error"}`)
	}))
	defer srv.Close()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	txid, err := client.BroadcastTx(context.Background(), "0100000001...")

	assert.Empty(t, txid)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectionFailed)
	// Initial attempt + 3 retries = 4 total.
	assert.Equal(t, int32(4), attempts.Load())
}

func TestARCBroadcastTx_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"status":429,"title":"Too Many Requests","detail":"rate limited"}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	client := NewARCClient(ARCConfig{BaseURL: srv.URL + "/v1"})
	txid, err := client.BroadcastTx(ctx, "0100000001...")

	assert.Empty(t, txid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context")
}
