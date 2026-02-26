package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// RPCClient is a JSON-RPC 1.0 client for communicating with BSV nodes.
// It handles request serialization, authentication, and response parsing.
// All high-level blockchain methods are built on top of the Call method.
type RPCClient struct {
	url    string
	user   string
	pass   string
	client *http.Client
	nextID atomic.Int64
}

// rpcRequest represents a JSON-RPC 1.0 request payload.
type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int64         `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// rpcResponse represents a JSON-RPC 1.0 response payload.
type rpcResponse struct {
	ID     int64           `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// rpcError represents an error returned by the JSON-RPC server.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewRPCClient creates a new JSON-RPC client with the given configuration.
// The client uses HTTP Basic Auth when User is non-empty, and maintains
// a connection pool for efficient reuse.
func NewRPCClient(cfg RPCConfig) *RPCClient {
	return &RPCClient{
		url:  cfg.URL,
		user: cfg.User,
		pass: cfg.Password,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

// Call invokes a JSON-RPC method on the BSV node. It serializes the request,
// sends it with optional Basic Auth, and deserializes the response into result.
//
// If params is nil, an empty params array is sent. If result is nil, the
// response result is discarded (useful for fire-and-forget calls like sendrawtransaction).
//
// Call returns ErrConnectionFailed if the HTTP request fails, and ErrInvalidResponse
// if the response cannot be decoded. RPC-level errors (e.g., -5 "No such mempool
// transaction") are returned as plain errors with the server's error message.
func (c *RPCClient) Call(ctx context.Context, method string, params []interface{}, result interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	reqBody := rpcRequest{
		JSONRPC: "1.0",
		ID:      c.nextID.Add(1),
		Method:  method,
		Params:  params,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("network: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("network: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%w: HTTP %d: %s", ErrConnectionFailed, resp.StatusCode, string(respBody))
	}

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return fmt.Errorf("%w: decode response: %w", ErrInvalidResponse, err)
	}

	if rpcResp.ID != reqBody.ID {
		return fmt.Errorf("%w: response ID mismatch: expected %d, got %d",
			ErrInvalidResponse, reqBody.ID, rpcResp.ID)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("network: rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if result != nil && rpcResp.Result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("%w: unmarshal result: %w", ErrInvalidResponse, err)
		}
	}

	return nil
}
