package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ARCConfig holds the connection parameters for a BSV ARC transaction processor.
type ARCConfig struct {
	BaseURL string // e.g. "https://arc.taal.com/v1"
	APIKey  string // optional Bearer token
}

// ARCClient is a REST client for the ARC (BSV transaction processor) API.
// It handles transaction broadcasting with automatic retry on transient errors.
type ARCClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// arcResponse represents the JSON response from the ARC API.
// On success, TxID and TxStatus are populated.
// On error, Status, Title, and Detail describe the failure.
type arcResponse struct {
	TxID      string `json:"txid"`
	TxStatus  string `json:"txStatus"`
	ExtraInfo string `json:"extraInfo"`
	Status    int    `json:"status"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
}

const (
	arcMaxRetries   = 3
	arcBaseBackoff  = 500 * time.Millisecond
	arcStatusFeeLow = 465
)

// NewARCClient creates a new ARC REST client with the given configuration.
func NewARCClient(cfg ARCConfig) *ARCClient {
	return &ARCClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// BroadcastTx submits a raw transaction hex string to the ARC API and returns
// the transaction ID on success. It retries on 429 (rate limit) and 5xx
// (server error) responses with exponential backoff, respecting the
// Retry-After header when present. Status 465 (fee too low) is not retried.
func (c *ARCClient) BroadcastTx(ctx context.Context, rawTxHex string) (string, error) {
	url := c.baseURL + "/tx"

	var lastErr error
	for attempt := 0; attempt <= arcMaxRetries; attempt++ {
		if attempt > 0 {
			if err := ctx.Err(); err != nil {
				return "", fmt.Errorf("network: context cancelled during retry: %w", err)
			}
		}

		txid, retryAfter, err := c.doPost(ctx, url, rawTxHex)
		if err == nil {
			return txid, nil
		}
		lastErr = err

		if retryAfter < 0 || attempt == arcMaxRetries {
			break
		}

		// Use the larger of exponential backoff and server-requested delay.
		backoff := arcBaseBackoff << uint(attempt)
		if retryAfter > backoff {
			backoff = retryAfter
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return "", fmt.Errorf("network: context cancelled during backoff: %w", ctx.Err())
		}
	}

	return "", lastErr
}

// doPost performs a single POST request to the ARC API.
// It returns the txid on success. On retryable failure, it returns a
// non-negative retryAfter duration (0 means use default backoff).
// On non-retryable failure, retryAfter is -1.
func (c *ARCClient) doPost(ctx context.Context, url, body string) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", -1, fmt.Errorf("network: create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", -1, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseSize = 1 << 20 // 1 MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", -1, fmt.Errorf("%w: read response: %w", ErrInvalidResponse, err)
	}

	var arcResp arcResponse
	if err := json.Unmarshal(respBody, &arcResp); err != nil {
		return "", -1, fmt.Errorf("%w: decode response: %w", ErrInvalidResponse, err)
	}

	// Success
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if arcResp.TxID == "" {
			return "", -1, fmt.Errorf("%w: missing txid in response", ErrInvalidResponse)
		}
		return arcResp.TxID, 0, nil
	}

	// Non-retryable: 465 fee too low
	if resp.StatusCode == arcStatusFeeLow {
		detail := arcResp.Detail
		if detail == "" {
			detail = "fee too low"
		}
		return "", -1, fmt.Errorf("%w: %s", ErrBroadcastRejected, detail)
	}

	// Retryable: 429 or 5xx
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		var retryAfter time.Duration
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				retryAfter = time.Duration(secs) * time.Second
				// Cap at 30 seconds to avoid indefinite waits.
				if retryAfter > 30*time.Second {
					retryAfter = 30 * time.Second
				}
			}
		}
		detail := arcResp.Detail
		if detail == "" {
			detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", retryAfter, fmt.Errorf("%w: %s", ErrConnectionFailed, detail)
	}

	// Non-retryable client error (4xx other than 429 and 465)
	detail := arcResp.Detail
	if detail == "" {
		detail = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, arcResp.Title)
	}
	return "", -1, fmt.Errorf("%w: %s", ErrBroadcastRejected, detail)
}
