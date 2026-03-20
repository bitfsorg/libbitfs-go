package network

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Compile-time interface checks.
var (
	_ BlockchainService = (*WoCClient)(nil)
	_ BlockHashProvider = (*WoCClient)(nil)
)

// WoCConfig holds configuration for connecting to the WhatsOnChain REST API.
type WoCConfig struct {
	// BaseURL is the API root, e.g. "https://api.whatsonchain.com/v1/bsv/main".
	// Trailing slashes are stripped automatically.
	BaseURL string `json:"base_url"`

	// APIKey is an optional WoC API key. When set, requests include the
	// "woc-api-key" header for authenticated rate limits.
	APIKey string `json:"api_key,omitempty"`
}

// WoCClient is a read-only WhatsOnChain REST API client that implements
// BlockchainService (except BroadcastTx) and BlockHashProvider.
//
// It provides blockchain queries with automatic retry on transient errors
// (HTTP 429 and 5xx) using exponential backoff.
type WoCClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// wocRetryConfig controls the exponential backoff behaviour.
const (
	wocMaxRetries   = 3
	wocBaseDelay    = 500 * time.Millisecond
	wocMaxDelay     = 15 * time.Second
	wocMaxPages     = 20
	wocMaxRespBytes = 10 << 20 // 10 MB
)

// NewWoCClient creates a new WhatsOnChain REST client.
func NewWoCClient(cfg WoCConfig) *WoCClient {
	return &WoCClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:  cfg.APIKey,
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

// doGet performs an HTTP GET with retry logic. It returns the response body
// bytes on success. On 404 it returns ErrTxNotFound. On other non-2xx
// responses after exhausting retries, it returns ErrConnectionFailed.
func (w *WoCClient) doGet(ctx context.Context, path string) ([]byte, error) {
	url := w.baseURL + path

	var lastErr error
	for attempt := 0; attempt <= wocMaxRetries; attempt++ {
		if attempt > 0 {
			delay := wocBaseDelay * time.Duration(1<<(attempt-1))
			if delay > wocMaxDelay {
				delay = wocMaxDelay
			}

			// Respect Retry-After header if present from last attempt.
			if retryAfter, ok := lastErr.(retryAfterError); ok {
				if retryAfter.after > delay {
					delay = retryAfter.after
				}
				if delay > wocMaxDelay {
					delay = wocMaxDelay
				}
			}

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %w", ErrConnectionFailed, ctx.Err())
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("woc: create request: %w", err)
		}
		if w.apiKey != "" {
			req.Header.Set("woc-api-key", w.apiKey)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("%w: %w", ErrConnectionFailed, err)
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, wocMaxRespBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("%w: read body: %w", ErrConnectionFailed, readErr)
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %s", ErrTxNotFound, path)
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			after := parseRetryAfter(resp.Header.Get("Retry-After"))
			lastErr = retryAfterError{
				err:   fmt.Errorf("woc: HTTP %d: %s", resp.StatusCode, truncate(string(body), 256)),
				after: after,
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("%w: HTTP %d: %s", ErrConnectionFailed, resp.StatusCode, truncate(string(body), 256))
		}

		return body, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: retries exhausted: %v", ErrConnectionFailed, lastErr)
	}
	return nil, fmt.Errorf("%w: retries exhausted", ErrConnectionFailed)
}

// retryAfterError wraps an error with a Retry-After duration.
type retryAfterError struct {
	err   error
	after time.Duration
}

func (e retryAfterError) Error() string { return e.err.Error() }
func (e retryAfterError) Unwrap() error { return e.err }

// parseRetryAfter parses the Retry-After header value as seconds.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// truncate limits s to n bytes for error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------- BlockchainService implementation ----------

// wocUnspentItem represents a single UTXO from the WoC unspent endpoint.
type wocUnspentItem struct {
	Height uint64 `json:"height"`
	TxPos  uint32 `json:"tx_pos"`
	TxHash string `json:"tx_hash"`
	Value  uint64 `json:"value"`
}

// ListUnspent returns all unspent transaction outputs for the given address.
// It paginates through the /address/{addr}/unspent/all endpoint.
func (w *WoCClient) ListUnspent(ctx context.Context, address string) ([]*UTXO, error) {
	var allUTXOs []*UTXO

	for page := 0; page < wocMaxPages; page++ {
		path := fmt.Sprintf("/address/%s/unspent/all", address)
		if page > 0 {
			path = fmt.Sprintf("/address/%s/unspent/all?nextPageToken=%d", address, page)
		}

		body, err := w.doGet(ctx, path)
		if err != nil {
			// 404 for an address with no UTXOs is not an error.
			if errors.Is(err, ErrTxNotFound) {
				return allUTXOs, nil
			}
			return nil, fmt.Errorf("woc: list unspent: %w", err)
		}

		// WoC /unspent/all returns either a flat array or a wrapped object
		// {"address":"...","result":[...],"nextPageToken":"..."}.
		var items []wocUnspentItem
		if err := json.Unmarshal(body, &items); err != nil {
			// Try wrapped format.
			var wrapped struct {
				Result        []wocUnspentItem `json:"result"`
				NextPageToken string           `json:"nextPageToken"`
			}
			if err2 := json.Unmarshal(body, &wrapped); err2 != nil {
				return nil, fmt.Errorf("%w: unmarshal unspent: %w: %s", ErrInvalidResponse, err, truncate(string(body), 128))
			}
			items = wrapped.Result
		}

		if len(items) == 0 {
			break
		}

		for _, item := range items {
			var confirmations int64
			if item.Height > 0 {
				confirmations = 1 // At least 1 confirmation if mined.
			}
			allUTXOs = append(allUTXOs, &UTXO{
				TxID:          item.TxHash,
				Vout:          item.TxPos,
				Amount:        item.Value,
				Address:       address,
				Confirmations: confirmations,
			})
		}

		// WoC returns fewer items when there are no more pages.
		// If we got a full page (1000 items), there may be more.
		if len(items) < 1000 {
			break
		}
	}

	return allUTXOs, nil
}

// wocTxVout represents a transaction output from the WoC tx info endpoint.
type wocTxVout struct {
	Value        float64 `json:"value"`
	N            uint32  `json:"n"`
	ScriptPubKey struct {
		Hex       string   `json:"hex"`
		Addresses []string `json:"addresses"`
	} `json:"scriptPubKey"`
}

// wocTxInfo represents the WoC /tx/{txid} response.
type wocTxInfo struct {
	TxID          string      `json:"txid"`
	Confirmations int64       `json:"confirmations"`
	BlockHash     string      `json:"blockhash"`
	BlockHeight   uint64      `json:"blockheight"`
	Vout          []wocTxVout `json:"vout"`
}

// GetUTXO returns a specific unspent transaction output by txid and output index.
// It fetches the full transaction info and extracts the requested vout.
func (w *WoCClient) GetUTXO(ctx context.Context, txid string, vout uint32) (*UTXO, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/tx/%s", txid))
	if err != nil {
		return nil, fmt.Errorf("woc: get utxo: %w", err)
	}

	var txInfo wocTxInfo
	if err := json.Unmarshal(body, &txInfo); err != nil {
		return nil, fmt.Errorf("%w: unmarshal tx info: %w", ErrInvalidResponse, err)
	}

	for _, out := range txInfo.Vout {
		if out.N == vout {
			utxo := &UTXO{
				TxID:          txid,
				Vout:          vout,
				Amount:        btcToSat(out.Value),
				ScriptPubKey:  out.ScriptPubKey.Hex,
				Confirmations: txInfo.Confirmations,
			}
			if len(out.ScriptPubKey.Addresses) > 0 {
				utxo.Address = out.ScriptPubKey.Addresses[0]
			}
			return utxo, nil
		}
	}

	return nil, fmt.Errorf("%w: output %s:%d not found", ErrTxNotFound, txid, vout)
}

// BroadcastTx is not supported by WoCClient. Use ARC for transaction broadcast.
func (w *WoCClient) BroadcastTx(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("%w: WoC does not support broadcast, use ARC", ErrBroadcastRejected)
}

// GetRawTx returns the raw transaction bytes for the given txid.
// It calls GET /tx/{txid}/hex which returns plain-text hex.
func (w *WoCClient) GetRawTx(ctx context.Context, txid string) ([]byte, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/tx/%s/hex", txid))
	if err != nil {
		return nil, fmt.Errorf("woc: get raw tx: %w", err)
	}

	rawHex := strings.TrimSpace(string(body))
	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tx hex: %w", ErrInvalidResponse, err)
	}
	return data, nil
}

// GetTxStatus returns the confirmation status of a transaction.
func (w *WoCClient) GetTxStatus(ctx context.Context, txid string) (*TxStatus, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/tx/%s", txid))
	if err != nil {
		return nil, fmt.Errorf("woc: get tx status: %w", err)
	}

	var txInfo wocTxInfo
	if err := json.Unmarshal(body, &txInfo); err != nil {
		return nil, fmt.Errorf("%w: unmarshal tx info: %w", ErrInvalidResponse, err)
	}

	return &TxStatus{
		Confirmed:   txInfo.Confirmations > 0,
		BlockHash:   txInfo.BlockHash,
		BlockHeight: txInfo.BlockHeight,
	}, nil
}

// wocBlockHeader represents the WoC /block/{hash}/header JSON response.
type wocBlockHeader struct {
	Version       int32  `json:"version"`
	PrevBlockHash string `json:"previousblockhash"`
	MerkleRoot    string `json:"merkleroot"`
	Time          uint32 `json:"time"`
	Bits          string `json:"bits"`
	Nonce         uint32 `json:"nonce"`
}

// GetBlockHeader returns the raw 80-byte block header for the given block hash.
// WoC returns JSON with individual header fields; we serialize them into the
// standard 80-byte binary format (little-endian wire order).
func (w *WoCClient) GetBlockHeader(ctx context.Context, blockHash string) ([]byte, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/block/%s/header", blockHash))
	if err != nil {
		return nil, fmt.Errorf("woc: get block header: %w", err)
	}

	var hdr wocBlockHeader
	if err := json.Unmarshal(body, &hdr); err != nil {
		return nil, fmt.Errorf("%w: unmarshal block header: %w", ErrInvalidResponse, err)
	}

	return serializeBlockHeader(hdr)
}

// serializeBlockHeader packs a wocBlockHeader into 80 bytes (wire format).
func serializeBlockHeader(hdr wocBlockHeader) ([]byte, error) {
	buf := make([]byte, 80)

	// Version: 4 bytes LE.
	binary.LittleEndian.PutUint32(buf[0:4], uint32(hdr.Version))

	// PrevBlockHash: 32 bytes, display hex (big-endian) reversed to wire order (LE).
	prevHash, err := hexToWireOrder(hdr.PrevBlockHash)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid prevblockhash: %w", ErrInvalidResponse, err)
	}
	copy(buf[4:36], prevHash)

	// MerkleRoot: 32 bytes, display hex reversed to wire order.
	merkleRoot, err := hexToWireOrder(hdr.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid merkleroot: %w", ErrInvalidResponse, err)
	}
	copy(buf[36:68], merkleRoot)

	// Time: 4 bytes LE.
	binary.LittleEndian.PutUint32(buf[68:72], hdr.Time)

	// Bits: 4 bytes LE. Bits is a hex string representing a uint32.
	bits, err := strconv.ParseUint(hdr.Bits, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid bits %q: %w", ErrInvalidResponse, hdr.Bits, err)
	}
	binary.LittleEndian.PutUint32(buf[72:76], uint32(bits))

	// Nonce: 4 bytes LE.
	binary.LittleEndian.PutUint32(buf[76:80], hdr.Nonce)

	return buf, nil
}

// hexToWireOrder decodes a hex string and reverses the bytes from display
// (big-endian) to wire (little-endian) order. Expects exactly 64 hex chars
// (32 bytes).
func hexToWireOrder(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	return reverseBytesCopy(b), nil
}

// wocTSCProof represents the WoC TSC Merkle proof response.
type wocTSCProof struct {
	Index  int      `json:"index"`
	TxOrID string   `json:"txOrId"`
	Target string   `json:"target"`
	Nodes  []string `json:"nodes"`
}

// GetMerkleProof returns a Merkle inclusion proof for a confirmed transaction.
// It uses the WoC TSC proof endpoint: GET /tx/{txid}/proof/tsc.
func (w *WoCClient) GetMerkleProof(ctx context.Context, txid string) (*MerkleProof, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/tx/%s/proof/tsc", txid))
	if err != nil {
		return nil, fmt.Errorf("woc: get merkle proof: %w", err)
	}

	var proof wocTSCProof
	if err := json.Unmarshal(body, &proof); err != nil {
		return nil, fmt.Errorf("%w: unmarshal tsc proof: %w", ErrInvalidResponse, err)
	}

	branches := make([][]byte, 0, len(proof.Nodes))
	for i, node := range proof.Nodes {
		if node == "*" {
			// "*" means the hash is a duplicate of the sibling — use nil sentinel.
			branches = append(branches, nil)
			continue
		}
		b, err := hex.DecodeString(node)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid node hash at index %d: %w", ErrInvalidResponse, i, err)
		}
		branches = append(branches, b)
	}

	return &MerkleProof{
		TxID:      txid,
		BlockHash: proof.Target,
		Branches:  branches,
		Index:     proof.Index,
	}, nil
}

// wocChainInfo represents the WoC /chain/info response (partial).
type wocChainInfo struct {
	Blocks uint64 `json:"blocks"`
}

// GetBestBlockHeight returns the height of the current chain tip.
func (w *WoCClient) GetBestBlockHeight(ctx context.Context) (uint64, error) {
	body, err := w.doGet(ctx, "/chain/info")
	if err != nil {
		return 0, fmt.Errorf("woc: get chain info: %w", err)
	}

	var info wocChainInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return 0, fmt.Errorf("%w: unmarshal chain info: %w", ErrInvalidResponse, err)
	}
	return info.Blocks, nil
}

// ImportAddress is a no-op for WoC. WhatsOnChain indexes all addresses
// automatically and does not require watch-only address registration.
func (w *WoCClient) ImportAddress(_ context.Context, _ string) error {
	return nil
}

// ---------- BlockHashProvider implementation ----------

// wocBlockHashResp represents the WoC /block/height/{height} response.
type wocBlockHashResp struct {
	Hash string `json:"hash"`
}

// GetBlockHash returns the block hash at the given height.
func (w *WoCClient) GetBlockHash(ctx context.Context, height uint64) (string, error) {
	body, err := w.doGet(ctx, fmt.Sprintf("/block/height/%d", height))
	if err != nil {
		return "", fmt.Errorf("woc: get block hash: %w", err)
	}

	// WoC may return the hash as a plain string or as a JSON object.
	s := strings.TrimSpace(string(body))
	if len(s) == 64 && isHex(s) {
		return s, nil
	}

	var resp wocBlockHashResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("%w: unmarshal block hash: %w", ErrInvalidResponse, err)
	}
	if resp.Hash == "" {
		return "", fmt.Errorf("%w: empty block hash at height %d", ErrInvalidResponse, height)
	}
	return resp.Hash, nil
}

// isHex returns true if s contains only hexadecimal characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// btcToSat and reverseBytesCopy are defined in rpc_blockchain.go.
