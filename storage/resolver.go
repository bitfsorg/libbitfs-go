package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MaxContentResponseSize is the maximum allowed response body size for content
// fetches (1 GB). This prevents memory exhaustion from malicious endpoints.
const MaxContentResponseSize = 1 << 30

// ContentResolver fetches encrypted content by key_hash from multiple sources
// in priority order: local FileStore -> daemon HTTP endpoints.
// It returns ciphertext only; the caller is responsible for decryption.
type ContentResolver struct {
	Store     *FileStore   // local content-addressed storage
	Endpoints []string     // daemon/CDN base URLs (e.g. "http://localhost:8080")
	Client    *http.Client // HTTP client for remote fetches; nil uses default
}

// NewContentResolver creates a ContentResolver with the given local store.
// Endpoints and Client can be set after creation.
func NewContentResolver(store *FileStore) *ContentResolver {
	return &ContentResolver{
		Store: store,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Fetch retrieves ciphertext for the given key_hash, trying sources in order:
//  1. Local FileStore (~/.bitfs/storage/)
//  2. Daemon HTTP endpoints (GET /_bitfs/data/{hex(keyHash)})
//
// Returns the first successful result or an error if all sources fail.
func (r *ContentResolver) Fetch(keyHash []byte) ([]byte, error) {
	if err := validateKeyHash(keyHash); err != nil {
		return nil, err
	}

	// 1. Try local storage first.
	if r.Store != nil {
		data, err := r.Store.Get(keyHash)
		if err == nil {
			return data, nil
		}
		// Only continue if not found; other errors are real failures.
		if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("resolver: local store: %w", err)
		}
	}

	// 2. Try daemon HTTP endpoints.
	hashHex := hex.EncodeToString(keyHash)
	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	for _, ep := range r.Endpoints {
		data, err := r.fetchFromEndpoint(client, ep, hashHex)
		if err == nil {
			// Verify content hash before trusting remote data.
			actualHash := sha256.Sum256(data)
			if len(keyHash) == KeyHashSize && !bytesEqual(actualHash[:], keyHash) {
				// Hash mismatch — skip this endpoint and try the next one.
				continue
			}
			// Cache locally for future access.
			if r.Store != nil {
				_ = r.Store.Put(keyHash, data) // best-effort cache
			}
			return data, nil
		}
		// Continue to next endpoint on any error.
	}

	return nil, fmt.Errorf("resolver: %w: key_hash %s", ErrNotFound, hashHex)
}

// fetchFromEndpoint fetches ciphertext from a single daemon endpoint.
// Endpoint: GET {baseURL}/_bitfs/data/{hashHex}
func (r *ContentResolver) fetchFromEndpoint(client *http.Client, baseURL, hashHex string) ([]byte, error) {
	url := baseURL + "/_bitfs/data/" + hashHex

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("resolver: endpoint %s: %w", baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resolver: endpoint %s: HTTP %d", baseURL, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxContentResponseSize))
	if err != nil {
		return nil, fmt.Errorf("resolver: endpoint %s: read body: %w", baseURL, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("resolver: endpoint %s: empty response", baseURL)
	}

	return data, nil
}

// bytesEqual returns true if a and b are equal length and contents.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
