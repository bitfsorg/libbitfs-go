package paymail

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPostClient wraps an httptest.Server to implement PostClient.
// It supports both GET (for capability discovery) and POST (for payment destination).
type mockPostClient struct {
	mockHTTPClient
}

func (m *mockPostClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	// Rewrite the URL to point to the test server, same logic as Get.
	return m.mockHTTPClient.rewriteAndDo("POST", url, contentType, body)
}

// rewriteAndDo rewrites the URL to the test server and performs the request.
func (m *mockHTTPClient) rewriteAndDo(method, rawURL, contentType string, body io.Reader) (*http.Response, error) {
	rewritten := m.rewriteURL(rawURL)
	req, err := http.NewRequest(method, rewritten, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return http.DefaultClient.Do(req)
}

// rewriteURL maps a production URL to the test server URL.
func (m *mockHTTPClient) rewriteURL(rawURL string) string {
	// Same rewriting logic as mockHTTPClient.Get, extracted for reuse.
	idx := indexOf(rawURL, "/.")
	if idx == -1 {
		idx = indexOf(rawURL, "/api/")
		if idx == -1 {
			parts := splitN(rawURL, "//", 2)
			if len(parts) == 2 {
				slashIdx := indexOf(parts[1], "/")
				if slashIdx >= 0 {
					return m.server.URL + parts[1][slashIdx:]
				}
				return m.server.URL + "/"
			}
		} else {
			return m.server.URL + rawURL[idx:]
		}
	} else {
		return m.server.URL + rawURL[idx:]
	}
	return m.server.URL + "/"
}

// indexOf returns the index of substr in s, or -1.
func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// splitN splits s by sep into at most n parts.
func splitN(s, sep string, n int) []string {
	idx := indexOf(s, sep)
	if idx == -1 || n <= 1 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

// setupPaymentDestinationServer creates a test server that advertises
// a payment destination capability and responds to POST requests.
func setupPaymentDestinationServer(t *testing.T, outputs []PaymentOutput) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/bsvalias", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki":          "https://example.com/api/v1/bsvalias/pki/{alias}@{domain.tld}",
				"2a40af698840": "https://example.com/api/v1/bsvalias/p2p-payment-destination/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/v1/bsvalias/p2p-payment-destination/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"outputs": outputs,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func TestResolvePaymentDestination_Success(t *testing.T) {
	outputs := []PaymentOutput{
		{Script: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", Satoshis: 1000},
	}
	server := setupPaymentDestinationServer(t, outputs)
	defer server.Close()

	client := &mockPostClient{mockHTTPClient{server: server}}
	result, err := ResolvePaymentDestinationWithClient("alice", "example.com", client)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", result[0].Script)
	assert.Equal(t, uint64(1000), result[0].Satoshis)
}

func TestResolvePaymentDestination_EmptyAlias(t *testing.T) {
	_, err := ResolvePaymentDestinationWithClient("", "example.com", &mockPostClient{mockHTTPClient{}})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAddressResolution)
}

func TestResolvePaymentDestination_EmptyDomain(t *testing.T) {
	_, err := ResolvePaymentDestinationWithClient("alice", "", &mockPostClient{mockHTTPClient{}})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAddressResolution)
}

func TestResolvePaymentDestination_NoCapability(t *testing.T) {
	// Server without payment destination capability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki": "https://example.com/api/v1/bsvalias/pki/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &mockPostClient{mockHTTPClient{server: server}}
	_, err := ResolvePaymentDestinationWithClient("alice", "example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAddressResolution)
}

func TestResolvePaymentDestination_EmptyOutputs(t *testing.T) {
	server := setupPaymentDestinationServer(t, []PaymentOutput{})
	defer server.Close()

	client := &mockPostClient{mockHTTPClient{server: server}}
	_, err := ResolvePaymentDestinationWithClient("alice", "example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAddressResolution)
}

func TestResolvePaymentDestination_MultipleOutputs(t *testing.T) {
	outputs := []PaymentOutput{
		{Script: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac", Satoshis: 500},
		{Script: "76a914aabbccddaabbccddaabbccddaabbccddaabbccdd88ac", Satoshis: 500},
	}
	server := setupPaymentDestinationServer(t, outputs)
	defer server.Close()

	client := &mockPostClient{mockHTTPClient{server: server}}
	result, err := ResolvePaymentDestinationWithClient("alice", "example.com", client)
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, uint64(500), result[0].Satoshis)
	assert.Equal(t, uint64(500), result[1].Satoshis)
}
