package paymail

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Thin wrapper functions — verify delegation works (expected to fail on DNS/HTTP)
// ---------------------------------------------------------------------------

func TestResolveEndpoints_DelegatesToWithResolver(t *testing.T) {
	// Uses real DNS; nonexistent domain should fail.
	_, err := ResolveEndpoints("nonexistent.invalid", SRVBitFS)
	assert.Error(t, err)
}

func TestResolveDNSLinkPubKey_DelegatesToWithResolver(t *testing.T) {
	_, err := ResolveDNSLinkPubKey("nonexistent.invalid")
	assert.Error(t, err)
}

func TestDiscoverCapabilities_DelegatesToWithClient(t *testing.T) {
	_, err := DiscoverCapabilities("nonexistent.invalid")
	assert.Error(t, err)
}

func TestResolvePKI_DelegatesToWithClient(t *testing.T) {
	_, err := ResolvePKI("alice", "nonexistent.invalid")
	assert.Error(t, err)
}

func TestResolveURI_DelegatesToWith(t *testing.T) {
	_, _, err := ResolveURI("bitfs://alice@nonexistent.invalid/test")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ResolveDNSLinkPubKeyWithResolver — empty TXT list (not error, just empty)
// ---------------------------------------------------------------------------

func TestResolveDNSLinkPubKey_EmptyTXTRecordList(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs_pubkey.example.com") // empty list
	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

// ---------------------------------------------------------------------------
// ResolvePKIWithClient — PKI returns wrong-length pubkey
// ---------------------------------------------------------------------------

func TestResolvePKI_WrongLengthPubKey(t *testing.T) {
	// PKI returns valid hex but only 20 bytes (not 33)
	shortPubHex := hex.EncodeToString(make([]byte, 20))
	server := setupPaymailServer(t, shortPubHex)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

// ---------------------------------------------------------------------------
// ResolvePKIWithClient — PKI returns valid-length but wrong-prefix pubkey
// ---------------------------------------------------------------------------

func TestResolvePKI_WrongPrefixPubKey(t *testing.T) {
	// 33 bytes with 0x04 prefix (uncompressed marker)
	badKey := make([]byte, 33)
	badKey[0] = 0x04
	badPubHex := hex.EncodeToString(badKey)

	server := setupPaymailServer(t, badPubHex)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

// ---------------------------------------------------------------------------
// ResolvePKIWithClient — HTTP client returns error on PKI endpoint
// ---------------------------------------------------------------------------

func TestResolvePKI_PKIEndpointConnectionError(t *testing.T) {
	// Server that serves .well-known but then immediately closes for PKI
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/bsvalias", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki": "https://down.example.com/api/v1/bsvalias/pki/{alias}@{domain.tld}",
			},
		}
		json.NewEncoder(w).Encode(resp)
	})
	// No handler for /api/ — the mockHTTPClient will redirect to our server
	// which will 404 for /api/ paths
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

// ---------------------------------------------------------------------------
// ResolveURIWith — Paymail with PKI failure
// ---------------------------------------------------------------------------

func TestResolveURIWith_PaymailPKIFailure(t *testing.T) {
	// Server returns empty capabilities (no PKI)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias":     "1.0",
			"capabilities": map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	resolver := newMockDNSResolver()
	client := &mockHTTPClient{server: server}

	_, _, err := ResolveURIWith("bitfs://alice@example.com/docs", client, resolver)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ResolveURIWith — DNSLink with pubkey resolution failure
// ---------------------------------------------------------------------------

func TestResolveURIWith_DNSLinkPubKeyFailure(t *testing.T) {
	resolver := newMockDNSResolver()
	// No TXT record for the domain → resolution fails

	_, _, err := ResolveURIWith("bitfs://example.com/docs", DefaultHTTPClient, resolver)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// DiscoverCapabilities — capability matching via 'contains' keywords
// ---------------------------------------------------------------------------

func TestDiscoverCapabilities_ContainsKeywordMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"some-pki-endpoint":             "https://example.com/pki/{alias}@{domain.tld}",
				"public-profile-v2":             "https://example.com/profile/{alias}@{domain.tld}",
				"verify-pubkey-implementation":  "https://example.com/verify/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	caps, err := DiscoverCapabilitiesWithClient("example.com", client)
	require.NoError(t, err)
	assert.NotEmpty(t, caps.PKI, "should match 'pki' keyword")
	assert.NotEmpty(t, caps.PublicProfile, "should match 'public-profile' keyword")
	assert.NotEmpty(t, caps.VerifyPubKey, "should match 'verify-pubkey' keyword")
}

// ---------------------------------------------------------------------------
// ResolveEndpoints — SRV trailing dot removal
// ---------------------------------------------------------------------------

func TestResolveEndpoints_TrailingDotRemoval(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bitfs", "tcp", "example.com",
		&net.SRV{Target: "node.example.com.", Port: 8443, Priority: 10, Weight: 100},
	)

	endpoints, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	require.NoError(t, err)
	assert.Equal(t, "node.example.com:8443", endpoints[0])
	assert.False(t, strings.HasSuffix(endpoints[0], "."), "trailing dot should be removed")
}

// ---------------------------------------------------------------------------
// defaultDNSResolver — verify it implements DNSResolver interface
// ---------------------------------------------------------------------------

func TestDefaultDNSResolver_ImplementsInterface(t *testing.T) {
	var _ DNSResolver = DefaultDNSResolver
	var _ DNSResolver = &defaultDNSResolver{}
}

// ---------------------------------------------------------------------------
// ParseURI — authority-only edge cases
// ---------------------------------------------------------------------------

func TestParseURI_DomainWithPort(t *testing.T) {
	// bitfs://example.com:8080/path — port is part of the authority
	parsed, err := ParseURI("bitfs://example.com:8080/path")
	require.NoError(t, err)
	assert.Equal(t, AddressDNSLink, parsed.Type)
	assert.Equal(t, "example.com:8080", parsed.Domain)
	assert.Equal(t, "/path", parsed.Path)
}

func TestParseURI_IPAddress(t *testing.T) {
	parsed, err := ParseURI("bitfs://192.168.1.1/file.txt")
	require.NoError(t, err)
	assert.Equal(t, AddressDNSLink, parsed.Type)
	assert.Equal(t, "192.168.1.1", parsed.Domain)
}

// ---------------------------------------------------------------------------
// ResolveURIWith — PubKey with valid pubkey returns nil endpoints
// ---------------------------------------------------------------------------

func TestResolveURIWith_PubKey_NilEndpoints(t *testing.T) {
	uri := "bitfs://" + testPubKeyHex + "/docs/file.txt"
	pubKey, endpoints, err := ResolveURIWith(uri, DefaultHTTPClient, newMockDNSResolver())
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.Nil(t, endpoints, "PubKey addressing should return nil endpoints")
}

// ---------------------------------------------------------------------------
// ResolveDNSLinkPubKeyWithResolver — multiple TXT records, first valid wins
// ---------------------------------------------------------------------------

func TestResolveDNSLinkPubKey_MultipleRecords_FirstValidWins(t *testing.T) {
	altKey := "03" + strings.Repeat("cd", 32)
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs_pubkey.example.com", testPubKeyHex, altKey)

	pubKey, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	require.NoError(t, err)

	expected, _ := hex.DecodeString(testPubKeyHex)
	assert.Equal(t, expected, pubKey, "should use first non-empty record")
}

// ---------------------------------------------------------------------------
// mockHTTPClient — path routing edge cases
// ---------------------------------------------------------------------------

func TestMockHTTPClient_PathRewriting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}

	// Test .well-known path
	resp, err := client.Get("https://example.com/.well-known/bsvalias")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
