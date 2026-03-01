package paymail

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	resolver.addTXT("_bitfs.example.com") // empty list
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
// DiscoverCapabilities — exact capability key matching (no substring matching)
// ---------------------------------------------------------------------------

func TestDiscoverCapabilities_ExactKeyMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				// Non-standard keys should NOT match (prevents "custom-spki" → "pki" false positive).
				"some-pki-endpoint":            "https://example.com/pki/{alias}@{domain.tld}",
				"public-profile-v2":            "https://example.com/profile/{alias}@{domain.tld}",
				"verify-pubkey-implementation": "https://example.com/verify/{alias}@{domain.tld}",
				// Standard keys SHOULD match.
				"pki":          "https://example.com/standard-pki/{alias}@{domain.tld}",
				"a9f510c16bde": "https://example.com/standard-verify/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	caps, err := DiscoverCapabilitiesWithClient("example.com", client)
	require.NoError(t, err)
	// Exact key matches should work.
	assert.Contains(t, caps.PKI, "standard-pki", "exact 'pki' key should match")
	assert.Contains(t, caps.VerifyPubKey, "standard-verify", "exact BRFC key should match")
	// Substring matches should NOT work — non-standard keys are ignored.
	assert.NotContains(t, caps.PKI, "/pki/{alias}@", "non-standard 'some-pki-endpoint' key should not match")
	assert.Empty(t, caps.PublicProfile, "non-standard 'public-profile-v2' key should not match")
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
	var _ = DefaultDNSResolver
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
	resolver.addTXT("_bitfs.example.com", "bitfs="+testPubKeyHex, "bitfs="+altKey)

	pubKey, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	require.NoError(t, err)

	expected, _ := hex.DecodeString(testPubKeyHex)
	assert.Equal(t, expected, pubKey, "should use first non-empty record")
}

// ---------------------------------------------------------------------------
// validateCapabilityHost — SSRF mitigation unit tests (R09-H1)
// ---------------------------------------------------------------------------

func TestValidateCapabilityHost(t *testing.T) {
	tests := []struct {
		name           string
		capHost        string
		originalDomain string
		want           bool
	}{
		// Exact match
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "Example.COM", "example.com", true},

		// Subdomain match
		{"subdomain match", "api.example.com", "example.com", true},
		{"deep subdomain match", "a.b.c.example.com", "example.com", true},
		{"subdomain case insensitive", "API.Example.COM", "example.com", true},

		// Rejections — different domain
		{"different domain", "evil.com", "example.com", false},
		{"similar suffix not subdomain", "notexample.com", "example.com", false},
		{"suffix attack", "malicious-example.com", "example.com", false},

		// Internal network targets (SSRF vectors)
		{"localhost", "localhost", "example.com", false},
		{"127.0.0.1", "127.0.0.1", "example.com", false},
		{"169.254 link-local", "169.254.169.254", "example.com", false},
		{"internal hostname", "internal.corp", "example.com", false},

		// Edge cases
		{"empty capHost", "", "example.com", false},
		{"empty originalDomain", "example.com", "", false},
		{"both empty", "", "", true}, // "" == "" is true (degenerate case)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateCapabilityHost(tt.capHost, tt.originalDomain)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// DiscoverCapabilities — SSRF domain mismatch rejection (R09-H1)
// ---------------------------------------------------------------------------

func TestDiscoverCapabilities_RejectsSSRFDomainMismatch(t *testing.T) {
	// Server returns capability URLs pointing to a different domain.
	// These should be silently dropped by SSRF validation.
	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"bsvalias": "1.0",
					"capabilities": {
						"pki":          "https://evil.attacker.com/pki/{alias}@{domain.tld}",
						"f12f968c92d6": "https://internal.corp/profile/{alias}@{domain.tld}",
						"a9f510c16bde": "https://169.254.169.254/verify/{alias}@{domain.tld}",
						"2a40af698840": "https://localhost:8080/pay/{alias}@{domain.tld}"
					}
				}`)),
			},
		},
	}

	caps, err := DiscoverCapabilitiesWithClient("example.com", mock)
	require.NoError(t, err, "SSRF mismatch should not cause an error, just skip")
	assert.Empty(t, caps.PKI, "PKI URL on evil.attacker.com should be rejected")
	assert.Empty(t, caps.PublicProfile, "profile URL on internal.corp should be rejected")
	assert.Empty(t, caps.VerifyPubKey, "verify URL on 169.254.169.254 should be rejected")
	assert.Empty(t, caps.PaymentDestination, "payment URL on localhost should be rejected")
}

func TestDiscoverCapabilities_AcceptsSubdomainURLs(t *testing.T) {
	// Server returns capability URLs on subdomains of the original domain.
	// These should be accepted.
	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"bsvalias": "1.0",
					"capabilities": {
						"pki":          "https://api.example.com/pki/{alias}@{domain.tld}",
						"f12f968c92d6": "https://cdn.example.com/profile/{alias}@{domain.tld}",
						"2a40af698840": "https://pay.api.example.com/dest/{alias}@{domain.tld}"
					}
				}`)),
			},
		},
	}

	caps, err := DiscoverCapabilitiesWithClient("example.com", mock)
	require.NoError(t, err)
	assert.NotEmpty(t, caps.PKI, "subdomain api.example.com should be accepted")
	assert.NotEmpty(t, caps.PublicProfile, "subdomain cdn.example.com should be accepted")
	assert.NotEmpty(t, caps.PaymentDestination, "deep subdomain pay.api.example.com should be accepted")
}

func TestDiscoverCapabilities_RejectsSuffixAttack(t *testing.T) {
	// Server returns a capability URL whose domain ends with the original domain
	// but is NOT a subdomain (e.g., "notexample.com" ends with "example.com"
	// but is not a subdomain of it).
	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"bsvalias": "1.0",
					"capabilities": {
						"pki": "https://notexample.com/pki/{alias}@{domain.tld}"
					}
				}`)),
			},
		},
	}

	caps, err := DiscoverCapabilitiesWithClient("example.com", mock)
	require.NoError(t, err)
	assert.Empty(t, caps.PKI, "notexample.com is not a subdomain of example.com")
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
