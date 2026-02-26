package paymail

import (
	"bytes"
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

// testPubKeyHex is a valid compressed secp256k1 public key (33 bytes, prefix 02).
const testPubKeyHex = "02a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

// --- ParseURI Tests ---

func TestParseURI_Paymail(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		alias  string
		domain string
		path   string
	}{
		{
			name:   "basic paymail",
			uri:    "bitfs://alice@example.com/docs/paper.pdf",
			alias:  "alice",
			domain: "example.com",
			path:   "/docs/paper.pdf",
		},
		{
			name:   "paymail no path",
			uri:    "bitfs://bob@mail.example.com",
			alias:  "bob",
			domain: "mail.example.com",
			path:   "",
		},
		{
			name:   "paymail root path",
			uri:    "bitfs://user@domain.org/",
			alias:  "user",
			domain: "domain.org",
			path:   "/",
		},
		{
			name:   "paymail with subdomain",
			uri:    "bitfs://satoshi@paymail.bsv.com/hello",
			alias:  "satoshi",
			domain: "paymail.bsv.com",
			path:   "/hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseURI(tt.uri)
			require.NoError(t, err)
			assert.Equal(t, AddressPaymail, parsed.Type)
			assert.Equal(t, tt.alias, parsed.Alias)
			assert.Equal(t, tt.domain, parsed.Domain)
			assert.Equal(t, tt.path, parsed.Path)
			assert.Equal(t, tt.uri, parsed.RawURI)
			assert.Nil(t, parsed.PubKey)
		})
	}
}

func TestParseURI_DNSLink(t *testing.T) {
	tests := []struct {
		name   string
		uri    string
		domain string
		path   string
	}{
		{
			name:   "basic domain",
			uri:    "bitfs://example.com/docs/paper.pdf",
			domain: "example.com",
			path:   "/docs/paper.pdf",
		},
		{
			name:   "domain no path",
			uri:    "bitfs://example.com",
			domain: "example.com",
			path:   "",
		},
		{
			name:   "domain with subdomain",
			uri:    "bitfs://cdn.example.com/data",
			domain: "cdn.example.com",
			path:   "/data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseURI(tt.uri)
			require.NoError(t, err)
			assert.Equal(t, AddressDNSLink, parsed.Type)
			assert.Equal(t, tt.domain, parsed.Domain)
			assert.Equal(t, tt.path, parsed.Path)
			assert.Empty(t, parsed.Alias)
			assert.Nil(t, parsed.PubKey)
		})
	}
}

func TestParseURI_PubKey(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		path string
	}{
		{
			name: "02 prefix pubkey with path",
			uri:  "bitfs://" + testPubKeyHex + "/docs/paper.pdf",
			path: "/docs/paper.pdf",
		},
		{
			name: "02 prefix pubkey no path",
			uri:  "bitfs://" + testPubKeyHex,
			path: "",
		},
		{
			name: "03 prefix pubkey",
			uri:  "bitfs://03a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2/file.txt",
			path: "/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseURI(tt.uri)
			require.NoError(t, err)
			assert.Equal(t, AddressPubKey, parsed.Type)
			assert.NotNil(t, parsed.PubKey)
			assert.Len(t, parsed.PubKey, 33)
			assert.Equal(t, tt.path, parsed.Path)
			assert.Empty(t, parsed.Alias)
			assert.Empty(t, parsed.Domain)
		})
	}
}

func TestParseURI_Errors(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"empty string", ""},
		{"wrong scheme", "https://example.com"},
		{"http scheme", "http://example.com"},
		{"ipfs scheme", "ipfs://something"},
		{"no authority", "bitfs://"},
		{"empty alias", "bitfs://@example.com/path"},
		{"empty domain after @", "bitfs://alice@/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseURI(tt.uri)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidURI)
		})
	}
}

func TestParseURI_AddressTypeString(t *testing.T) {
	assert.Equal(t, "Paymail", AddressPaymail.String())
	assert.Equal(t, "DNSLink", AddressDNSLink.String())
	assert.Equal(t, "PubKey", AddressPubKey.String())
	assert.Equal(t, "Unknown", AddressType(99).String())
}

// --- Mock infrastructure ---

// mockDNSResolver provides mock DNS lookups for testing.
type mockDNSResolver struct {
	srvRecords map[string][]*net.SRV // key: "service_proto_name"
	txtRecords map[string][]string   // key: name
	srvErr     error
	txtErr     error
}

func newMockDNSResolver() *mockDNSResolver {
	return &mockDNSResolver{
		srvRecords: make(map[string][]*net.SRV),
		txtRecords: make(map[string][]string),
	}
}

func (m *mockDNSResolver) LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	if m.srvErr != nil {
		return "", nil, m.srvErr
	}
	key := service + "_" + proto + "_" + name
	records, ok := m.srvRecords[key]
	if !ok {
		return "", nil, fmt.Errorf("no SRV records for _%s._%s.%s", service, proto, name)
	}
	return "", records, nil
}

func (m *mockDNSResolver) LookupTXT(name string) ([]string, error) {
	if m.txtErr != nil {
		return nil, m.txtErr
	}
	records, ok := m.txtRecords[name]
	if !ok {
		return nil, fmt.Errorf("no TXT records for %s", name)
	}
	return records, nil
}

func (m *mockDNSResolver) addSRV(service, proto, name string, records ...*net.SRV) {
	key := service + "_" + proto + "_" + name
	m.srvRecords[key] = records
}

func (m *mockDNSResolver) addTXT(name string, records ...string) {
	m.txtRecords[name] = records
}

// mockHTTPClient wraps an httptest.Server to implement HTTPClient.
type mockHTTPClient struct {
	server *httptest.Server
}

func (m *mockHTTPClient) Get(url string) (*http.Response, error) {
	// Rewrite the URL to point to the test server
	// Replace https://domain with the test server URL
	idx := strings.Index(url, "/.")
	if idx == -1 {
		idx = strings.Index(url, "/api/")
		if idx == -1 {
			// Try to find the path after the domain
			parts := strings.SplitN(url, "//", 2)
			if len(parts) == 2 {
				slashIdx := strings.Index(parts[1], "/")
				if slashIdx >= 0 {
					url = m.server.URL + parts[1][slashIdx:]
				} else {
					url = m.server.URL + "/"
				}
			}
		} else {
			url = m.server.URL + url[idx:]
		}
	} else {
		url = m.server.URL + url[idx:]
	}
	return http.Get(url)
}

// --- DNS Resolution Tests ---

func TestResolveEndpoints_Success(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bsvalias", "tcp", "example.com",
		&net.SRV{Target: "cdn1.example.com.", Port: 443, Priority: 10, Weight: 60},
		&net.SRV{Target: "cdn2.example.com.", Port: 443, Priority: 20, Weight: 40},
	)

	endpoints, err := ResolveEndpointsWithResolver("example.com", SRVPaymail, resolver)
	require.NoError(t, err)
	require.Len(t, endpoints, 2)
	assert.Equal(t, "cdn1.example.com:443", endpoints[0])
	assert.Equal(t, "cdn2.example.com:443", endpoints[1])
}

func TestResolveEndpoints_PrioritySorting(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bitfs", "tcp", "example.com",
		&net.SRV{Target: "low.example.com.", Port: 443, Priority: 30, Weight: 10},
		&net.SRV{Target: "high.example.com.", Port: 8443, Priority: 5, Weight: 50},
		&net.SRV{Target: "mid.example.com.", Port: 443, Priority: 10, Weight: 30},
	)

	endpoints, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	require.NoError(t, err)
	require.Len(t, endpoints, 3)
	assert.Equal(t, "high.example.com:8443", endpoints[0])
	assert.Equal(t, "mid.example.com:443", endpoints[1])
	assert.Equal(t, "low.example.com:443", endpoints[2])
}

func TestResolveEndpoints_WeightSorting(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bitfs", "tcp", "example.com",
		&net.SRV{Target: "light.example.com.", Port: 443, Priority: 10, Weight: 10},
		&net.SRV{Target: "heavy.example.com.", Port: 443, Priority: 10, Weight: 90},
	)

	endpoints, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	require.NoError(t, err)
	require.Len(t, endpoints, 2)
	// Higher weight should come first within same priority
	assert.Equal(t, "heavy.example.com:443", endpoints[0])
	assert.Equal(t, "light.example.com:443", endpoints[1])
}

func TestResolveEndpoints_EmptyDomain(t *testing.T) {
	resolver := newMockDNSResolver()
	_, err := ResolveEndpointsWithResolver("", SRVBitFS, resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveEndpoints_EmptyRecordType(t *testing.T) {
	resolver := newMockDNSResolver()
	_, err := ResolveEndpointsWithResolver("example.com", "", resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveEndpoints_LookupError(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.srvErr = fmt.Errorf("network error")
	_, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveEndpoints_NoRecords(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bitfs", "tcp", "example.com") // empty list
	_, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	assert.ErrorIs(t, err, ErrNoEndpoints)
}

func TestResolveDNSLinkPubKey_Success(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "bitfs="+testPubKeyHex)

	pubKey, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.Equal(t, byte(0x02), pubKey[0])
}

func TestResolveDNSLinkPubKey_EmptyDomain(t *testing.T) {
	resolver := newMockDNSResolver()
	_, err := ResolveDNSLinkPubKeyWithResolver("", resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveDNSLinkPubKey_LookupError(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.txtErr = fmt.Errorf("DNS timeout")
	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveDNSLinkPubKey_NoRecords(t *testing.T) {
	resolver := newMockDNSResolver()
	// Lookup returns error for unknown name in our mock
	_, err := ResolveDNSLinkPubKeyWithResolver("unknown.com", resolver)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveDNSLinkPubKey_InvalidHex(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "bitfs=not-valid-hex!")
	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

func TestResolveDNSLinkPubKey_WrongLength(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "bitfs=02a1b2c3") // too short
	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

func TestResolveDNSLinkPubKey_WrongPrefix(t *testing.T) {
	resolver := newMockDNSResolver()
	// 33 bytes but starts with 04 (uncompressed prefix)
	badKey := "04" + strings.Repeat("ab", 32)
	resolver.addTXT("_bitfs.example.com", "bitfs="+badKey)
	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

// --- Paymail Discovery & PKI Tests ---

func setupPaymailServer(t *testing.T, pubKeyHex string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/bsvalias", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki":          "{server}/api/v1/bsvalias/pki/{alias}@{domain.tld}",
				"f12f968c92d6": "{server}/api/v1/bsvalias/public-profile/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/v1/bsvalias/pki/", func(w http.ResponseWriter, r *http.Request) {
		resp := PKIResponse{
			BSVAlias: "1.0",
			Handle:   "alice@example.com",
			PubKey:   pubKeyHex,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func TestDiscoverCapabilities_Success(t *testing.T) {
	server := setupPaymailServer(t, testPubKeyHex)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	caps, err := DiscoverCapabilitiesWithClient("example.com", client)
	require.NoError(t, err)
	assert.NotEmpty(t, caps.PKI)
	assert.NotEmpty(t, caps.PublicProfile)
}

func TestDiscoverCapabilities_EmptyDomain(t *testing.T) {
	_, err := DiscoverCapabilitiesWithClient("", DefaultHTTPClient)
	assert.ErrorIs(t, err, ErrPaymailDiscovery)
}

func TestDiscoverCapabilities_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := DiscoverCapabilitiesWithClient("example.com", client)
	assert.ErrorIs(t, err, ErrPaymailDiscovery)
}

func TestDiscoverCapabilities_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := DiscoverCapabilitiesWithClient("example.com", client)
	assert.ErrorIs(t, err, ErrPaymailDiscovery)
}

func TestResolvePKI_Success(t *testing.T) {
	server := setupPaymailServer(t, testPubKeyHex)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	pubKey, err := ResolvePKIWithClient("alice", "example.com", client)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)

	expected, _ := hex.DecodeString(testPubKeyHex)
	assert.Equal(t, expected, pubKey)
}

func TestResolvePKI_EmptyAlias(t *testing.T) {
	_, err := ResolvePKIWithClient("", "example.com", DefaultHTTPClient)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

func TestResolvePKI_EmptyDomain(t *testing.T) {
	_, err := ResolvePKIWithClient("alice", "", DefaultHTTPClient)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

func TestResolvePKI_EmptyPubKeyResponse(t *testing.T) {
	server := setupPaymailServer(t, "")
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

func TestResolvePKI_InvalidPubKeyHex(t *testing.T) {
	server := setupPaymailServer(t, "zzzz")
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

func TestResolvePKI_NoPKICapability(t *testing.T) {
	// Server with no PKI capability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias":     "1.0",
			"capabilities": map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

// --- ResolveURI Tests ---

func TestResolveURI_Paymail(t *testing.T) {
	server := setupPaymailServer(t, testPubKeyHex)
	defer server.Close()

	resolver := newMockDNSResolver()
	resolver.addSRV("bsvalias", "tcp", "example.com",
		&net.SRV{Target: "cdn.example.com.", Port: 443, Priority: 10, Weight: 60},
	)

	client := &mockHTTPClient{server: server}
	pubKey, endpoints, err := ResolveURIWith("bitfs://alice@example.com/docs", client, resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.NotEmpty(t, endpoints)
	assert.Equal(t, "cdn.example.com:443", endpoints[0])
}

func TestResolveURI_Paymail_NoSRV_Fallback(t *testing.T) {
	server := setupPaymailServer(t, testPubKeyHex)
	defer server.Close()

	resolver := newMockDNSResolver()
	// No SRV records added -- should fall back to domain:443

	client := &mockHTTPClient{server: server}
	pubKey, endpoints, err := ResolveURIWith("bitfs://alice@example.com/docs", client, resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.Equal(t, []string{"example.com:443"}, endpoints)
}

func TestResolveURI_DNSLink(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "bitfs="+testPubKeyHex)
	resolver.addSRV("bitfs", "tcp", "example.com",
		&net.SRV{Target: "node1.example.com.", Port: 443, Priority: 10, Weight: 60},
	)

	pubKey, endpoints, err := ResolveURIWith("bitfs://example.com/docs", DefaultHTTPClient, resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.NotEmpty(t, endpoints)
}

func TestResolveURI_PubKey(t *testing.T) {
	uri := "bitfs://" + testPubKeyHex + "/docs"
	pubKey, endpoints, err := ResolveURIWith(uri, DefaultHTTPClient, newMockDNSResolver())
	require.NoError(t, err)

	expected, _ := hex.DecodeString(testPubKeyHex)
	assert.Equal(t, expected, pubKey)
	assert.Nil(t, endpoints) // No endpoints for direct pubkey
}

func TestResolveURI_InvalidURI(t *testing.T) {
	_, _, err := ResolveURIWith("invalid", DefaultHTTPClient, newMockDNSResolver())
	assert.ErrorIs(t, err, ErrInvalidURI)
}

// --- Validation Tests ---

func TestValidateCompressedPubKey(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 02 prefix",
			key:     mustDecodeHex(testPubKeyHex),
			wantErr: false,
		},
		{
			name:    "valid 03 prefix",
			key:     mustDecodeHex("03" + strings.Repeat("ab", 32)),
			wantErr: false,
		},
		{
			name:    "too short",
			key:     []byte{0x02, 0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "too long",
			key:     make([]byte, 65),
			wantErr: true,
		},
		{
			name:    "wrong prefix 04",
			key:     append([]byte{0x04}, make([]byte, 32)...),
			wantErr: true,
		},
		{
			name:    "wrong prefix 00",
			key:     append([]byte{0x00}, make([]byte, 32)...),
			wantErr: true,
		},
		{
			name:    "nil",
			key:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCompressedPubKey(tt.key)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidPubKey)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsPubKeyHex(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"valid 02", testPubKeyHex, true},
		{"valid 03", "03" + strings.Repeat("ab", 32), true},
		{"too short", "02abc", false},
		{"too long", "02" + strings.Repeat("ab", 33), false},
		{"wrong prefix", "04" + strings.Repeat("ab", 32), false},
		{"not hex", "02" + strings.Repeat("zz", 32), false},
		{"empty", "", false},
		{"domain-like", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPubKeyHex(tt.s))
		})
	}
}

// =============================================================================
// Supplementary tests: untested code paths
// =============================================================================

// --- URI Edge Cases ---

func TestParseURI_CaseSensitiveScheme(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"all caps", "BITFS://example.com"},
		{"mixed case", "BitFs://example.com"},
		{"uppercase B", "Bitfs://example.com"},
		{"uppercase trailing", "bitFS://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseURI(tt.uri)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidURI)
		})
	}
}

func TestParseURI_WhitespaceInURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"leading space", " bitfs://example.com"},
		{"leading tab", "\tbitfs://example.com"},
		{"leading newline", "\nbitfs://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseURI(tt.uri)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidURI)
		})
	}
}

func TestParseURI_PathWithQueryAndFragment(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		wantPath string
	}{
		{
			name:     "path with query string",
			uri:      "bitfs://alice@example.com/docs/file.pdf?version=2",
			wantPath: "/docs/file.pdf?version=2",
		},
		{
			name:     "path with fragment",
			uri:      "bitfs://alice@example.com/docs/file.pdf#page=5",
			wantPath: "/docs/file.pdf#page=5",
		},
		{
			name:     "path with query and fragment",
			uri:      "bitfs://alice@example.com/docs/file.pdf?v=2#page=5",
			wantPath: "/docs/file.pdf?v=2#page=5",
		},
		{
			name:     "DNSLink path with query",
			uri:      "bitfs://example.com/file.txt?download=true",
			wantPath: "/file.txt?download=true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseURI(tt.uri)
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath, parsed.Path)
		})
	}
}

func TestParseURI_PubKeyLooksLikeDNSLink(t *testing.T) {
	// 64 hex chars (32 bytes) with 02 prefix -- NOT 66 chars, so not a pubkey.
	// isPubKeyHex requires exactly 66 hex chars; 64 chars should fall through to DNSLink.
	shortHex := "02" + strings.Repeat("ab", 31) // 2 + 62 = 64 hex chars (32 bytes)

	parsed, err := ParseURI("bitfs://" + shortHex + "/path")
	require.NoError(t, err)
	assert.Equal(t, AddressDNSLink, parsed.Type, "64 hex chars (not 66) should be classified as DNSLink")
	assert.Equal(t, shortHex, parsed.Domain)
	assert.Equal(t, "/path", parsed.Path)
	assert.Nil(t, parsed.PubKey)
}

// --- DNS Resolution Edge Cases ---

func TestResolveDNSLinkPubKey_SkipsEmptyTXTRecords(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "", "", "bitfs="+testPubKeyHex)

	pubKey, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.Equal(t, byte(0x02), pubKey[0])
}

func TestResolveDNSLinkPubKey_AllEmptyTXTRecords(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "", "", "")

	_, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestResolveDNSLinkPubKey_WhitespaceTrimming(t *testing.T) {
	resolver := newMockDNSResolver()
	padded := "  bitfs=" + testPubKeyHex + "  "
	resolver.addTXT("_bitfs.example.com", padded)

	pubKey, err := ResolveDNSLinkPubKeyWithResolver("example.com", resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)

	expected, _ := hex.DecodeString(testPubKeyHex)
	assert.Equal(t, expected, pubKey)
}

func TestResolveEndpoints_SingleRecord(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addSRV("bitfs", "tcp", "example.com",
		&net.SRV{Target: "solo.example.com.", Port: 8080, Priority: 10, Weight: 100},
	)

	endpoints, err := ResolveEndpointsWithResolver("example.com", SRVBitFS, resolver)
	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	assert.Equal(t, "solo.example.com:8080", endpoints[0])
}

// --- Paymail Discovery Edge Cases ---

func TestDiscoverCapabilities_NonStringCapabilityValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki":          12345,                // non-string: should be skipped
				"f12f968c92d6": true,                 // non-string: should be skipped
				"a9f510c16bde": []string{"not", "a"}, // non-string: should be skipped
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &mockHTTPClient{server: server}
	caps, err := DiscoverCapabilitiesWithClient("example.com", client)
	require.NoError(t, err, "non-string capability values should be skipped gracefully")
	assert.Empty(t, caps.PKI, "integer PKI value should be skipped")
	assert.Empty(t, caps.PublicProfile, "boolean public profile value should be skipped")
	assert.Empty(t, caps.VerifyPubKey, "array verify-pubkey value should be skipped")
}

func TestDiscoverCapabilities_ConnectionRefused(t *testing.T) {
	// Create a client whose Get always returns an error
	client := &errorHTTPClient{err: fmt.Errorf("connection refused")}

	_, err := DiscoverCapabilitiesWithClient("example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPaymailDiscovery)
}

// --- ResolvePKI Edge Cases ---

func TestResolvePKI_PKIEndpointNon200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/bsvalias", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki": "{server}/api/v1/bsvalias/pki/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v1/bsvalias/pki/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

func TestResolvePKI_PKIEndpointInvalidJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/bsvalias", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"bsvalias": "1.0",
			"capabilities": map[string]interface{}{
				"pki": "{server}/api/v1/bsvalias/pki/{alias}@{domain.tld}",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v1/bsvalias/pki/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{garbled json!!!"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &mockHTTPClient{server: server}
	_, err := ResolvePKIWithClient("alice", "example.com", client)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKIResolution)
}

// --- ResolveURI Edge Cases ---

func TestResolveURI_DNSLink_NoSRV_Fallback(t *testing.T) {
	resolver := newMockDNSResolver()
	resolver.addTXT("_bitfs.example.com", "bitfs="+testPubKeyHex)
	// No SRV records added -- should fall back to domain:443

	pubKey, endpoints, err := ResolveURIWith("bitfs://example.com/docs", DefaultHTTPClient, resolver)
	require.NoError(t, err)
	assert.Len(t, pubKey, 33)
	assert.Equal(t, []string{"example.com:443"}, endpoints,
		"DNSLink with no SRV records should fall back to domain:443")
}

// --- Helper: error HTTP client ---

// errorHTTPClient is an HTTPClient that always returns an error.
type errorHTTPClient struct {
	err error
}

func (e *errorHTTPClient) Get(url string) (*http.Response, error) {
	return nil, e.err
}

// responseMockHTTPClient returns pre-built responses keyed by URL.
type responseMockHTTPClient struct {
	responses  map[string]*http.Response
	captureURL *string // if non-nil, captures the last requested URL
}

func (m *responseMockHTTPClient) Get(url string) (*http.Response, error) {
	if m.captureURL != nil {
		*m.captureURL = url
	}
	resp, ok := m.responses[url]
	if !ok {
		return nil, fmt.Errorf("no mock response for %s", url)
	}
	return resp, nil
}

func TestDiscoverCapabilities_OversizedResponse(t *testing.T) {
	// Server returns a response larger than MaxPaymailResponseSize.
	bigBody := make([]byte, MaxPaymailResponseSize+1)
	for i := range bigBody {
		bigBody[i] = 'x'
	}

	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(bigBody)),
			},
		},
	}

	_, err := DiscoverCapabilitiesWithClient("example.com", mock)
	// Should fail with JSON parse error since body is truncated garbage
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing JSON")
}

func TestDiscoverCapabilities_RejectsNonHTTPS(t *testing.T) {
	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"bsvalias": "1.0",
					"capabilities": {
						"pki": "http://evil.com/pki/{alias}@{domain.tld}"
					}
				}`)),
			},
		},
	}

	caps, err := DiscoverCapabilitiesWithClient("example.com", mock)
	require.NoError(t, err)
	assert.Empty(t, caps.PKI, "non-HTTPS PKI URL should be rejected")
}

func TestResolvePKI_EscapesTemplateVars(t *testing.T) {
	var capturedURL string
	mock := &responseMockHTTPClient{
		responses: map[string]*http.Response{
			"https://example.com/.well-known/bsvalias": {
				StatusCode: 200,
				Body: io.NopCloser(strings.NewReader(`{
					"bsvalias": "1.0",
					"capabilities": {
						"pki": "https://example.com/pki/{alias}@{domain.tld}"
					}
				}`)),
			},
		},
		captureURL: &capturedURL,
	}

	// Alias with path-traversal characters
	_, _ = ResolvePKIWithClient("test/../admin", "example.com", mock)

	// The ".." must be percent-encoded in the URL
	assert.NotContains(t, capturedURL, "test/../admin")
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
