package paymail

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PaymailCapabilities holds discovered Paymail server capabilities.
type PaymailCapabilities struct {
	PKI           string // URL template for public key infrastructure
	PublicProfile string // URL template for profile info
	VerifyPubKey  string // URL template for key verification
}

// PKIResponse holds the response from a Paymail PKI endpoint.
type PKIResponse struct {
	BSVAlias string `json:"bsvalias"`
	Handle   string `json:"handle"`
	PubKey   string `json:"pubkey"` // Hex-encoded compressed public key
}

// HTTPClient defines the interface for HTTP requests.
// This allows tests to mock HTTP calls.
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// DefaultHTTPClient is the production HTTP client.
var DefaultHTTPClient HTTPClient = http.DefaultClient

// wellKnownResponse represents the JSON structure of .well-known/bsvalias.
type wellKnownResponse struct {
	BSVAlias     string            `json:"bsvalias"`
	Capabilities map[string]interface{} `json:"capabilities"`
}

// Known Paymail capability URNs.
const (
	capPKI           = "pki"
	capPublicProfile = "f12f968c92d6"
	capVerifyPubKey  = "a9f510c16bde"

	// Full URN prefixes used by some servers.
	capPKIFull           = "6745385c3fc0"
	capPublicProfileFull = "f12f968c92d6"
)

// DiscoverCapabilities fetches .well-known/bsvalias from a domain
// and returns the Paymail server capabilities.
func DiscoverCapabilities(domain string) (*PaymailCapabilities, error) {
	return DiscoverCapabilitiesWithClient(domain, DefaultHTTPClient)
}

// DiscoverCapabilitiesWithClient fetches capabilities using the provided HTTP client.
func DiscoverCapabilitiesWithClient(domain string, client HTTPClient) (*PaymailCapabilities, error) {
	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain", ErrPaymailDiscovery)
	}

	url := "https://" + domain + "/.well-known/bsvalias"
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrPaymailDiscovery, url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned status %d", ErrPaymailDiscovery, url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", ErrPaymailDiscovery, err)
	}

	var wk wellKnownResponse
	if err := json.Unmarshal(body, &wk); err != nil {
		return nil, fmt.Errorf("%w: parsing JSON: %v", ErrPaymailDiscovery, err)
	}

	caps := &PaymailCapabilities{}

	// Extract capability URLs from the capabilities map
	for key, val := range wk.Capabilities {
		urlStr, ok := val.(string)
		if !ok {
			continue
		}
		switch {
		case key == capPKI || key == capPKIFull || strings.Contains(key, "pki"):
			caps.PKI = urlStr
		case key == capPublicProfile || key == capPublicProfileFull || strings.Contains(key, "public-profile"):
			caps.PublicProfile = urlStr
		case key == capVerifyPubKey || strings.Contains(key, "verify-pubkey"):
			caps.VerifyPubKey = urlStr
		}
	}

	return caps, nil
}

// ResolvePKI resolves a Paymail alias to its public key using the PKI capability.
// Returns the P_root compressed public key bytes for the alias's vault.
func ResolvePKI(alias, domain string) ([]byte, error) {
	return ResolvePKIWithClient(alias, domain, DefaultHTTPClient)
}

// ResolvePKIWithClient resolves PKI using the provided HTTP client.
func ResolvePKIWithClient(alias, domain string, client HTTPClient) ([]byte, error) {
	if alias == "" || domain == "" {
		return nil, fmt.Errorf("%w: alias and domain are required", ErrPKIResolution)
	}

	// First discover capabilities
	caps, err := DiscoverCapabilitiesWithClient(domain, client)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPKIResolution, err)
	}

	if caps.PKI == "" {
		return nil, fmt.Errorf("%w: no PKI capability found for %s", ErrPKIResolution, domain)
	}

	// Build PKI URL from template
	pkiURL := strings.ReplaceAll(caps.PKI, "{alias}", alias)
	pkiURL = strings.ReplaceAll(pkiURL, "{domain.tld}", domain)

	resp, err := client.Get(pkiURL)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrPKIResolution, pkiURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned status %d", ErrPKIResolution, pkiURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", ErrPKIResolution, err)
	}

	var pki PKIResponse
	if err := json.Unmarshal(body, &pki); err != nil {
		return nil, fmt.Errorf("%w: parsing PKI response: %v", ErrPKIResolution, err)
	}

	if pki.PubKey == "" {
		return nil, fmt.Errorf("%w: empty public key in response", ErrPKIResolution)
	}

	pubKeyBytes, err := hex.DecodeString(pki.PubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex public key: %v", ErrInvalidPubKey, err)
	}

	if err := validateCompressedPubKey(pubKeyBytes); err != nil {
		return nil, err
	}

	return pubKeyBytes, nil
}

// ResolveURI performs full URI resolution:
//  1. Parse URI
//  2. Resolve public key (via Paymail PKI, DNSLink TXT, or direct from URI)
//  3. Resolve endpoints (via SRV records)
//
// Returns (pubkey, endpoints, error).
func ResolveURI(uri string) ([]byte, []string, error) {
	return ResolveURIWith(uri, DefaultHTTPClient, DefaultDNSResolver)
}

// ResolveURIWith performs full URI resolution with provided client and resolver.
func ResolveURIWith(uri string, client HTTPClient, resolver DNSResolver) ([]byte, []string, error) {
	parsed, err := ParseURI(uri)
	if err != nil {
		return nil, nil, err
	}

	var pubKey []byte
	var endpoints []string

	switch parsed.Type {
	case AddressPaymail:
		// Resolve public key via Paymail PKI
		pubKey, err = ResolvePKIWithClient(parsed.Alias, parsed.Domain, client)
		if err != nil {
			return nil, nil, err
		}
		// Resolve endpoints via Paymail SRV
		endpoints, err = ResolveEndpointsWithResolver(parsed.Domain, SRVPaymail, resolver)
		if err != nil {
			// Endpoints are optional; fall back to domain:443
			endpoints = []string{parsed.Domain + ":443"}
		}

	case AddressDNSLink:
		// Resolve public key via DNS TXT record
		pubKey, err = ResolveDNSLinkPubKeyWithResolver(parsed.Domain, resolver)
		if err != nil {
			return nil, nil, err
		}
		// Resolve endpoints via BitFS SRV
		endpoints, err = ResolveEndpointsWithResolver(parsed.Domain, SRVBitFS, resolver)
		if err != nil {
			// Endpoints are optional; fall back to domain:443
			endpoints = []string{parsed.Domain + ":443"}
		}

	case AddressPubKey:
		// Public key is directly in the URI
		pubKey = parsed.PubKey
		if err := validateCompressedPubKey(pubKey); err != nil {
			return nil, nil, err
		}
		// No endpoints for direct pubkey addressing
		endpoints = nil
	}

	return pubKey, endpoints, nil
}
