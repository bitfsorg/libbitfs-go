package paymail

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// DNSResolver defines the interface for DNS lookups.
// This allows tests to mock DNS resolution.
type DNSResolver interface {
	// LookupSRV looks up SRV records for the given service, proto, and name.
	LookupSRV(service, proto, name string) (string, []*net.SRV, error)

	// LookupTXT looks up TXT records for the given name.
	LookupTXT(name string) ([]string, error)
}

// defaultDNSResolver wraps the standard net package DNS functions.
type defaultDNSResolver struct{}

func (d *defaultDNSResolver) LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	return net.LookupSRV(service, proto, name)
}

func (d *defaultDNSResolver) LookupTXT(name string) ([]string, error) {
	return net.LookupTXT(name)
}

// DefaultDNSResolver is the production DNS resolver using the net package.
var DefaultDNSResolver DNSResolver = &defaultDNSResolver{}

// SRV record types for BitFS.
const (
	SRVPaymail = "bsvalias" // _bsvalias._tcp.{domain}
	SRVBitFS   = "bitfs"    // _bitfs._tcp.{domain}
)

// ResolveEndpoints resolves SRV records for a domain.
// recordType should be SRVPaymail ("bsvalias") or SRVBitFS ("bitfs").
// Returns endpoint addresses (host:port) sorted by priority then weight.
func ResolveEndpoints(domain string, recordType string) ([]string, error) {
	return ResolveEndpointsWithResolver(domain, recordType, DefaultDNSResolver)
}

// ResolveEndpointsWithResolver resolves SRV records using the provided DNS resolver.
func ResolveEndpointsWithResolver(domain string, recordType string, resolver DNSResolver) ([]string, error) {
	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain", ErrDNSLookupFailed)
	}
	if recordType == "" {
		return nil, fmt.Errorf("%w: empty record type", ErrDNSLookupFailed)
	}

	_, addrs, err := resolver.LookupSRV(recordType, "tcp", domain)
	if err != nil {
		return nil, fmt.Errorf("%w: SRV lookup for _%s._tcp.%s: %w", ErrDNSLookupFailed, recordType, domain, err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no SRV records for _%s._tcp.%s", ErrNoEndpoints, recordType, domain)
	}

	// Sort by priority (ascending), then by weight (descending)
	sort.Slice(addrs, func(i, j int) bool {
		if addrs[i].Priority != addrs[j].Priority {
			return addrs[i].Priority < addrs[j].Priority
		}
		return addrs[i].Weight > addrs[j].Weight
	})

	endpoints := make([]string, len(addrs))
	for i, srv := range addrs {
		host := strings.TrimSuffix(srv.Target, ".")
		endpoints[i] = fmt.Sprintf("%s:%d", host, srv.Port)
	}

	return endpoints, nil
}

// ResolveDNSLinkPubKey resolves _bitfs.{domain} TXT record with bitfs= prefix.
// Returns the P_node compressed public key bytes.
func ResolveDNSLinkPubKey(domain string) ([]byte, error) {
	return ResolveDNSLinkPubKeyWithResolver(domain, DefaultDNSResolver)
}

// ResolveDNSLinkPubKeyWithResolver resolves the DNSLink public key using the provided DNS resolver.
// It looks up _bitfs.{domain} TXT records and extracts the pubkey from records
// with the "bitfs=" prefix (e.g., "bitfs=02a1b2c3...").
func ResolveDNSLinkPubKeyWithResolver(domain string, resolver DNSResolver) ([]byte, error) {
	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain", ErrDNSLookupFailed)
	}

	name := "_bitfs." + domain
	txts, err := resolver.LookupTXT(name)
	if err != nil {
		return nil, fmt.Errorf("%w: TXT lookup for %s: %w", ErrDNSLookupFailed, name, err)
	}

	if len(txts) == 0 {
		return nil, fmt.Errorf("%w: no TXT records for %s", ErrDNSLookupFailed, name)
	}

	// Find the first TXT record with the "bitfs=" prefix.
	const prefix = "bitfs="
	var pubKeyHex string
	for _, txt := range txts {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, prefix) {
			pubKeyHex = strings.TrimSpace(strings.TrimPrefix(txt, prefix))
			break
		}
	}

	if pubKeyHex == "" {
		return nil, fmt.Errorf("%w: no bitfs= TXT record for %s", ErrDNSLookupFailed, name)
	}

	if len(pubKeyHex) != 66 {
		return nil, fmt.Errorf("%w: expected 66 hex chars, got %d", ErrInvalidPubKey, len(pubKeyHex))
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex in TXT record: %w", ErrInvalidPubKey, err)
	}

	if err := validateCompressedPubKey(pubKeyBytes); err != nil {
		return nil, err
	}

	return pubKeyBytes, nil
}
