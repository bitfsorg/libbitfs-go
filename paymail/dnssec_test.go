package paymail

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit tests (always run) ---

func TestDNSSECResolver_ImplementsDNSResolver(t *testing.T) {
	var _ DNSResolver = (*DNSSECResolver)(nil)
}

func TestNewDNSSECResolver_Defaults(t *testing.T) {
	r := NewDNSSECResolver("")
	assert.Equal(t, "8.8.8.8:53", r.Upstream)
}

func TestNewDNSSECResolver_Custom(t *testing.T) {
	r := NewDNSSECResolver("1.1.1.1:53")
	assert.Equal(t, "1.1.1.1:53", r.Upstream)
}

// --- Integration tests (skip in short mode) ---

func TestDNSSECResolver_LookupTXT_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewDNSSECResolver("")

	// Query a domain known to have DNSSEC (e.g., cloudflare.com).
	txts, err := r.LookupTXT("cloudflare.com")
	if err != nil {
		// The AD flag may not be set depending on the network/resolver.
		if errors.Is(err, ErrDNSSECValidationFailed) {
			t.Skipf("skipping: upstream resolver did not set AD flag: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	require.NotEmpty(t, txts)
	t.Logf("TXT records for cloudflare.com: %v", txts)
}

func TestDNSSECResolver_LookupTXT_NonExistentDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewDNSSECResolver("")

	_, err := r.LookupTXT("this-domain-definitely-does-not-exist-12345.example")
	require.Error(t, err)
	t.Logf("error for non-existent domain: %v", err)
}

func TestDNSSECResolver_LookupSRV_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	r := NewDNSSECResolver("")

	// Try a well-known SRV record. _imaps._tcp.gmail.com is commonly available.
	_, srvs, err := r.LookupSRV("imaps", "tcp", "gmail.com")
	if err != nil {
		// AD flag may not be set; skip gracefully.
		if errors.Is(err, ErrDNSSECValidationFailed) {
			t.Skipf("skipping: upstream resolver did not set AD flag: %v", err)
		}
		// Some networks block non-standard SRV lookups; skip gracefully.
		t.Skipf("skipping: SRV lookup failed (may be network-dependent): %v", err)
	}

	require.NotEmpty(t, srvs)
	for _, srv := range srvs {
		assert.IsType(t, &net.SRV{}, srv)
		assert.NotEmpty(t, srv.Target)
		t.Logf("SRV: %s:%d (priority=%d, weight=%d)", srv.Target, srv.Port, srv.Priority, srv.Weight)
	}
}
