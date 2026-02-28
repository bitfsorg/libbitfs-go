package paymail

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultUpstream is the default recursive resolver for DNSSEC queries.
	defaultUpstream = "8.8.8.8:53"

	// dnssecTimeout is the timeout for DNSSEC queries.
	dnssecTimeout = 10 * time.Second

	// edns0BufSize is the EDNS0 UDP buffer size.
	edns0BufSize = 4096
)

// DNSSECResolver implements DNSResolver with DNSSEC validation.
// It relies on the upstream recursive resolver to perform DNSSEC validation
// and checks the AD (Authenticated Data) flag in responses.
type DNSSECResolver struct {
	// Upstream is the recursive resolver address (e.g., "8.8.8.8:53").
	Upstream string
}

// NewDNSSECResolver creates a new DNSSECResolver.
// If upstream is empty, it defaults to "8.8.8.8:53".
func NewDNSSECResolver(upstream string) *DNSSECResolver {
	if upstream == "" {
		upstream = defaultUpstream
	}
	return &DNSSECResolver{Upstream: upstream}
}

// queryWithDNSSEC sends a DNS query with the DNSSEC OK flag set and validates
// that the response has the AD (Authenticated Data) flag.
func (r *DNSSECResolver) queryWithDNSSEC(name string, qtype uint16) (*dns.Msg, error) {
	// Ensure FQDN.
	fqdn := dns.Fqdn(name)

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(edns0BufSize, true) // DO (DNSSEC OK) flag

	client := &dns.Client{Timeout: dnssecTimeout}
	resp, _, err := client.Exchange(msg, r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("%w: query %s %s: %w",
			ErrDNSLookupFailed, name, dns.TypeToString[qtype], err)
	}

	// Allow RcodeSuccess and RcodeNameError (NXDOMAIN).
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%w: query %s %s: rcode %s",
			ErrDNSLookupFailed, name, dns.TypeToString[qtype],
			dns.RcodeToString[resp.Rcode])
	}

	// Require the AD flag — the recursive resolver validated DNSSEC.
	if !resp.AuthenticatedData {
		return nil, fmt.Errorf("%w: AD flag not set for %s %s",
			ErrDNSSECValidationFailed, name, dns.TypeToString[qtype])
	}

	return resp, nil
}

// LookupSRV looks up SRV records with DNSSEC validation.
// The first return value (cname) is always empty since miekg/dns does not
// return a canonical name for SRV queries the way net.LookupSRV does.
func (r *DNSSECResolver) LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	qname := fmt.Sprintf("_%s._%s.%s", service, proto, name)

	resp, err := r.queryWithDNSSEC(qname, dns.TypeSRV)
	if err != nil {
		return "", nil, err
	}

	var srvs []*net.SRV
	for _, rr := range resp.Answer {
		if srv, ok := rr.(*dns.SRV); ok {
			srvs = append(srvs, &net.SRV{
				Target:   strings.TrimSuffix(srv.Target, "."),
				Port:     srv.Port,
				Priority: srv.Priority,
				Weight:   srv.Weight,
			})
		}
	}

	if len(srvs) == 0 {
		return "", nil, fmt.Errorf("%w: no SRV records for %s", ErrDNSLookupFailed, qname)
	}

	return "", srvs, nil
}

// LookupTXT looks up TXT records with DNSSEC validation.
func (r *DNSSECResolver) LookupTXT(name string) ([]string, error) {
	resp, err := r.queryWithDNSSEC(name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	var txts []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			// TXT records may be split into multiple strings; join them.
			txts = append(txts, strings.Join(txt.Txt, ""))
		}
	}

	if len(txts) == 0 {
		return nil, fmt.Errorf("%w: no TXT records for %s", ErrDNSLookupFailed, name)
	}

	return txts, nil
}
