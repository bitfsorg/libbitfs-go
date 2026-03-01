package paymail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PostClient extends HTTPClient with POST capability.
// This is needed for P2P payment destination resolution, which requires
// a POST request after capability discovery (GET).
type PostClient interface {
	HTTPClient
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

// defaultPostClient wraps an http.Client with timeout to implement PostClient.
type defaultPostClient struct {
	client *http.Client
}

func (d *defaultPostClient) Get(rawURL string) (*http.Response, error) {
	return d.client.Get(rawURL)
}

func (d *defaultPostClient) Post(rawURL, contentType string, body io.Reader) (*http.Response, error) {
	return d.client.Post(rawURL, contentType, body)
}

// DefaultPostClient is the production PostClient with a 30-second timeout.
var DefaultPostClient PostClient = &defaultPostClient{
	client: &http.Client{Timeout: 30 * time.Second},
}

// PaymentOutput represents a single output in a P2P payment destination response.
type PaymentOutput struct {
	Script   string `json:"script"`
	Satoshis uint64 `json:"satoshis"`
}

// paymentDestinationResponse is the JSON envelope returned by the payment destination endpoint.
type paymentDestinationResponse struct {
	Outputs []PaymentOutput `json:"outputs"`
}

// ResolvePaymentDestination resolves a Paymail alias to P2P payment destination outputs
// using the default HTTP client.
func ResolvePaymentDestination(alias, domain string) ([]PaymentOutput, error) {
	return ResolvePaymentDestinationWithClient(alias, domain, DefaultPostClient)
}

// ResolvePaymentDestinationWithClient resolves a Paymail alias to P2P payment
// destination outputs using the provided PostClient.
//
// It performs capability discovery (GET), then POSTs to the payment destination
// endpoint to obtain output scripts for payment.
func ResolvePaymentDestinationWithClient(alias, domain string, client PostClient) ([]PaymentOutput, error) {
	if alias == "" || domain == "" {
		return nil, fmt.Errorf("%w: alias and domain are required", ErrAddressResolution)
	}

	// Discover capabilities (GET .well-known/bsvalias).
	caps, err := DiscoverCapabilitiesWithClient(domain, client)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAddressResolution, err)
	}

	if caps.PaymentDestination == "" {
		return nil, fmt.Errorf("%w: no payment destination capability found for %s", ErrAddressResolution, domain)
	}

	// Build URL from template, escaping variables to prevent path traversal.
	destURL := strings.ReplaceAll(caps.PaymentDestination, "{alias}", url.PathEscape(alias))
	destURL = strings.ReplaceAll(destURL, "{domain.tld}", url.PathEscape(domain))

	// POST with sender metadata.
	reqBody := strings.NewReader(`{"senderName":"BitFS","purpose":"revshare"}`)
	resp, err := client.Post(destURL, "application/json", reqBody)
	if err != nil {
		return nil, fmt.Errorf("%w: POST %s: %w", ErrAddressResolution, destURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: POST %s returned status %d", ErrAddressResolution, destURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxPaymailResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrAddressResolution, err)
	}

	var destResp paymentDestinationResponse
	if err := json.Unmarshal(body, &destResp); err != nil {
		return nil, fmt.Errorf("%w: parsing response: %w", ErrAddressResolution, err)
	}

	if len(destResp.Outputs) == 0 {
		return nil, fmt.Errorf("%w: no outputs in response", ErrAddressResolution)
	}

	return destResp.Outputs, nil
}
