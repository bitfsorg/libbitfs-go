package x402

import (
	"fmt"
	"net/http"
	"strconv"
)

// x402 HTTP header names.
const (
	HeaderPrice      = "X-Price"
	HeaderPricePerKB = "X-Price-Per-KB"
	HeaderFileSize   = "X-File-Size"
	HeaderInvoiceID  = "X-Invoice-Id"
	HeaderExpiry     = "X-Expiry"
)

// PaymentHeaders holds the x402 HTTP headers.
type PaymentHeaders struct {
	Price      uint64
	PricePerKB uint64
	FileSize   uint64
	InvoiceID  string
	Expiry     int64
}

// SetPaymentHeaders sets x402 headers on an HTTP response.
// Also sets the status code to 402 Payment Required.
func SetPaymentHeaders(w http.ResponseWriter, headers *PaymentHeaders) {
	w.Header().Set(HeaderPrice, strconv.FormatUint(headers.Price, 10))
	w.Header().Set(HeaderPricePerKB, strconv.FormatUint(headers.PricePerKB, 10))
	w.Header().Set(HeaderFileSize, strconv.FormatUint(headers.FileSize, 10))
	w.Header().Set(HeaderInvoiceID, headers.InvoiceID)
	w.Header().Set(HeaderExpiry, strconv.FormatInt(headers.Expiry, 10))
	w.WriteHeader(http.StatusPaymentRequired)
}

// PaymentHeadersFromInvoice creates PaymentHeaders from an Invoice.
func PaymentHeadersFromInvoice(inv *Invoice) *PaymentHeaders {
	return &PaymentHeaders{
		Price:      inv.Price,
		PricePerKB: inv.PricePerKB,
		FileSize:   inv.FileSize,
		InvoiceID:  inv.ID,
		Expiry:     inv.Expiry,
	}
}

// ParsePaymentHeaders extracts x402 headers from an HTTP response.
func ParsePaymentHeaders(resp *http.Response) (*PaymentHeaders, error) {
	priceStr := resp.Header.Get(HeaderPrice)
	if priceStr == "" {
		return nil, fmt.Errorf("%w: %s header missing", ErrMissingHeaders, HeaderPrice)
	}

	price, err := strconv.ParseUint(priceStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s value: %w", ErrMissingHeaders, HeaderPrice, err)
	}

	pricePerKBStr := resp.Header.Get(HeaderPricePerKB)
	if pricePerKBStr == "" {
		return nil, fmt.Errorf("%w: %s header missing", ErrMissingHeaders, HeaderPricePerKB)
	}

	pricePerKB, err := strconv.ParseUint(pricePerKBStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s value: %w", ErrMissingHeaders, HeaderPricePerKB, err)
	}

	fileSizeStr := resp.Header.Get(HeaderFileSize)
	if fileSizeStr == "" {
		return nil, fmt.Errorf("%w: %s header missing", ErrMissingHeaders, HeaderFileSize)
	}

	fileSize, err := strconv.ParseUint(fileSizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s value: %w", ErrMissingHeaders, HeaderFileSize, err)
	}

	invoiceID := resp.Header.Get(HeaderInvoiceID)
	if invoiceID == "" {
		return nil, fmt.Errorf("%w: %s header missing", ErrMissingHeaders, HeaderInvoiceID)
	}

	expiryStr := resp.Header.Get(HeaderExpiry)
	if expiryStr == "" {
		return nil, fmt.Errorf("%w: %s header missing", ErrMissingHeaders, HeaderExpiry)
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s value: %w", ErrMissingHeaders, HeaderExpiry, err)
	}

	return &PaymentHeaders{
		Price:      price,
		PricePerKB: pricePerKB,
		FileSize:   fileSize,
		InvoiceID:  invoiceID,
		Expiry:     expiry,
	}, nil
}
