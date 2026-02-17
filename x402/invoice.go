// Package x402 implements the x402 payment protocol for BitFS.
//
// It handles HTTP 402 Payment Required responses with structured headers,
// invoice creation and verification, and HTLC atomic swap integration
// for content purchases.
package x402

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Invoice represents a payment request for content access.
type Invoice struct {
	ID          string `json:"id"`
	Price       uint64 `json:"price"`         // Total price in satoshis
	PricePerKB  uint64 `json:"price_per_kb"`  // Unit price
	FileSize    uint64 `json:"file_size"`     // Content size in bytes
	PaymentAddr string `json:"payment_addr"`  // BSV address for payment
	Expiry      int64  `json:"expiry"`        // Unix timestamp
	KeyHash     []byte `json:"key_hash"`      // Content key hash
	CapsuleHash []byte `json:"capsule_hash"`  // SHA256(ECDH capsule) for HTLC
}

// PaymentProof represents a submitted payment for verification.
type PaymentProof struct {
	RawTx       []byte `json:"raw_tx"`       // Serialized BSV transaction
	MerkleProof []byte `json:"merkle_proof"` // Optional Merkle proof
}

// CalculatePrice computes the total price for content.
// total = ceil(pricePerKB * fileSize / 1024)
func CalculatePrice(pricePerKB, fileSize uint64) uint64 {
	if pricePerKB == 0 || fileSize == 0 {
		return 0
	}
	// Ceiling division: (a + b - 1) / b
	numerator := pricePerKB * fileSize
	return (numerator + 1023) / 1024
}

// NewInvoice creates a new payment invoice.
// pricePerKB is the unit price in satoshis per kilobyte.
// fileSize is the content size in bytes.
// paymentAddr is the BSV address where payment should be sent.
// capsuleHash is SHA256(capsule) for the HTLC hash lock (32 bytes).
// ttlSeconds is the invoice time-to-live in seconds.
func NewInvoice(pricePerKB, fileSize uint64, paymentAddr string, capsuleHash []byte, ttlSeconds int64) *Invoice {
	invoiceID := generateInvoiceID()
	totalPrice := CalculatePrice(pricePerKB, fileSize)
	now := time.Now()

	return &Invoice{
		ID:          invoiceID,
		Price:       totalPrice,
		PricePerKB:  pricePerKB,
		FileSize:    fileSize,
		PaymentAddr: paymentAddr,
		Expiry:      now.Unix() + ttlSeconds,
		CapsuleHash: capsuleHash,
	}
}

// IsExpired returns true if the invoice has passed its expiry time.
func (inv *Invoice) IsExpired() bool {
	return time.Now().Unix() > inv.Expiry
}

// generateInvoiceID creates a random 16-byte hex-encoded invoice ID.
func generateInvoiceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("inv-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
