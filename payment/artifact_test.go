package payment

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadArtifact(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)
	assert.NotEmpty(t, art.Hex)
	assert.NotEmpty(t, art.ABI)
	assert.Equal(t, "BitfsHTLC", art.Contract)
	assert.Equal(t, 9, art.Version)

	// Verify ABI has constructor + 2 methods
	var constructorFound bool
	var claimFound, refundFound bool
	for _, abi := range art.ABI {
		switch abi.Type {
		case "constructor":
			constructorFound = true
			assert.Len(t, abi.Params, 5)
		case "function":
			switch abi.Name {
			case "claim":
				claimFound = true
			case "refund":
				refundFound = true
			}
		}
	}
	assert.True(t, constructorFound, "constructor ABI not found")
	assert.True(t, claimFound, "claim ABI not found")
	assert.True(t, refundFound, "refund ABI not found")
}

func TestInstantiateHTLC(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)

	invoiceID := make([]byte, InvoiceIDLen)
	capsuleHash := make([]byte, CapsuleHashLen)
	sellerPkh := make([]byte, PubKeyHashLen)
	buyerPkh := make([]byte, PubKeyHashLen)
	timeout := uint32(72)

	script, err := art.Instantiate(invoiceID, capsuleHash, sellerPkh, buyerPkh, timeout)
	require.NoError(t, err)
	assert.NotEmpty(t, script)

	// Verify no placeholders remain in the hex
	hexStr := hex.EncodeToString(script)
	assert.NotContains(t, hexStr, "<")
	assert.NotContains(t, hexStr, ">")
}

func TestInstantiateHTLC_NonZeroParams(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)

	invoiceID := make([]byte, InvoiceIDLen)
	for i := range invoiceID {
		invoiceID[i] = byte(i + 1)
	}
	capsuleHash := make([]byte, CapsuleHashLen)
	for i := range capsuleHash {
		capsuleHash[i] = byte(0xaa)
	}
	sellerPkh := make([]byte, PubKeyHashLen)
	for i := range sellerPkh {
		sellerPkh[i] = byte(0xbb)
	}
	buyerPkh := make([]byte, PubKeyHashLen)
	for i := range buyerPkh {
		buyerPkh[i] = byte(0xcc)
	}
	timeout := uint32(144)

	script, err := art.Instantiate(invoiceID, capsuleHash, sellerPkh, buyerPkh, timeout)
	require.NoError(t, err)
	assert.NotEmpty(t, script)

	hexStr := hex.EncodeToString(script)
	// Verify the substituted values appear in the output
	assert.Contains(t, hexStr, hex.EncodeToString(invoiceID))
	assert.Contains(t, hexStr, hex.EncodeToString(capsuleHash))
	assert.Contains(t, hexStr, hex.EncodeToString(sellerPkh))
	assert.Contains(t, hexStr, hex.EncodeToString(buyerPkh))
	// timeout=144 in sCrypt int encoding: 9000 (little-endian signed magnitude)
	assert.Contains(t, hexStr, "9000")
}

func TestInstantiateHTLC_InvalidParams(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)

	validInvoiceID := make([]byte, InvoiceIDLen)
	validCapsuleHash := make([]byte, CapsuleHashLen)
	validSellerPkh := make([]byte, PubKeyHashLen)
	validBuyerPkh := make([]byte, PubKeyHashLen)

	tests := []struct {
		name        string
		invoiceID   []byte
		capsuleHash []byte
		sellerPkh   []byte
		buyerPkh    []byte
		timeout     uint32
		errContains string
	}{
		{
			name:        "wrong invoiceID length",
			invoiceID:   make([]byte, 10),
			capsuleHash: validCapsuleHash,
			sellerPkh:   validSellerPkh,
			buyerPkh:    validBuyerPkh,
			timeout:     72,
			errContains: "invoiceID",
		},
		{
			name:        "wrong capsuleHash length",
			invoiceID:   validInvoiceID,
			capsuleHash: make([]byte, 16),
			sellerPkh:   validSellerPkh,
			buyerPkh:    validBuyerPkh,
			timeout:     72,
			errContains: "capsuleHash",
		},
		{
			name:        "wrong sellerPkh length",
			invoiceID:   validInvoiceID,
			capsuleHash: validCapsuleHash,
			sellerPkh:   make([]byte, 10),
			buyerPkh:    validBuyerPkh,
			timeout:     72,
			errContains: "sellerPkh",
		},
		{
			name:        "wrong buyerPkh length",
			invoiceID:   validInvoiceID,
			capsuleHash: validCapsuleHash,
			sellerPkh:   validSellerPkh,
			buyerPkh:    make([]byte, 10),
			timeout:     72,
			errContains: "buyerPkh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := art.Instantiate(tt.invoiceID, tt.capsuleHash, tt.sellerPkh, tt.buyerPkh, tt.timeout)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestEncodeScryptInt(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		expected string
	}{
		{"zero", 0, "00"},
		{"one", 1, "01"},
		{"72 (default timeout)", 72, "48"},
		{"127", 127, "7f"},
		{"128 (needs extra byte)", 128, "8000"},
		{"144", 144, "9000"},
		{"255", 255, "ff00"},
		{"256", 256, "0001"},
		{"288 (max timeout)", 288, "2001"},
		{"negative one", -1, "81"},
		{"negative 128", -128, "8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeScryptInt(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestInstantiateHTLC_Deterministic(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)

	invoiceID := make([]byte, InvoiceIDLen)
	capsuleHash := make([]byte, CapsuleHashLen)
	sellerPkh := make([]byte, PubKeyHashLen)
	buyerPkh := make([]byte, PubKeyHashLen)
	timeout := uint32(72)

	script1, err := art.Instantiate(invoiceID, capsuleHash, sellerPkh, buyerPkh, timeout)
	require.NoError(t, err)

	script2, err := art.Instantiate(invoiceID, capsuleHash, sellerPkh, buyerPkh, timeout)
	require.NoError(t, err)

	assert.Equal(t, script1, script2, "Instantiate should be deterministic")
}

func TestArtifactHexContainsPlaceholders(t *testing.T) {
	art, err := LoadArtifact()
	require.NoError(t, err)

	// The raw hex template should contain all 5 placeholders
	assert.True(t, strings.Contains(art.Hex, "<invoiceId>"))
	assert.True(t, strings.Contains(art.Hex, "<capsuleHash>"))
	assert.True(t, strings.Contains(art.Hex, "<sellerPkh>"))
	assert.True(t, strings.Contains(art.Hex, "<buyerPkh>"))
	assert.True(t, strings.Contains(art.Hex, "<timeout>"))
}
