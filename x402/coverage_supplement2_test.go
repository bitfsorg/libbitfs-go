package x402

import (
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseHTLCPreimage — OP_1 variant (alias for OP_TRUE)
// ---------------------------------------------------------------------------

func TestParseHTLCPreimage_Op1Variant(t *testing.T) {
	tx := transaction.NewTransaction()
	dummyTxID := chainhash.DoubleHashH([]byte("op1-variant"))

	s := &script.Script{}
	_ = s.AppendPushData([]byte("sig"))
	_ = s.AppendPushData([]byte("pubkey"))
	_ = s.AppendPushData([]byte("capsule-preimage-op1"))
	_ = s.AppendOpcodes(script.Op1) // Op1 instead of OpTRUE

	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  s,
	})

	_ = tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 546)
	raw := tx.Bytes()

	preimage, err := ParseHTLCPreimage(raw)
	require.NoError(t, err)
	assert.Equal(t, []byte("capsule-preimage-op1"), preimage)
}

// ---------------------------------------------------------------------------
// ParseHTLCPreimage — non-OP_TRUE last chunk is skipped
// ---------------------------------------------------------------------------

func TestParseHTLCPreimage_NonOpTrueLastChunk(t *testing.T) {
	tx := transaction.NewTransaction()
	dummyTxID := chainhash.DoubleHashH([]byte("not-true"))

	s := &script.Script{}
	_ = s.AppendPushData([]byte("sig"))
	_ = s.AppendPushData([]byte("pubkey"))
	_ = s.AppendPushData([]byte("preimage"))
	_ = s.AppendOpcodes(script.OpFALSE) // Not OP_TRUE → buyer refund path, not seller claim

	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  s,
	})

	_ = tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 546)
	raw := tx.Bytes()

	_, err := ParseHTLCPreimage(raw)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

// ---------------------------------------------------------------------------
// VerifyPayment — output with nil LockingScript (actual nil)
// ---------------------------------------------------------------------------

func TestVerifyPayment_EmptyLockingScript(t *testing.T) {
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	tx := transaction.NewTransaction()

	// First output has empty (non-P2PKH) LockingScript — should be skipped
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: &script.Script{},
	})

	// Second output is valid P2PKH
	_ = tx.PayToAddress(addr, 1000)

	raw := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: addr,
	}
	proof := &PaymentProof{RawTx: raw}

	err := VerifyPayment(proof, inv)
	assert.NoError(t, err, "should skip empty LockingScript output and match the valid one")
}

// ---------------------------------------------------------------------------
// VerifyPayment — zero price invoice (free content)
// ---------------------------------------------------------------------------

func TestVerifyPayment_ZeroPriceInvoice(t *testing.T) {
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	tx := transaction.NewTransaction()
	_ = tx.PayToAddress(addr, 0)
	raw := tx.Bytes()

	inv := &Invoice{
		Price:       0,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: addr,
	}
	proof := &PaymentProof{RawTx: raw}

	err := VerifyPayment(proof, inv)
	assert.NoError(t, err, "zero-price invoice should accept zero-value output")
}

// ---------------------------------------------------------------------------
// encodeScriptNum — more boundary values
// ---------------------------------------------------------------------------

func TestEncodeScriptNum_LargePositive(t *testing.T) {
	// 0x100000 = 1048576 → 3 bytes: [0x00, 0x00, 0x10]
	result := encodeScriptNum(0x100000)
	assert.Equal(t, []byte{0x00, 0x00, 0x10}, result)
}

func TestEncodeScriptNum_MaxInt32(t *testing.T) {
	// 2^31 - 1 = 2147483647
	result := encodeScriptNum(2147483647)
	assert.NotEmpty(t, result)
	// 0x7FFFFFFF → [0xFF, 0xFF, 0xFF, 0x7F] — high bit NOT set on MSB
	assert.Equal(t, []byte{0xFF, 0xFF, 0xFF, 0x7F}, result)
}

func TestEncodeScriptNum_PowerOfTwo(t *testing.T) {
	// 256 = 0x100 → [0x00, 0x01]
	result := encodeScriptNum(256)
	assert.Equal(t, []byte{0x00, 0x01}, result)
}

func TestEncodeScriptNum_NegativeLarge(t *testing.T) {
	// -256 → [0x00, 0x81] (0x100 with sign bit)
	result := encodeScriptNum(-256)
	assert.Equal(t, []byte{0x00, 0x81}, result)
}

// ---------------------------------------------------------------------------
// BuildHTLC — large timeout encoding
// ---------------------------------------------------------------------------

func TestBuildHTLC_LargeTimeout(t *testing.T) {
	params := validHTLCParams()
	params.Timeout = 500000 // large value

	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Find CLTV and verify timeout was encoded
	for i, chunk := range chunks {
		if chunk.Op == script.OpCHECKLOCKTIMEVERIFY && i > 0 {
			assert.NotNil(t, chunks[i-1].Data, "timeout data should precede OP_CHECKLOCKTIMEVERIFY")
			break
		}
	}
}

// ---------------------------------------------------------------------------
// NewInvoice — edge cases
// ---------------------------------------------------------------------------

func TestNewInvoice_ZeroPrice(t *testing.T) {
	inv := NewInvoice(0, 1024, "addr", make([]byte, 32), 60)
	assert.Equal(t, uint64(0), inv.Price)
	assert.NotEmpty(t, inv.ID)
}

func TestNewInvoice_ZeroTTL(t *testing.T) {
	inv := NewInvoice(100, 1024, "addr", make([]byte, 32), 0)
	// With 0 TTL, expiry should be approximately now
	assert.InDelta(t, time.Now().Unix(), inv.Expiry, 2)
}

// ---------------------------------------------------------------------------
// IsExpired — boundary
// ---------------------------------------------------------------------------

func TestInvoice_IsExpired_ExactlyNow(t *testing.T) {
	// Expiry exactly at current time — should NOT be expired
	// (condition is >, not >=)
	inv := &Invoice{Expiry: time.Now().Unix()}
	assert.False(t, inv.IsExpired())
}
