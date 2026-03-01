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

	preimage, err := ParseHTLCPreimage(raw, nil)
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
	_ = s.AppendOpcodes(script.OpFALSE) // Not OP_TRUE -> buyer refund path, not seller claim

	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  s,
	})

	_ = tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 546)
	raw := tx.Bytes()

	_, err := ParseHTLCPreimage(raw, nil)
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

	_, err := VerifyPayment(proof, inv)
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

	_, err := VerifyPayment(proof, inv)
	assert.NoError(t, err, "zero-price invoice should accept zero-value output")
}

// ---------------------------------------------------------------------------
// BuildHTLC — 2-of-2 multisig refund path
// ---------------------------------------------------------------------------

func TestBuildHTLC_MultisigRefundPath(t *testing.T) {
	params := validHTLCParams()

	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Find OP_CHECKMULTISIG and verify OP_2 precedes it
	for i, chunk := range chunks {
		if chunk.Op == script.OpCHECKMULTISIG && i >= 4 {
			// Should be: OP_2 <buyer_pk> <seller_pk> OP_2 OP_CHECKMULTISIG
			assert.Equal(t, script.Op2, chunks[i-1].Op, "OP_2 should precede OP_CHECKMULTISIG")
			assert.Equal(t, script.Op2, chunks[i-4].Op, "OP_2 should start the multisig block")
			break
		}
	}
}

// ---------------------------------------------------------------------------
// NewInvoice — edge cases
// ---------------------------------------------------------------------------

func TestNewInvoice_ZeroPrice(t *testing.T) {
	inv, err := NewInvoice(0, 1024, "addr", make([]byte, 32), 60)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), inv.Price)
	assert.NotEmpty(t, inv.ID)
}

func TestNewInvoice_ZeroTTL(t *testing.T) {
	inv, err := NewInvoice(100, 1024, "addr", make([]byte, 32), 0)
	require.NoError(t, err)
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
