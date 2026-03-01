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
// BuildHTLC — script opcode branches (66% -> higher)
// ---------------------------------------------------------------------------

func TestBuildHTLC_ValidScript_Length(t *testing.T) {
	params := makeHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)
	assert.Greater(t, len(scriptBytes), 100)
}

func TestBuildHTLC_DifferentTimeouts(t *testing.T) {
	timeouts := []uint32{MinHTLCTimeout, DefaultHTLCTimeout, 100, 200, MaxHTLCTimeout}
	for _, timeout := range timeouts {
		params := makeHTLCParams()
		params.Timeout = timeout
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err, "timeout=%d", timeout)
		assert.NotEmpty(t, scriptBytes)
	}
}

func TestBuildHTLC_DifferentAmounts(t *testing.T) {
	amounts := []uint64{1, 546, 10000, 1e8, 21e6 * 1e8}
	for _, amount := range amounts {
		params := makeHTLCParams()
		params.Amount = amount
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err, "amount=%d", amount)
		assert.NotEmpty(t, scriptBytes)
	}
}

func TestBuildHTLC_ScriptContainsOpcodes(t *testing.T) {
	params := makeHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	opcodes := make(map[byte]bool)
	for _, c := range chunks {
		opcodes[c.Op] = true
	}
	assert.True(t, opcodes[script.OpIF])
	assert.True(t, opcodes[script.OpELSE])
	assert.True(t, opcodes[script.OpENDIF])
	assert.True(t, opcodes[script.OpSHA256])
	assert.True(t, opcodes[script.OpCHECKSIG])
	assert.True(t, opcodes[script.OpCHECKMULTISIG])
}

// ---------------------------------------------------------------------------
// generateInvoiceID — coverage of normal path (75% -> higher)
// ---------------------------------------------------------------------------

func TestGenerateInvoiceID_Uniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateInvoiceID()
		assert.Len(t, id, 32) // 16 bytes hex-encoded
		assert.False(t, ids[id], "duplicate invoice ID")
		ids[id] = true
	}
}

// ---------------------------------------------------------------------------
// ParseHTLCPreimage — edge cases (81% -> higher)
// ---------------------------------------------------------------------------

func TestParseHTLCPreimage_NoHTLCSpend(t *testing.T) {
	tx := transaction.NewTransaction()
	dummyTxID := chainhash.DoubleHashH([]byte("no-htlc"))
	s := &script.Script{}
	s.AppendPushData([]byte("just a signature"))
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  s,
	})
	raw := tx.Bytes()
	_, err := ParseHTLCPreimage(raw, nil)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

func TestParseHTLCPreimage_NilUnlockingScript(t *testing.T) {
	tx := transaction.NewTransaction()
	dummyTxID := chainhash.DoubleHashH([]byte("nil-script"))
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  nil,
	})
	raw := tx.Bytes()
	_, err := ParseHTLCPreimage(raw, nil)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

func TestParseHTLCPreimage_EmptyPreimageData(t *testing.T) {
	tx := transaction.NewTransaction()
	dummyTxID := chainhash.DoubleHashH([]byte("empty-preimage"))
	s := &script.Script{}
	s.AppendPushData([]byte("sig"))
	s.AppendPushData([]byte("pubkey"))
	s.AppendPushData([]byte{}) // empty preimage
	s.AppendOpcodes(script.OpTRUE)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID,
		SourceTxOutIndex: 0,
		UnlockingScript:  s,
	})
	raw := tx.Bytes()
	_, err := ParseHTLCPreimage(raw, nil)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

func TestParseHTLCPreimage_MultipleInputsSecondMatches(t *testing.T) {
	tx := transaction.NewTransaction()

	// First input: no match (too few chunks).
	dummyTxID1 := chainhash.DoubleHashH([]byte("input1"))
	s1 := &script.Script{}
	s1.AppendPushData([]byte("sig-only"))
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID1,
		SourceTxOutIndex: 0,
		UnlockingScript:  s1,
	})

	// Second input: valid HTLC spend pattern.
	dummyTxID2 := chainhash.DoubleHashH([]byte("input2"))
	s2 := &script.Script{}
	s2.AppendPushData([]byte("signature"))
	s2.AppendPushData([]byte("pubkey"))
	s2.AppendPushData([]byte("capsule-preimage"))
	s2.AppendOpcodes(script.OpTRUE)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       &dummyTxID2,
		SourceTxOutIndex: 0,
		UnlockingScript:  s2,
	})

	raw := tx.Bytes()
	preimage, err := ParseHTLCPreimage(raw, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("capsule-preimage"), preimage)
}

// ---------------------------------------------------------------------------
// VerifyPayment — edge cases (90.5% -> higher)
// ---------------------------------------------------------------------------

func TestVerifyPayment_NonP2PKHOutputs(t *testing.T) {
	tx := transaction.NewTransaction()
	opRetScript := &script.Script{}
	opRetScript.AppendOpcodes(script.OpRETURN)
	opRetScript.AppendPushData([]byte("data"))
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: opRetScript,
		Satoshis:      10000,
	})
	raw := tx.Bytes()

	invoice := &Invoice{
		Price:       1000,
		PaymentAddr: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		Expiry:      time.Now().Unix() + 3600,
	}
	proof := &PaymentProof{RawTx: raw}
	_, err := VerifyPayment(proof, invoice)
	assert.Error(t, err)
}

func TestVerifyPayment_EmptyPaymentAddress(t *testing.T) {
	tx := transaction.NewTransaction()
	err := tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 10000)
	require.NoError(t, err)
	raw := tx.Bytes()

	invoice := &Invoice{
		Price:       1000,
		PaymentAddr: "",
		Expiry:      time.Now().Unix() + 3600,
	}
	proof := &PaymentProof{RawTx: raw}
	_, err = VerifyPayment(proof, invoice)
	assert.Error(t, err)
}

func TestVerifyPayment_ExactAmount(t *testing.T) {
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	tx := transaction.NewTransaction()
	err := tx.PayToAddress(addr, 5000)
	require.NoError(t, err)
	raw := tx.Bytes()

	invoice := &Invoice{
		Price:       5000,
		PaymentAddr: addr,
		Expiry:      time.Now().Unix() + 3600,
	}
	proof := &PaymentProof{RawTx: raw}
	_, err = VerifyPayment(proof, invoice)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makeHTLCParams() *HTLCParams {
	buyerPub := make([]byte, CompressedPubKeyLen)
	buyerPub[0] = 0x02
	for i := 1; i < 33; i++ {
		buyerPub[i] = byte(i)
	}
	sellerPub := make([]byte, CompressedPubKeyLen)
	sellerPub[0] = 0x03
	for i := 1; i < 33; i++ {
		sellerPub[i] = byte(i + 50)
	}
	return &HTLCParams{
		BuyerPubKey:  buyerPub,
		SellerPubKey: sellerPub,
		SellerAddr:   make([]byte, PubKeyHashLen),
		CapsuleHash:  make([]byte, CapsuleHashLen),
		Amount:       10000,
		Timeout:      DefaultHTLCTimeout,
	}
}
