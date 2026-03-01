package x402

import (
	"bytes"
	"crypto/sha256"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/method42"
)

func TestVerifyHTLCFunding(t *testing.T) {
	// Build a known HTLC script for test.
	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := bytes.Repeat([]byte{0xcd}, 20)
	buyerPubKey := make([]byte, 33)
	buyerPubKey[0] = 0x02
	for i := 1; i < 33; i++ {
		buyerPubKey[i] = byte(i)
	}
	sellerPubKey := make([]byte, 33)
	sellerPubKey[0] = 0x03
	for i := 1; i < 33; i++ {
		sellerPubKey[i] = byte(i + 50)
	}

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPubKey,
		SellerPubKey: sellerPubKey,
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	// Build a mock funding transaction with the HTLC output.
	fundingTx := transaction.NewTransaction()
	htlcLockingScript := script.Script(htlcScript)
	fundingTx.AddOutput(&transaction.TransactionOutput{
		LockingScript: &htlcLockingScript,
		Satoshis:      1000,
	})

	t.Run("valid funding tx", func(t *testing.T) {
		vout, err := VerifyHTLCFunding(fundingTx.Bytes(), htlcScript, 1000)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), vout)
	})

	t.Run("amount exceeds minimum", func(t *testing.T) {
		vout, err := VerifyHTLCFunding(fundingTx.Bytes(), htlcScript, 500)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), vout)
	})

	t.Run("insufficient amount", func(t *testing.T) {
		_, err := VerifyHTLCFunding(fundingTx.Bytes(), htlcScript, 2000)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInsufficientPayment)
	})

	t.Run("wrong script", func(t *testing.T) {
		wrongScript := bytes.Repeat([]byte{0xff}, 50)
		_, err := VerifyHTLCFunding(fundingTx.Bytes(), wrongScript, 1000)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoMatchingOutput)
	})

	t.Run("empty raw tx", func(t *testing.T) {
		_, err := VerifyHTLCFunding(nil, htlcScript, 1000)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTx)
	})

	t.Run("nil expected script", func(t *testing.T) {
		_, err := VerifyHTLCFunding(fundingTx.Bytes(), nil, 1000)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
	})

	t.Run("htlc output at index 1", func(t *testing.T) {
		// Build tx with a P2PKH output first, then HTLC second.
		tx2 := transaction.NewTransaction()
		dummyScript := script.Script([]byte{0x76, 0xa9})
		tx2.AddOutput(&transaction.TransactionOutput{
			LockingScript: &dummyScript,
			Satoshis:      500,
		})
		tx2.AddOutput(&transaction.TransactionOutput{
			LockingScript: &htlcLockingScript,
			Satoshis:      1000,
		})
		vout, err := VerifyHTLCFunding(tx2.Bytes(), htlcScript, 1000)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), vout)
	})
}

func TestBuildHTLCFundingTx(t *testing.T) {
	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	sellerPubKey := sellerPriv.PubKey().Compressed()
	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	changeAddr := buyerPriv.PubKey().Hash()

	// Build a mock P2PKH script for the UTXO.
	buyerPKH := buyerPriv.PubKey().Hash()
	p2pkhScript := buildTestP2PKHScript(t, buyerPKH)

	mockTxID := sha256.Sum256([]byte("mock-utxo-txid"))

	t.Run("single UTXO sufficient funds", func(t *testing.T) {
		result, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			SellerPubKey: sellerPubKey,
			CapsuleHash:  capsuleHash,
			Amount:       1000,
			Timeout:      DefaultHTLCTimeout,
			UTXOs: []*HTLCUTXO{{
				TxID:         mockTxID[:],
				Vout:         0,
				Amount:       10000,
				ScriptPubKey: p2pkhScript,
			}},
			ChangeAddr: changeAddr,
			FeeRate:    1,
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.RawTx)
		require.NotEmpty(t, result.TxID)
		require.NotEmpty(t, result.HTLCScript)
		assert.Equal(t, uint32(0), result.HTLCVout)
		assert.Equal(t, uint64(1000), result.HTLCAmount)

		// Verify the funding tx with VerifyHTLCFunding.
		vout, err := VerifyHTLCFunding(result.RawTx, result.HTLCScript, 1000)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), vout)
	})

	t.Run("small amount passes through as-is", func(t *testing.T) {
		result, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			SellerPubKey: sellerPubKey,
			CapsuleHash:  capsuleHash,
			Amount:       100, // Small amount (no dust limit enforcement)
			Timeout:      DefaultHTLCTimeout,
			UTXOs: []*HTLCUTXO{{
				TxID:         mockTxID[:],
				Vout:         0,
				Amount:       10000,
				ScriptPubKey: p2pkhScript,
			}},
			ChangeAddr: changeAddr,
			FeeRate:    1,
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(100), result.HTLCAmount, "amount should pass through without dust adjustment")
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(nil)
		require.Error(t, err)
	})

	t.Run("no UTXOs", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			SellerPubKey: sellerPubKey,
			CapsuleHash:  capsuleHash,
			Amount:       1000,
			Timeout:      DefaultHTLCTimeout,
			UTXOs:        nil,
			ChangeAddr:   changeAddr,
		})
		require.Error(t, err)
	})

	t.Run("insufficient funds", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			SellerPubKey: sellerPubKey,
			CapsuleHash:  capsuleHash,
			Amount:       100000,
			Timeout:      DefaultHTLCTimeout,
			UTXOs: []*HTLCUTXO{{
				TxID:         mockTxID[:],
				Vout:         0,
				Amount:       1000,
				ScriptPubKey: p2pkhScript,
			}},
			ChangeAddr: changeAddr,
		})
		require.Error(t, err)
	})
}

func TestBuildHTLCFundingTx_FeeAccountsForScriptSize(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	sellerPubKey := sellerPriv.PubKey().Compressed()
	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	changeAddr := priv.PubKey().Hash()
	buyerPKH := priv.PubKey().Hash()
	p2pkhScript := buildTestP2PKHScript(t, buyerPKH)
	mockTxID := sha256.Sum256([]byte("fee-test-utxo"))

	result, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: priv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPubKey,
		CapsuleHash:  capsuleHash,
		Amount:       50000,
		Timeout:      DefaultHTLCTimeout,
		UTXOs: []*HTLCUTXO{{
			TxID:         mockTxID[:],
			Vout:         0,
			Amount:       100000,
			ScriptPubKey: p2pkhScript,
		}},
		ChangeAddr: changeAddr,
		FeeRate:    1,
	})
	require.NoError(t, err)

	// Parse the tx to check the fee
	tx, err := transaction.NewTransactionFromBytes(result.RawTx)
	require.NoError(t, err)

	var totalOut uint64
	for _, o := range tx.Outputs {
		totalOut += o.Satoshis
	}
	actualFee := uint64(100000) - totalOut
	actualSize := uint64(len(result.RawTx))

	// Fee should be at least 1 sat/byte for the actual tx size.
	assert.GreaterOrEqual(t, actualFee, actualSize,
		"fee must cover actual transaction size at 1 sat/byte")
}

func TestBuildHTLCFundingTx_RejectsZeroAmount(t *testing.T) {
	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	_, err = BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		UTXOs:        []*HTLCUTXO{{TxID: make([]byte, 32), Vout: 0, Amount: 10000}},
		Amount:       0,
		SellerAddr:   make([]byte, PubKeyHashLen),
		SellerPubKey: make([]byte, CompressedPubKeyLen),
		CapsuleHash:  make([]byte, CapsuleHashLen),
		ChangeAddr:   make([]byte, PubKeyHashLen),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidParams, "zero amount should be rejected with ErrInvalidParams")
	assert.Contains(t, err.Error(), "amount")
}

func TestBuildSellerClaimTx(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsule := bytes.Repeat([]byte{0xde}, 32)
	fileTxID := bytes.Repeat([]byte{0xf0}, 32) // mock file txid
	capsuleHash := method42.ComputeCapsuleHash(fileTxID, capsule)
	sellerAddr := sellerPriv.PubKey().Hash()
	changeAddr := sellerPriv.PubKey().Hash()

	// Build HTLC script.
	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	mockTxID := sha256.Sum256([]byte("htlc-funding-txid"))

	t.Run("valid seller claim", func(t *testing.T) {
		claimTx, err := BuildSellerClaimTx(&SellerClaimParams{
			FundingTxID:   mockTxID[:],
			FundingVout:   0,
			FundingAmount: 1000,
			HTLCScript:    htlcScript,
			Capsule:       capsule,
			FileTxID:      fileTxID,
			SellerPrivKey: sellerPriv,
			OutputAddr:    changeAddr,
			FeeRate:       1,
		})
		require.NoError(t, err)
		require.NotNil(t, claimTx)
		require.NotEmpty(t, claimTx.Bytes())

		// Verify we can extract the capsule from the claim tx.
		extracted, err := ParseHTLCPreimage(claimTx.Bytes(), nil)
		require.NoError(t, err)
		assert.Equal(t, capsule, extracted)
	})

	t.Run("nil params fields", func(t *testing.T) {
		_, err := BuildSellerClaimTx(nil)
		require.Error(t, err)

		_, err = BuildSellerClaimTx(&SellerClaimParams{
			FundingTxID: mockTxID[:],
			// Missing other fields
		})
		require.Error(t, err)
	})
}

func TestBuildSellerPreSignedRefund(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	mockTxID := sha256.Sum256([]byte("htlc-funding-txid"))

	t.Run("valid seller pre-sign", func(t *testing.T) {
		result, err := BuildSellerPreSignedRefund(&SellerPreSignParams{
			FundingTxID:     mockTxID[:],
			FundingVout:     0,
			FundingAmount:   1000,
			HTLCScript:      htlcScript,
			SellerPrivKey:   sellerPriv,
			BuyerOutputAddr: buyerAddr,
			Timeout:         DefaultHTLCTimeout,
			FeeRate:         1,
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.TxBytes)
		require.NotEmpty(t, result.SellerSig)

		// Verify the tx structure.
		tx, err := transaction.NewTransactionFromBytes(result.TxBytes)
		require.NoError(t, err)
		assert.Equal(t, uint32(DefaultHTLCTimeout), tx.LockTime)
		assert.Equal(t, uint32(0xfffffffe), tx.Inputs[0].SequenceNumber)
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := BuildSellerPreSignedRefund(nil)
		require.Error(t, err)
	})

	t.Run("timeout zero defaults", func(t *testing.T) {
		result, err := BuildSellerPreSignedRefund(&SellerPreSignParams{
			FundingTxID:     mockTxID[:],
			FundingVout:     0,
			FundingAmount:   1000,
			HTLCScript:      htlcScript,
			SellerPrivKey:   sellerPriv,
			BuyerOutputAddr: buyerAddr,
			Timeout:         0,
			FeeRate:         1,
		})
		require.NoError(t, err)
		// Verify that zero timeout defaults to DefaultHTLCTimeout.
		tx, err := transaction.NewTransactionFromBytes(result.TxBytes)
		require.NoError(t, err)
		assert.Equal(t, uint32(DefaultHTLCTimeout), tx.LockTime)
	})
}

func TestBuildBuyerRefundTx(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	mockTxID := sha256.Sum256([]byte("htlc-funding-txid"))

	// First, get the seller's pre-signed refund.
	preSign, err := BuildSellerPreSignedRefund(&SellerPreSignParams{
		FundingTxID:     mockTxID[:],
		FundingVout:     0,
		FundingAmount:   1000,
		HTLCScript:      htlcScript,
		SellerPrivKey:   sellerPriv,
		BuyerOutputAddr: buyerAddr,
		Timeout:         DefaultHTLCTimeout,
		FeeRate:         1,
	})
	require.NoError(t, err)

	t.Run("valid buyer refund", func(t *testing.T) {
		refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: preSign.TxBytes,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
		})
		require.NoError(t, err)
		require.NotNil(t, refundTx)

		// Verify nLockTime is set.
		assert.Equal(t, uint32(DefaultHTLCTimeout), refundTx.LockTime)

		// Verify the unlocking script has OP_FALSE at end (selects ELSE branch).
		chunks, err := refundTx.Inputs[0].UnlockingScript.Chunks()
		require.NoError(t, err)
		lastChunk := chunks[len(chunks)-1]
		assert.Equal(t, script.OpFALSE, lastChunk.Op)

		// Verify first chunk is also OP_FALSE/OP_0 (CHECKMULTISIG dummy).
		assert.Equal(t, script.OpFALSE, chunks[0].Op)

		// Verify there are 4 chunks: OP_0 <buyer_sig> <seller_sig> OP_FALSE
		assert.Len(t, chunks, 4)
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := BuildBuyerRefundTx(nil)
		require.Error(t, err)
	})

	t.Run("empty pre-signed tx", func(t *testing.T) {
		_, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: nil,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
		})
		require.Error(t, err)
	})
}

func TestBuildBuyerRefundTx_FundingVerification(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	mockTxID := sha256.Sum256([]byte("htlc-funding-txid"))

	// Get the seller's pre-signed refund.
	preSign, err := BuildSellerPreSignedRefund(&SellerPreSignParams{
		FundingTxID:     mockTxID[:],
		FundingVout:     0,
		FundingAmount:   1000,
		HTLCScript:      htlcScript,
		SellerPrivKey:   sellerPriv,
		BuyerOutputAddr: buyerAddr,
		Timeout:         DefaultHTLCTimeout,
		FeeRate:         1,
	})
	require.NoError(t, err)

	t.Run("correct FundingTxID passes", func(t *testing.T) {
		refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: preSign.TxBytes,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
			FundingTxID:       mockTxID[:],
			FundingVout:       0,
		})
		require.NoError(t, err)
		require.NotNil(t, refundTx)
	})

	t.Run("nil FundingTxID skips check", func(t *testing.T) {
		refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: preSign.TxBytes,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
			// FundingTxID not set — should skip verification.
		})
		require.NoError(t, err)
		require.NotNil(t, refundTx)
	})

	t.Run("wrong FundingTxID rejected", func(t *testing.T) {
		wrongTxID := bytes.Repeat([]byte{0xff}, 32)

		_, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: preSign.TxBytes,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
			FundingTxID:       wrongTxID,
			FundingVout:       0,
		})
		assert.ErrorIs(t, err, ErrFundingMismatch)
	})

	t.Run("wrong FundingVout rejected", func(t *testing.T) {
		_, err := BuildBuyerRefundTx(&BuyerRefundParams{
			SellerPreSignedTx: preSign.TxBytes,
			SellerSig:         preSign.SellerSig,
			HTLCScript:        htlcScript,
			FundingAmount:     1000,
			BuyerPrivKey:      buyerPriv,
			FundingTxID:       mockTxID[:], // correct TxID
			FundingVout:       99,          // wrong vout
		})
		assert.ErrorIs(t, err, ErrFundingMismatch)
	})
}

// TestHTLCRoundTrip tests the full HTLC lifecycle in memory:
// encrypt -> invoice -> build funding tx -> verify funding -> build claim -> extract preimage -> decrypt
func TestHTLCRoundTrip(t *testing.T) {
	// Generate seller and buyer keys.
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	// --- Seller side: encrypt content and compute XOR-masked capsule ---
	plaintext := []byte("Top secret BitFS content for HTLC atomic swap test")

	encResult, err := method42.Encrypt(plaintext, sellerPriv, sellerPriv.PubKey(), method42.AccessPaid)
	require.NoError(t, err)

	// Capsule = aes_key XOR buyer_mask (XOR masking, buyer-specific).
	capsule, err := method42.ComputeCapsule(sellerPriv, sellerPriv.PubKey(), buyerPriv.PubKey(), encResult.KeyHash)
	require.NoError(t, err)

	fileTxID := bytes.Repeat([]byte{0xf1}, 32) // mock file txid
	capsuleHash := method42.ComputeCapsuleHash(fileTxID, capsule)

	// --- Create invoice ---
	pricePerKB := uint64(50000)
	fileSize := uint64(len(plaintext))
	invoice, err := NewInvoice(pricePerKB, fileSize, "1SellerAddr", capsuleHash, 3600)
	require.NoError(t, err)

	// --- Buyer side: build HTLC funding tx ---
	mockTxID := sha256.Sum256([]byte("buyer-utxo-txid"))
	buyerPKHScript := buildTestP2PKHScript(t, buyerPriv.PubKey().Hash())

	fundingResult, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		CapsuleHash:  capsuleHash,
		Amount:       invoice.Price,
		Timeout:      DefaultHTLCTimeout,
		UTXOs: []*HTLCUTXO{{
			TxID:         mockTxID[:],
			Vout:         0,
			Amount:       100000,
			ScriptPubKey: buyerPKHScript,
		}},
		ChangeAddr: buyerAddr,
		FeeRate:    1,
	})
	require.NoError(t, err)

	// --- Seller side: verify the funding tx ---
	vout, err := VerifyHTLCFunding(fundingResult.RawTx, fundingResult.HTLCScript, invoice.Price)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), vout)

	// --- Seller side: build claim tx (reveals capsule) ---
	claimTx, err := BuildSellerClaimTx(&SellerClaimParams{
		FundingTxID:   fundingResult.TxID,
		FundingVout:   fundingResult.HTLCVout,
		FundingAmount: fundingResult.HTLCAmount,
		HTLCScript:    fundingResult.HTLCScript,
		Capsule:       capsule,
		FileTxID:      fileTxID,
		SellerPrivKey: sellerPriv,
		OutputAddr:    sellerAddr,
		FeeRate:       1,
	})
	require.NoError(t, err)

	// --- Buyer side: extract capsule from claim tx ---
	extractedCapsule, err := ParseHTLCPreimage(claimTx.Bytes(), nil)
	require.NoError(t, err)
	assert.Equal(t, capsule, extractedCapsule)

	// Verify hash matches.
	extractedHash := method42.ComputeCapsuleHash(fileTxID, extractedCapsule)
	assert.Equal(t, capsuleHash, extractedHash)

	// --- Buyer side: decrypt content using capsule + buyer's private key ---
	decResult, err := method42.DecryptWithCapsule(encResult.Ciphertext, extractedCapsule, encResult.KeyHash, buyerPriv, sellerPriv.PubKey())
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)

	t.Logf("HTLC round-trip: encrypt -> fund -> claim -> extract -> decrypt OK (%d bytes)", len(plaintext))
}

// TestHTLCBuyerRefundRoundTrip tests the buyer refund path via pre-signed 2-of-2 multisig.
func TestHTLCBuyerRefundRoundTrip(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	// Build HTLC funding tx.
	mockTxID := sha256.Sum256([]byte("buyer-utxo-txid"))
	buyerPKHScript := buildTestP2PKHScript(t, buyerPriv.PubKey().Hash())

	fundingResult, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
		UTXOs: []*HTLCUTXO{{
			TxID:         mockTxID[:],
			Vout:         0,
			Amount:       100000,
			ScriptPubKey: buyerPKHScript,
		}},
		ChangeAddr: buyerAddr,
		FeeRate:    1,
	})
	require.NoError(t, err)

	// Seller pre-signs refund.
	preSign, err := BuildSellerPreSignedRefund(&SellerPreSignParams{
		FundingTxID:     fundingResult.TxID,
		FundingVout:     fundingResult.HTLCVout,
		FundingAmount:   fundingResult.HTLCAmount,
		HTLCScript:      fundingResult.HTLCScript,
		SellerPrivKey:   sellerPriv,
		BuyerOutputAddr: buyerAddr,
		Timeout:         DefaultHTLCTimeout,
		FeeRate:         1,
	})
	require.NoError(t, err)

	// Buyer counter-signs refund.
	refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
		SellerPreSignedTx: preSign.TxBytes,
		SellerSig:         preSign.SellerSig,
		HTLCScript:        fundingResult.HTLCScript,
		FundingAmount:     fundingResult.HTLCAmount,
		BuyerPrivKey:      buyerPriv,
	})
	require.NoError(t, err)
	require.NotNil(t, refundTx)

	assert.Equal(t, uint32(DefaultHTLCTimeout), refundTx.LockTime)
	assert.Equal(t, uint32(0xfffffffe), refundTx.Inputs[0].SequenceNumber)

	// Verify no preimage is extractable (refund path has no capsule).
	_, err = ParseHTLCPreimage(refundTx.Bytes(), nil)
	assert.Error(t, err, "refund tx should not contain a capsule preimage")

	t.Logf("HTLC buyer refund round-trip OK")
}

func TestBuildSellerClaimTx_RejectsWrongCapsule(t *testing.T) {
	capsule := []byte("the-real-capsule-data!!")
	fileTxID := bytes.Repeat([]byte{0xf0}, 32) // mock file txid
	capsuleHash := method42.ComputeCapsuleHash(fileTxID, capsule)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sellerPub := sellerPriv.PubKey().Compressed()
	sellerAddr := sellerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPub,
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       50000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	// Wrong capsule — hash won't match what's in the HTLC script.
	wrongCapsule := []byte("wrong-capsule-data-here!!")

	_, err = BuildSellerClaimTx(&SellerClaimParams{
		SellerPrivKey: sellerPriv,
		FundingTxID:   make([]byte, 32),
		FundingVout:   0,
		FundingAmount: 100000,
		HTLCScript:    htlcScript,
		Capsule:       wrongCapsule,
		FileTxID:      fileTxID,
		OutputAddr:    sellerAddr,
	})
	assert.Error(t, err, "wrong capsule must be rejected")
	assert.Contains(t, err.Error(), "capsule hash mismatch")
}

func TestParseHTLCPreimage_WithHashVerification(t *testing.T) {
	capsule := []byte("secret-capsule-data-for-test!!")
	fileTxID := bytes.Repeat([]byte{0xf0}, 32) // mock file txid
	capsuleHash := method42.ComputeCapsuleHash(fileTxID, capsule)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerPub := sellerPriv.PubKey().Compressed()
	sellerAddr := sellerPriv.PubKey().Hash()

	mockTxID := sha256.Sum256([]byte("hash-verify-funding"))
	buyerPKH := buyerPriv.PubKey().Hash()
	p2pkhScript := buildTestP2PKHScript(t, buyerPKH)

	fundResult, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPub,
		CapsuleHash:  capsuleHash,
		Amount:       50000,
		Timeout:      DefaultHTLCTimeout,
		UTXOs:        []*HTLCUTXO{{TxID: mockTxID[:], Vout: 0, Amount: 100000, ScriptPubKey: p2pkhScript}},
		ChangeAddr:   buyerPKH,
		FeeRate:      1,
	})
	require.NoError(t, err)

	claimTx, err := BuildSellerClaimTx(&SellerClaimParams{
		SellerPrivKey: sellerPriv,
		FundingTxID:   fundResult.TxID,
		FundingVout:   fundResult.HTLCVout,
		FundingAmount: fundResult.HTLCAmount,
		HTLCScript:    fundResult.HTLCScript,
		Capsule:       capsule,
		FileTxID:      fileTxID,
		OutputAddr:    sellerAddr,
	})
	require.NoError(t, err)

	// ParseHTLCPreimage verifies SHA256(fileTxID ‖ preimage) against expectedCapsuleHash.
	// When fileTxID is provided, the hash includes the file identity binding.

	// Correct hash with fileTxID: should succeed.
	extracted, err := ParseHTLCPreimage(claimTx.Bytes(), capsuleHash, fileTxID)
	require.NoError(t, err)
	assert.Equal(t, capsule, extracted)

	// Wrong hash: should fail.
	wrongHash := make([]byte, 32)
	wrongHash[0] = 0xFF
	_, err = ParseHTLCPreimage(claimTx.Bytes(), wrongHash, fileTxID)
	assert.Error(t, err, "wrong capsule hash must be rejected")

	// Nil hash (backward compat): should succeed without verification.
	extracted2, err := ParseHTLCPreimage(claimTx.Bytes(), nil)
	require.NoError(t, err)
	assert.Equal(t, capsule, extracted2)
}

func TestSigSerializeAppendSafety(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	sig, err := priv.Sign(hash)
	require.NoError(t, err)

	serialized := sig.Serialize()
	originalCopy := make([]byte, len(serialized))
	copy(originalCopy, serialized)

	// Simulate what the code does: append sighash flag.
	_ = appendSighashFlag(serialized)

	// Original serialized bytes must not be mutated.
	assert.Equal(t, originalCopy, sig.Serialize(), "sig.Serialize() must not be mutated by append")
}

// --- Invoice ID Replay Protection Tests ---

func TestBuildHTLC_WithInvoiceID(t *testing.T) {
	params := validHTLCParams()
	invoiceID := bytes.Repeat([]byte{0xaa}, InvoiceIDLen)
	params.InvoiceID = invoiceID

	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)
	assert.NotEmpty(t, scriptBytes)

	// Parse and verify structure: <invoice_id_16> OP_DROP OP_IF ...
	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// First chunk should be the invoice ID push data.
	assert.Equal(t, invoiceID, chunks[0].Data, "first chunk should be invoice ID")

	// Second chunk should be OP_DROP.
	assert.Equal(t, script.OpDROP, chunks[1].Op, "second chunk should be OP_DROP")

	// Third chunk should be OP_IF (start of normal HTLC).
	assert.Equal(t, script.OpIF, chunks[2].Op, "third chunk should be OP_IF")

	// Last chunk should be OP_ENDIF.
	assert.Equal(t, script.OpENDIF, chunks[len(chunks)-1].Op)
}

func TestBuildHTLC_WithoutInvoiceID_BackwardCompatible(t *testing.T) {
	params := validHTLCParams()
	// InvoiceID is nil — legacy format.

	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// First chunk should be OP_IF directly (no prefix).
	assert.Equal(t, script.OpIF, chunks[0].Op, "legacy script should start with OP_IF")
}

func TestBuildHTLC_InvalidInvoiceIDLength(t *testing.T) {
	params := validHTLCParams()

	// Too short.
	params.InvoiceID = bytes.Repeat([]byte{0xaa}, 8)
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
	assert.Contains(t, err.Error(), "invoice ID must be 16 bytes")

	// Too long.
	params.InvoiceID = bytes.Repeat([]byte{0xaa}, 32)
	_, err = BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestExtractInvoiceIDFromHTLC(t *testing.T) {
	invoiceID := bytes.Repeat([]byte{0xbb}, InvoiceIDLen)

	t.Run("with invoice ID", func(t *testing.T) {
		params := validHTLCParams()
		params.InvoiceID = invoiceID
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err)

		extracted, err := ExtractInvoiceIDFromHTLC(scriptBytes)
		require.NoError(t, err)
		assert.Equal(t, invoiceID, extracted)
	})

	t.Run("without invoice ID (legacy)", func(t *testing.T) {
		params := validHTLCParams()
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err)

		extracted, err := ExtractInvoiceIDFromHTLC(scriptBytes)
		require.NoError(t, err)
		assert.Nil(t, extracted, "legacy script should return nil invoice ID")
	})

	t.Run("empty script", func(t *testing.T) {
		extracted, err := ExtractInvoiceIDFromHTLC([]byte{})
		require.NoError(t, err)
		assert.Nil(t, extracted)
	})
}

func TestExtractCapsuleHashFromHTLC_BothFormats(t *testing.T) {
	params := validHTLCParams()

	t.Run("legacy format", func(t *testing.T) {
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err)

		capsuleHash, err := ExtractCapsuleHashFromHTLC(scriptBytes)
		require.NoError(t, err)
		assert.Equal(t, params.CapsuleHash, capsuleHash)
	})

	t.Run("with invoice ID", func(t *testing.T) {
		params.InvoiceID = bytes.Repeat([]byte{0xcc}, InvoiceIDLen)
		scriptBytes, err := BuildHTLC(params)
		require.NoError(t, err)

		capsuleHash, err := ExtractCapsuleHashFromHTLC(scriptBytes)
		require.NoError(t, err)
		assert.Equal(t, params.CapsuleHash, capsuleHash)
	})
}

func TestHTLC_ReplayProtection_DifferentInvoiceIDs(t *testing.T) {
	params := validHTLCParams()

	// Same capsule hash but different invoice IDs -> different scripts.
	invoiceID1 := bytes.Repeat([]byte{0x01}, InvoiceIDLen)
	invoiceID2 := bytes.Repeat([]byte{0x02}, InvoiceIDLen)

	params.InvoiceID = invoiceID1
	script1, err := BuildHTLC(params)
	require.NoError(t, err)

	params.InvoiceID = invoiceID2
	script2, err := BuildHTLC(params)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(script1, script2),
		"same capsule hash + different invoice IDs must produce different scripts")

	// Verify VerifyHTLCFunding rejects wrong invoice ID.
	// Build a funding tx with script1 but try to verify against script2.
	fundingTx := transaction.NewTransaction()
	htlcLockingScript := script.Script(script1)
	fundingTx.AddOutput(&transaction.TransactionOutput{
		LockingScript: &htlcLockingScript,
		Satoshis:      1000,
	})

	// Should succeed with the correct script.
	vout, err := VerifyHTLCFunding(fundingTx.Bytes(), script1, 1000)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), vout)

	// Should fail with the wrong script (different invoice ID).
	_, err = VerifyHTLCFunding(fundingTx.Bytes(), script2, 1000)
	assert.ErrorIs(t, err, ErrNoMatchingOutput,
		"funding tx with invoice_id_1 must not match HTLC script with invoice_id_2")
}

func TestBuildHTLCFundingTx_WithInvoiceID(t *testing.T) {
	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	changeAddr := buyerPriv.PubKey().Hash()
	buyerPKH := buyerPriv.PubKey().Hash()
	p2pkhScript := buildTestP2PKHScript(t, buyerPKH)
	mockTxID := sha256.Sum256([]byte("invoice-id-funding"))
	invoiceID := bytes.Repeat([]byte{0xdd}, InvoiceIDLen)

	result, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
		UTXOs: []*HTLCUTXO{{
			TxID:         mockTxID[:],
			Vout:         0,
			Amount:       10000,
			ScriptPubKey: p2pkhScript,
		}},
		ChangeAddr: changeAddr,
		FeeRate:    1,
		InvoiceID:  invoiceID,
	})
	require.NoError(t, err)

	// Verify the HTLC script contains the invoice ID.
	extractedID, err := ExtractInvoiceIDFromHTLC(result.HTLCScript)
	require.NoError(t, err)
	assert.Equal(t, invoiceID, extractedID)

	// Verify the capsule hash is still extractable.
	extractedHash, err := ExtractCapsuleHashFromHTLC(result.HTLCScript)
	require.NoError(t, err)
	assert.Equal(t, capsuleHash, extractedHash)

	// Verify the funding tx matches the generated script.
	vout, err := VerifyHTLCFunding(result.RawTx, result.HTLCScript, 1000)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), vout)
}

func TestHTLCRoundTrip_WithInvoiceID(t *testing.T) {
	// Full lifecycle with invoice ID: fund -> verify -> claim -> extract -> verify invoice ID
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	capsule := bytes.Repeat([]byte{0xde}, 32)
	fileTxID := bytes.Repeat([]byte{0xf0}, 32)
	capsuleHash := method42.ComputeCapsuleHash(fileTxID, capsule)
	invoiceID := bytes.Repeat([]byte{0xee}, InvoiceIDLen)

	// Build HTLC with invoice ID.
	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
		InvoiceID:    invoiceID,
	})
	require.NoError(t, err)

	// Build funding tx.
	mockTxID := sha256.Sum256([]byte("round-trip-invoice-id"))
	buyerPKHScript := buildTestP2PKHScript(t, buyerAddr)

	fundingResult, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
		UTXOs: []*HTLCUTXO{{
			TxID:         mockTxID[:],
			Vout:         0,
			Amount:       100000,
			ScriptPubKey: buyerPKHScript,
		}},
		ChangeAddr: buyerAddr,
		FeeRate:    1,
		InvoiceID:  invoiceID,
	})
	require.NoError(t, err)

	// Verify funding matches.
	assert.Equal(t, htlcScript, fundingResult.HTLCScript)
	vout, err := VerifyHTLCFunding(fundingResult.RawTx, htlcScript, 1000)
	require.NoError(t, err)
	assert.Equal(t, uint32(0), vout)

	// Seller claim.
	claimTx, err := BuildSellerClaimTx(&SellerClaimParams{
		FundingTxID:   fundingResult.TxID,
		FundingVout:   fundingResult.HTLCVout,
		FundingAmount: fundingResult.HTLCAmount,
		HTLCScript:    fundingResult.HTLCScript,
		Capsule:       capsule,
		FileTxID:      fileTxID,
		SellerPrivKey: sellerPriv,
		OutputAddr:    sellerAddr,
		FeeRate:       1,
	})
	require.NoError(t, err)

	// Extract capsule from claim tx.
	extractedCapsule, err := ParseHTLCPreimage(claimTx.Bytes(), nil)
	require.NoError(t, err)
	assert.Equal(t, capsule, extractedCapsule)

	// Verify invoice ID is in the script.
	extractedID, err := ExtractInvoiceIDFromHTLC(fundingResult.HTLCScript)
	require.NoError(t, err)
	assert.Equal(t, invoiceID, extractedID)

	t.Logf("HTLC round-trip with invoice ID replay protection OK")
}

// --- HTLC Timeout Bounds Tests ---

func TestBuildHTLCFundingTx_TimeoutDefaults(t *testing.T) {
	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	mockTxID := make([]byte, 32)
	mockTxID[0] = 0x01
	buyerPKH := buyerPriv.PubKey().Hash()
	p2pkhScript := buildTestP2PKHScript(t, buyerPKH)

	baseParams := func() *HTLCFundingParams {
		return &HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerPriv.PubKey().Hash(),
			SellerPubKey: sellerPriv.PubKey().Compressed(),
			CapsuleHash:  bytes.Repeat([]byte{0xab}, 32),
			Amount:       1000,
			UTXOs: []*HTLCUTXO{{
				TxID:         mockTxID,
				Vout:         0,
				Amount:       100000,
				ScriptPubKey: p2pkhScript,
			}},
			ChangeAddr: buyerPKH,
			FeeRate:    1,
		}
	}

	t.Run("zero defaults to DefaultHTLCTimeout", func(t *testing.T) {
		params := baseParams()
		params.Timeout = 0
		result, err := BuildHTLCFundingTx(params)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("custom timeout within bounds", func(t *testing.T) {
		params := baseParams()
		params.Timeout = 100
		result, err := BuildHTLCFundingTx(params)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("minimum timeout accepted", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MinHTLCTimeout
		result, err := BuildHTLCFundingTx(params)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("maximum timeout accepted", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MaxHTLCTimeout
		result, err := BuildHTLCFundingTx(params)
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("below minimum rejected", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MinHTLCTimeout - 1
		_, err := BuildHTLCFundingTx(params)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
		assert.Contains(t, err.Error(), "below minimum")
	})

	t.Run("above maximum rejected", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MaxHTLCTimeout + 1
		_, err := BuildHTLCFundingTx(params)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}

func TestBuildSellerPreSignedRefund_TimeoutBounds(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPriv.PubKey().Compressed(),
		SellerPubKey: sellerPriv.PubKey().Compressed(),
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      DefaultHTLCTimeout,
	})
	require.NoError(t, err)

	mockTxID := make([]byte, 32)
	mockTxID[0] = 0x02

	baseParams := func() *SellerPreSignParams {
		return &SellerPreSignParams{
			FundingTxID:     mockTxID,
			FundingVout:     0,
			FundingAmount:   1000,
			HTLCScript:      htlcScript,
			SellerPrivKey:   sellerPriv,
			BuyerOutputAddr: buyerAddr,
			FeeRate:         1,
		}
	}

	t.Run("zero defaults to DefaultHTLCTimeout", func(t *testing.T) {
		params := baseParams()
		params.Timeout = 0
		result, err := BuildSellerPreSignedRefund(params)
		require.NoError(t, err)
		tx, err := transaction.NewTransactionFromBytes(result.TxBytes)
		require.NoError(t, err)
		assert.Equal(t, uint32(DefaultHTLCTimeout), tx.LockTime)
	})

	t.Run("custom timeout within bounds", func(t *testing.T) {
		params := baseParams()
		params.Timeout = 48
		result, err := BuildSellerPreSignedRefund(params)
		require.NoError(t, err)
		tx, err := transaction.NewTransactionFromBytes(result.TxBytes)
		require.NoError(t, err)
		assert.Equal(t, uint32(48), tx.LockTime)
	})

	t.Run("below minimum rejected", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MinHTLCTimeout - 1
		_, err := BuildSellerPreSignedRefund(params)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
		assert.Contains(t, err.Error(), "below minimum")
	})

	t.Run("above maximum rejected", func(t *testing.T) {
		params := baseParams()
		params.Timeout = MaxHTLCTimeout + 1
		_, err := BuildSellerPreSignedRefund(params)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidParams)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}

func TestBuildHTLC_TimeoutBounds(t *testing.T) {
	params := validHTLCParams()

	t.Run("below minimum rejected", func(t *testing.T) {
		p := *params
		p.Timeout = MinHTLCTimeout - 1
		_, err := BuildHTLC(&p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHTLCBuildFailed)
		assert.Contains(t, err.Error(), "below minimum")
	})

	t.Run("above maximum rejected", func(t *testing.T) {
		p := *params
		p.Timeout = MaxHTLCTimeout + 1
		_, err := BuildHTLC(&p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrHTLCBuildFailed)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("minimum accepted", func(t *testing.T) {
		p := *params
		p.Timeout = MinHTLCTimeout
		script, err := BuildHTLC(&p)
		require.NoError(t, err)
		assert.NotEmpty(t, script)
	})

	t.Run("maximum accepted", func(t *testing.T) {
		p := *params
		p.Timeout = MaxHTLCTimeout
		script, err := BuildHTLC(&p)
		require.NoError(t, err)
		assert.NotEmpty(t, script)
	})
}

// buildTestP2PKHScript creates a P2PKH locking script for testing.
func buildTestP2PKHScript(t *testing.T, pubKeyHash []byte) []byte {
	t.Helper()
	s := &script.Script{}
	require.NoError(t, s.AppendOpcodes(script.OpDUP))
	require.NoError(t, s.AppendOpcodes(script.OpHASH160))
	require.NoError(t, s.AppendPushData(pubKeyHash))
	require.NoError(t, s.AppendOpcodes(script.OpEQUALVERIFY))
	require.NoError(t, s.AppendOpcodes(script.OpCHECKSIG))
	return s.Bytes()
}
