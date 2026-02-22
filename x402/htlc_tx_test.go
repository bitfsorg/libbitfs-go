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
	"github.com/tongxiaofeng/libbitfs/method42"
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

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey: buyerPubKey,
		SellerAddr:  sellerAddr,
		CapsuleHash: capsuleHash,
		Amount:      1000,
		Timeout:     144,
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

	sellerAddr := bytes.Repeat([]byte{0xcd}, 20)
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
			CapsuleHash:  capsuleHash,
			Amount:       1000,
			Timeout:      144,
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
		assert.GreaterOrEqual(t, result.HTLCAmount, uint64(1000))

		// Verify the funding tx with VerifyHTLCFunding.
		vout, err := VerifyHTLCFunding(result.RawTx, result.HTLCScript, 1000)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), vout)
	})

	t.Run("amount enforces dust limit", func(t *testing.T) {
		result, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			CapsuleHash:  capsuleHash,
			Amount:       100, // Below dust limit (546)
			Timeout:      144,
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
		assert.GreaterOrEqual(t, result.HTLCAmount, uint64(546))
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(nil)
		require.Error(t, err)
	})

	t.Run("no UTXOs", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			CapsuleHash:  capsuleHash,
			Amount:       1000,
			Timeout:      144,
			UTXOs:        nil,
			ChangeAddr:   changeAddr,
		})
		require.Error(t, err)
	})

	t.Run("insufficient funds", func(t *testing.T) {
		_, err := BuildHTLCFundingTx(&HTLCFundingParams{
			BuyerPrivKey: buyerPriv,
			SellerAddr:   sellerAddr,
			CapsuleHash:  capsuleHash,
			Amount:       100000,
			Timeout:      144,
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

func TestBuildSellerClaimTx(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsule := bytes.Repeat([]byte{0xde}, 32)
	capsuleHash := sha256.Sum256(capsule)
	sellerAddr := sellerPriv.PubKey().Hash()
	changeAddr := sellerPriv.PubKey().Hash()

	// Build HTLC script.
	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey: buyerPriv.PubKey().Compressed(),
		SellerAddr:  sellerAddr,
		CapsuleHash: capsuleHash[:],
		Amount:      1000,
		Timeout:     144,
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
			SellerPrivKey: sellerPriv,
			OutputAddr:    changeAddr,
			FeeRate:       1,
		})
		require.NoError(t, err)
		require.NotNil(t, claimTx)
		require.NotEmpty(t, claimTx.Bytes())

		// Verify we can extract the capsule from the claim tx.
		extracted, err := ParseHTLCPreimage(claimTx.Bytes())
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

func TestBuildBuyerRefundTx(t *testing.T) {
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	capsuleHash := bytes.Repeat([]byte{0xab}, 32)
	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey: buyerPriv.PubKey().Compressed(),
		SellerAddr:  sellerAddr,
		CapsuleHash: capsuleHash,
		Amount:      1000,
		Timeout:     144,
	})
	require.NoError(t, err)

	mockTxID := sha256.Sum256([]byte("htlc-funding-txid"))

	t.Run("valid buyer refund", func(t *testing.T) {
		refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
			FundingTxID:   mockTxID[:],
			FundingVout:   0,
			FundingAmount: 1000,
			HTLCScript:    htlcScript,
			BuyerPrivKey:  buyerPriv,
			OutputAddr:    buyerAddr,
			Locktime:      144, // exactly the timeout
			FeeRate:       1,
		})
		require.NoError(t, err)
		require.NotNil(t, refundTx)

		// Verify nLockTime is set.
		assert.Equal(t, uint32(144), refundTx.LockTime)

		// Verify the unlocking script has OP_FALSE (0x00) at end.
		chunks, err := refundTx.Inputs[0].UnlockingScript.Chunks()
		require.NoError(t, err)
		lastChunk := chunks[len(chunks)-1]
		assert.Equal(t, script.OpFALSE, lastChunk.Op)
	})

	t.Run("locktime zero rejected", func(t *testing.T) {
		_, err := BuildBuyerRefundTx(&BuyerRefundParams{
			FundingTxID:   mockTxID[:],
			FundingVout:   0,
			FundingAmount: 1000,
			HTLCScript:    htlcScript,
			BuyerPrivKey:  buyerPriv,
			OutputAddr:    buyerAddr,
			Locktime:      0,
		})
		require.Error(t, err)
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := BuildBuyerRefundTx(nil)
		require.Error(t, err)
	})
}

// TestHTLCRoundTrip tests the full HTLC lifecycle in memory:
// encrypt → invoice → build funding tx → verify funding → build claim → extract preimage → decrypt
func TestHTLCRoundTrip(t *testing.T) {
	// Generate seller and buyer keys.
	sellerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	buyerPriv, err := ec.NewPrivateKey()
	require.NoError(t, err)

	sellerAddr := sellerPriv.PubKey().Hash()
	buyerAddr := buyerPriv.PubKey().Hash()

	// --- Seller side: encrypt content and compute capsule ---
	plaintext := []byte("Top secret BitFS content for HTLC atomic swap test")

	encResult, err := method42.Encrypt(plaintext, sellerPriv, sellerPriv.PubKey(), method42.AccessPaid)
	require.NoError(t, err)

	// Capsule = ECDH(D_seller, P_seller).x (owner's shared secret).
	capsule, err := method42.ECDH(sellerPriv, sellerPriv.PubKey())
	require.NoError(t, err)

	capsuleHash := method42.ComputeCapsuleHash(capsule)

	// --- Create invoice ---
	// Use a price high enough that the claim output exceeds dust (546 sats).
	pricePerKB := uint64(50000)
	fileSize := uint64(len(plaintext))
	invoice := NewInvoice(pricePerKB, fileSize, "1SellerAddr", capsuleHash, 3600)
	require.NotNil(t, invoice)
	require.Greater(t, invoice.Price, dustLimit, "invoice price must exceed dust for claim tx")

	// --- Buyer side: build HTLC funding tx ---
	mockTxID := sha256.Sum256([]byte("buyer-utxo-txid"))
	buyerPKHScript := buildTestP2PKHScript(t, buyerPriv.PubKey().Hash())

	fundingResult, err := BuildHTLCFundingTx(&HTLCFundingParams{
		BuyerPrivKey: buyerPriv,
		SellerAddr:   sellerAddr,
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
		SellerPrivKey: sellerPriv,
		OutputAddr:    sellerAddr,
		FeeRate:       1,
	})
	require.NoError(t, err)

	// --- Buyer side: extract capsule from claim tx ---
	extractedCapsule, err := ParseHTLCPreimage(claimTx.Bytes())
	require.NoError(t, err)
	assert.Equal(t, capsule, extractedCapsule)

	// Verify hash matches.
	extractedHash := sha256.Sum256(extractedCapsule)
	assert.Equal(t, capsuleHash, extractedHash[:])

	// --- Buyer side: decrypt content ---
	decResult, err := method42.DecryptWithCapsule(encResult.Ciphertext, extractedCapsule, encResult.KeyHash)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResult.Plaintext)

	t.Logf("HTLC round-trip: encrypt -> fund -> claim -> extract -> decrypt OK (%d bytes)", len(plaintext))
}

// TestHTLCBuyerRefundRoundTrip tests the buyer refund path.
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
		CapsuleHash:  capsuleHash,
		Amount:       1000,
		Timeout:      144,
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

	// Build refund tx.
	refundTx, err := BuildBuyerRefundTx(&BuyerRefundParams{
		FundingTxID:   fundingResult.TxID,
		FundingVout:   fundingResult.HTLCVout,
		FundingAmount: fundingResult.HTLCAmount,
		HTLCScript:    fundingResult.HTLCScript,
		BuyerPrivKey:  buyerPriv,
		OutputAddr:    buyerAddr,
		Locktime:      144,
		FeeRate:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, refundTx)

	assert.Equal(t, uint32(144), refundTx.LockTime)
	assert.Equal(t, uint32(0xfffffffe), refundTx.Inputs[0].SequenceNumber)

	// Verify no preimage is extractable (refund path has no capsule).
	_, err = ParseHTLCPreimage(refundTx.Bytes())
	assert.Error(t, err, "refund tx should not contain a capsule preimage")

	t.Logf("HTLC buyer refund round-trip OK")
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
