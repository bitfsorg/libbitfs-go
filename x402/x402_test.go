package x402

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CalculatePrice Tests ---

func TestCalculatePrice(t *testing.T) {
	tests := []struct {
		name       string
		pricePerKB uint64
		fileSize   uint64
		want       uint64
	}{
		{"zero price", 0, 1024, 0},
		{"zero size", 50, 0, 0},
		{"exact 1KB", 50, 1024, 50},
		{"exact 2KB", 50, 2048, 100},
		{"partial KB rounds up", 50, 1025, 51},
		{"1 byte", 50, 1, 1},
		{"512 bytes", 100, 512, 50},
		{"large file", 10, 1048576, 10240}, // 1MB at 10 sat/KB
		{"small price large file", 1, 10240, 10},
		{"both zero", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePrice(tt.pricePerKB, tt.fileSize)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- Invoice Tests ---

func TestNewInvoice(t *testing.T) {
	capsuleHash := make([]byte, 32)
	capsuleHash[0] = 0xab

	inv := NewInvoice(50, 2048, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", capsuleHash, 3600)

	assert.NotEmpty(t, inv.ID)
	assert.Equal(t, uint64(100), inv.Price) // 50 * 2048 / 1024 = 100
	assert.Equal(t, uint64(50), inv.PricePerKB)
	assert.Equal(t, uint64(2048), inv.FileSize)
	assert.Equal(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", inv.PaymentAddr)
	assert.Equal(t, capsuleHash, inv.CapsuleHash)
	assert.Greater(t, inv.Expiry, time.Now().Unix())
	assert.LessOrEqual(t, inv.Expiry, time.Now().Unix()+3601)
}

func TestInvoice_IsExpired(t *testing.T) {
	inv := &Invoice{Expiry: time.Now().Unix() - 1}
	assert.True(t, inv.IsExpired())

	inv2 := &Invoice{Expiry: time.Now().Unix() + 3600}
	assert.False(t, inv2.IsExpired())
}

func TestNewInvoice_UniqueIDs(t *testing.T) {
	capsuleHash := make([]byte, 32)
	inv1 := NewInvoice(10, 1024, "addr1", capsuleHash, 60)
	inv2 := NewInvoice(10, 1024, "addr1", capsuleHash, 60)
	assert.NotEqual(t, inv1.ID, inv2.ID)
}

// --- PaymentHeaders Tests ---

func TestSetPaymentHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	headers := &PaymentHeaders{
		Price:      500,
		PricePerKB: 50,
		FileSize:   10240,
		InvoiceID:  "abc123",
		Expiry:     1708000000,
	}

	SetPaymentHeaders(w, headers)

	assert.Equal(t, http.StatusPaymentRequired, w.Code)
	assert.Equal(t, "500", w.Header().Get(HeaderPrice))
	assert.Equal(t, "50", w.Header().Get(HeaderPricePerKB))
	assert.Equal(t, "10240", w.Header().Get(HeaderFileSize))
	assert.Equal(t, "abc123", w.Header().Get(HeaderInvoiceID))
	assert.Equal(t, "1708000000", w.Header().Get(HeaderExpiry))
}

func TestParsePaymentHeaders_Success(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}
	resp.Header.Set(HeaderPrice, "500")
	resp.Header.Set(HeaderPricePerKB, "50")
	resp.Header.Set(HeaderFileSize, "10240")
	resp.Header.Set(HeaderInvoiceID, "abc123")
	resp.Header.Set(HeaderExpiry, "1708000000")

	headers, err := ParsePaymentHeaders(resp)
	require.NoError(t, err)
	assert.Equal(t, uint64(500), headers.Price)
	assert.Equal(t, uint64(50), headers.PricePerKB)
	assert.Equal(t, uint64(10240), headers.FileSize)
	assert.Equal(t, "abc123", headers.InvoiceID)
	assert.Equal(t, int64(1708000000), headers.Expiry)
}

func TestParsePaymentHeaders_MissingHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "missing price",
			headers: map[string]string{
				HeaderPricePerKB: "50",
				HeaderFileSize:   "10240",
				HeaderInvoiceID:  "abc",
				HeaderExpiry:     "1708000000",
			},
		},
		{
			name: "missing price per KB",
			headers: map[string]string{
				HeaderPrice:     "500",
				HeaderFileSize:  "10240",
				HeaderInvoiceID: "abc",
				HeaderExpiry:    "1708000000",
			},
		},
		{
			name: "missing file size",
			headers: map[string]string{
				HeaderPrice:      "500",
				HeaderPricePerKB: "50",
				HeaderInvoiceID:  "abc",
				HeaderExpiry:     "1708000000",
			},
		},
		{
			name: "missing invoice ID",
			headers: map[string]string{
				HeaderPrice:      "500",
				HeaderPricePerKB: "50",
				HeaderFileSize:   "10240",
				HeaderExpiry:     "1708000000",
			},
		},
		{
			name: "missing expiry",
			headers: map[string]string{
				HeaderPrice:      "500",
				HeaderPricePerKB: "50",
				HeaderFileSize:   "10240",
				HeaderInvoiceID:  "abc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			_, err := ParsePaymentHeaders(resp)
			assert.ErrorIs(t, err, ErrMissingHeaders)
		})
	}
}

func TestParsePaymentHeaders_InvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"invalid price", HeaderPrice, "not-a-number"},
		{"invalid price per KB", HeaderPricePerKB, "xyz"},
		{"invalid file size", HeaderFileSize, "abc"},
		{"invalid expiry", HeaderExpiry, "tomorrow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			resp.Header.Set(HeaderPrice, "500")
			resp.Header.Set(HeaderPricePerKB, "50")
			resp.Header.Set(HeaderFileSize, "10240")
			resp.Header.Set(HeaderInvoiceID, "abc")
			resp.Header.Set(HeaderExpiry, "1708000000")
			// Override the specific header with invalid value
			resp.Header.Set(tt.header, tt.value)

			_, err := ParsePaymentHeaders(resp)
			assert.ErrorIs(t, err, ErrMissingHeaders)
		})
	}
}

func TestPaymentHeadersFromInvoice(t *testing.T) {
	inv := &Invoice{
		ID:         "test-id",
		Price:      500,
		PricePerKB: 50,
		FileSize:   10240,
		Expiry:     1708000000,
	}

	headers := PaymentHeadersFromInvoice(inv)
	assert.Equal(t, inv.Price, headers.Price)
	assert.Equal(t, inv.PricePerKB, headers.PricePerKB)
	assert.Equal(t, inv.FileSize, headers.FileSize)
	assert.Equal(t, inv.ID, headers.InvoiceID)
	assert.Equal(t, inv.Expiry, headers.Expiry)
}

func TestSetAndParsePaymentHeaders_RoundTrip(t *testing.T) {
	original := &PaymentHeaders{
		Price:      12345,
		PricePerKB: 100,
		FileSize:   65536,
		InvoiceID:  "round-trip-test",
		Expiry:     9999999999,
	}

	w := httptest.NewRecorder()
	SetPaymentHeaders(w, original)

	resp := &http.Response{Header: w.Header()}
	parsed, err := ParsePaymentHeaders(resp)
	require.NoError(t, err)

	assert.Equal(t, original.Price, parsed.Price)
	assert.Equal(t, original.PricePerKB, parsed.PricePerKB)
	assert.Equal(t, original.FileSize, parsed.FileSize)
	assert.Equal(t, original.InvoiceID, parsed.InvoiceID)
	assert.Equal(t, original.Expiry, parsed.Expiry)
}

// --- HTLC Tests ---

func validHTLCParams() *HTLCParams {
	buyerPub := make([]byte, 33)
	buyerPub[0] = 0x02
	for i := 1; i < 33; i++ {
		buyerPub[i] = byte(i)
	}

	sellerPub := make([]byte, 33)
	sellerPub[0] = 0x03
	for i := 1; i < 33; i++ {
		sellerPub[i] = byte(i + 50)
	}

	sellerAddr := make([]byte, 20)
	for i := range sellerAddr {
		sellerAddr[i] = byte(i + 100)
	}

	capsuleHash := sha256.Sum256([]byte("test-capsule"))

	return &HTLCParams{
		BuyerPubKey:  buyerPub,
		SellerPubKey: sellerPub,
		SellerAddr:   sellerAddr,
		CapsuleHash:  capsuleHash[:],
		Amount:       1000,
		Timeout:      144,
	}
}

func TestBuildHTLC_Success(t *testing.T) {
	params := validHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)
	assert.NotEmpty(t, scriptBytes)

	// Parse the script to verify structure
	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Verify OP_IF is first
	assert.Equal(t, script.OpIF, chunks[0].Op)

	// Verify OP_SHA256 follows
	assert.Equal(t, script.OpSHA256, chunks[1].Op)

	// Verify capsule hash is pushed (chunk 2)
	assert.Equal(t, params.CapsuleHash, chunks[2].Data)

	// Verify OP_EQUALVERIFY
	assert.Equal(t, script.OpEQUALVERIFY, chunks[3].Op)

	// Find OP_ELSE
	foundElse := false
	for _, chunk := range chunks {
		if chunk.Op == script.OpELSE {
			foundElse = true
			break
		}
	}
	assert.True(t, foundElse, "OP_ELSE not found in HTLC script")

	// Find OP_CHECKMULTISIG (buyer refund path uses 2-of-2 multisig)
	foundMultisig := false
	for _, chunk := range chunks {
		if chunk.Op == script.OpCHECKMULTISIG {
			foundMultisig = true
			break
		}
	}
	assert.True(t, foundMultisig, "OP_CHECKMULTISIG not found in HTLC script")

	// Verify OP_ENDIF is last
	assert.Equal(t, script.OpENDIF, chunks[len(chunks)-1].Op)
}

func TestBuildHTLC_NilParams(t *testing.T) {
	_, err := BuildHTLC(nil)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_InvalidBuyerPubKey(t *testing.T) {
	params := validHTLCParams()
	params.BuyerPubKey = []byte{0x02, 0x01} // too short
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_InvalidSellerPubKey(t *testing.T) {
	params := validHTLCParams()
	params.SellerPubKey = []byte{0x03, 0x01} // too short
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_InvalidSellerAddr(t *testing.T) {
	params := validHTLCParams()
	params.SellerAddr = []byte{0x01, 0x02} // too short
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_InvalidCapsuleHash(t *testing.T) {
	params := validHTLCParams()
	params.CapsuleHash = []byte{0x01} // too short
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_ZeroAmount(t *testing.T) {
	params := validHTLCParams()
	params.Amount = 0
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_ZeroTimeout(t *testing.T) {
	params := validHTLCParams()
	params.Timeout = 0
	_, err := BuildHTLC(params)
	assert.ErrorIs(t, err, ErrHTLCBuildFailed)
}

func TestBuildHTLC_ContainsBuyerPubKey(t *testing.T) {
	params := validHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Find buyer pubkey in the script
	found := false
	for _, chunk := range chunks {
		if len(chunk.Data) == 33 {
			match := true
			for i := range chunk.Data {
				if chunk.Data[i] != params.BuyerPubKey[i] {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "buyer pubkey not found in HTLC script")
}


// --- ParseHTLCPreimage Tests ---

func TestParseHTLCPreimage_EmptyTx(t *testing.T) {
	_, err := ParseHTLCPreimage(nil)
	assert.ErrorIs(t, err, ErrInvalidPreimage)

	_, err = ParseHTLCPreimage([]byte{})
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

func TestParseHTLCPreimage_InvalidTx(t *testing.T) {
	_, err := ParseHTLCPreimage([]byte{0x01, 0x02, 0x03})
	assert.ErrorIs(t, err, ErrInvalidTx)
}

func TestParseHTLCPreimage_ValidTx(t *testing.T) {
	// Build a transaction with a seller-claim unlocking script
	tx := transaction.NewTransaction()

	// Create an unlocking script: <sig> <pubkey> <preimage> OP_TRUE
	unlockScript := &script.Script{}
	// Dummy signature (71 bytes typical)
	dummySig := make([]byte, 71)
	dummySig[0] = 0x30
	_ = unlockScript.AppendPushData(dummySig)
	// Dummy pubkey (33 bytes)
	dummyPub := make([]byte, 33)
	dummyPub[0] = 0x02
	_ = unlockScript.AppendPushData(dummyPub)
	// Preimage (32 bytes capsule)
	preimage := make([]byte, 32)
	preimage[0] = 0xca
	preimage[1] = 0xfe
	_ = unlockScript.AppendPushData(preimage)
	// OP_TRUE to select IF branch
	_ = unlockScript.AppendOpcodes(script.OpTRUE)

	dummyTxID := chainhash.DoubleHashH([]byte("dummy-txid"))
	input := &transaction.TransactionInput{
		SourceTXID:      &dummyTxID,
		SequenceNumber:  0xffffffff,
		UnlockingScript: unlockScript,
	}
	tx.AddInput(input)

	// Add a dummy P2PKH output
	err := tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	extracted, err := ParseHTLCPreimage(rawTx)
	require.NoError(t, err)
	assert.Equal(t, preimage, extracted)
}

// --- VerifyPayment Tests ---

func TestVerifyPayment_NilProof(t *testing.T) {
	inv := &Invoice{Expiry: time.Now().Unix() + 3600}
	err := VerifyPayment(nil, inv)
	assert.ErrorIs(t, err, ErrInvalidParams)
}

func TestVerifyPayment_NilInvoice(t *testing.T) {
	proof := &PaymentProof{RawTx: []byte{0x01}}
	err := VerifyPayment(proof, nil)
	assert.ErrorIs(t, err, ErrInvalidParams)
}

func TestVerifyPayment_ExpiredInvoice(t *testing.T) {
	inv := &Invoice{
		Expiry:      time.Now().Unix() - 1,
		PaymentAddr: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	}
	proof := &PaymentProof{RawTx: []byte{0x01}}
	err := VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrInvoiceExpired)
}

func TestVerifyPayment_EmptyRawTx(t *testing.T) {
	inv := &Invoice{
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	}
	proof := &PaymentProof{RawTx: []byte{}}
	err := VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrInvalidTx)
}

func TestVerifyPayment_InvalidRawTx(t *testing.T) {
	inv := &Invoice{
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	}
	proof := &PaymentProof{RawTx: []byte{0x01, 0x02, 0x03}}
	err := VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrInvalidTx)
}

func TestVerifyPayment_Success(t *testing.T) {
	// Create a valid P2PKH address
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	// Build a transaction that pays to this address
	tx := transaction.NewTransaction()
	err := tx.PayToAddress(addr, 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: addr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.NoError(t, err)
}

func TestVerifyPayment_InsufficientAmount(t *testing.T) {
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	tx := transaction.NewTransaction()
	err := tx.PayToAddress(addr, 500)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: addr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrInsufficientPayment)
}

func TestVerifyPayment_NoMatchingOutput(t *testing.T) {
	// Pay to a different address
	tx := transaction.NewTransaction()
	err := tx.PayToAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrNoMatchingOutput)
}

// --- Supplementary Tests: VerifyPayment Edge Cases ---

func TestVerifyPayment_InvalidInvoiceAddress(t *testing.T) {
	// Build a valid transaction so we reach the address-parsing path
	tx := transaction.NewTransaction()
	err := tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: "NOT_A_VALID_ADDRESS!!!",
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.ErrorIs(t, err, ErrInvalidParams)
	assert.Contains(t, err.Error(), "invalid invoice address")
}

func TestVerifyPayment_Overpayment(t *testing.T) {
	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	// Build a transaction that pays MORE than the invoice requires
	tx := transaction.NewTransaction()
	err := tx.PayToAddress(addr, 2000) // pays 2000, invoice only needs 1000
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: addr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.NoError(t, err, "overpayment should be accepted")
}

func TestVerifyPayment_MultipleOutputs_OneMatches(t *testing.T) {
	targetAddr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	otherAddr := "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

	// Build a transaction with multiple outputs, only one pays the target
	tx := transaction.NewTransaction()
	err := tx.PayToAddress(otherAddr, 500)
	require.NoError(t, err)
	err = tx.PayToAddress(targetAddr, 1000)
	require.NoError(t, err)
	err = tx.PayToAddress(otherAddr, 300)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: targetAddr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.NoError(t, err, "should succeed when one of multiple outputs matches")
}

func TestVerifyPayment_SkipsNonP2PKH(t *testing.T) {
	targetAddr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	tx := transaction.NewTransaction()

	// Add an OP_RETURN output (non-P2PKH) first
	opReturnScript := &script.Script{}
	_ = opReturnScript.AppendOpcodes(script.OpRETURN)
	_ = opReturnScript.AppendPushData([]byte("test data"))
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnScript,
	})

	// Then add a valid P2PKH output to the target address
	err := tx.PayToAddress(targetAddr, 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: targetAddr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.NoError(t, err, "should skip OP_RETURN output and find matching P2PKH output")
}

func TestVerifyPayment_NilLockingScript(t *testing.T) {
	targetAddr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	tx := transaction.NewTransaction()

	// Add an output with an empty locking script (non-P2PKH, will be skipped)
	emptyScript := &script.Script{}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: emptyScript,
	})

	// Then add a valid P2PKH output
	err := tx.PayToAddress(targetAddr, 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	// Verify the transaction has the empty-script output first
	parsedTx, err := transaction.NewTransactionFromBytes(rawTx)
	require.NoError(t, err)
	require.Len(t, parsedTx.Outputs, 2)
	assert.False(t, parsedTx.Outputs[0].LockingScript.IsP2PKH(), "first output should not be P2PKH")

	inv := &Invoice{
		Price:       1000,
		Expiry:      time.Now().Unix() + 3600,
		PaymentAddr: targetAddr,
	}
	proof := &PaymentProof{RawTx: rawTx}

	err = VerifyPayment(proof, inv)
	assert.NoError(t, err, "should skip empty-script output and find matching P2PKH output")
}

// --- Supplementary Tests: BuildHTLC Validation ---

func TestBuildHTLC_ContainsSellerAddr(t *testing.T) {
	params := validHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Find seller address hash (20 bytes) in the script
	found := false
	for _, chunk := range chunks {
		if len(chunk.Data) == PubKeyHashLen {
			match := true
			for i := range chunk.Data {
				if chunk.Data[i] != params.SellerAddr[i] {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "seller address hash not found in HTLC script")
}

func TestBuildHTLC_ContainsSellerPubKey(t *testing.T) {
	params := validHTLCParams()
	scriptBytes, err := BuildHTLC(params)
	require.NoError(t, err)

	s := script.NewFromBytes(scriptBytes)
	chunks, err := s.Chunks()
	require.NoError(t, err)

	// Find seller pubkey in the 2-of-2 multisig section
	found := false
	for _, chunk := range chunks {
		if len(chunk.Data) == CompressedPubKeyLen {
			match := true
			for i := range chunk.Data {
				if chunk.Data[i] != params.SellerPubKey[i] {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "seller pubkey not found in HTLC script")
}

// --- Supplementary Tests: ParseHTLCPreimage Edge Cases ---

func TestParseHTLCPreimage_NoHTLCInput(t *testing.T) {
	// Build a valid transaction with a standard P2PKH unlocking script
	// (no HTLC pattern: needs OP_TRUE as last chunk)
	tx := transaction.NewTransaction()

	// Create a standard P2PKH unlocking script: <sig> <pubkey>
	unlockScript := &script.Script{}
	dummySig := make([]byte, 71)
	dummySig[0] = 0x30
	_ = unlockScript.AppendPushData(dummySig)
	dummyPub := make([]byte, 33)
	dummyPub[0] = 0x02
	_ = unlockScript.AppendPushData(dummyPub)
	// No OP_TRUE at the end -> not an HTLC pattern

	dummyTxID := chainhash.DoubleHashH([]byte("dummy"))
	input := &transaction.TransactionInput{
		SourceTXID:      &dummyTxID,
		SequenceNumber:  0xffffffff,
		UnlockingScript: unlockScript,
	}
	tx.AddInput(input)

	err := tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 1000)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	_, err = ParseHTLCPreimage(rawTx)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
	assert.Contains(t, err.Error(), "no HTLC preimage found")
}

func TestParseHTLCPreimage_ShortUnlockingScript(t *testing.T) {
	// Build a transaction where the unlocking script has fewer than 4 chunks
	// (a standard P2PKH unlock has only 2 chunks: <sig> <pubkey>)
	tx := transaction.NewTransaction()

	unlockScript := &script.Script{}
	// Only 2 chunks: sig + pubkey
	dummySig := make([]byte, 71)
	dummySig[0] = 0x30
	_ = unlockScript.AppendPushData(dummySig)
	dummyPub := make([]byte, 33)
	dummyPub[0] = 0x02
	_ = unlockScript.AppendPushData(dummyPub)

	dummyTxID := chainhash.DoubleHashH([]byte("short-unlock"))
	input := &transaction.TransactionInput{
		SourceTXID:      &dummyTxID,
		SequenceNumber:  0xffffffff,
		UnlockingScript: unlockScript,
	}
	tx.AddInput(input)

	err := tx.PayToAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 546)
	require.NoError(t, err)

	rawTx := tx.Bytes()

	_, err = ParseHTLCPreimage(rawTx)
	assert.ErrorIs(t, err, ErrInvalidPreimage)
}

// --- Supplementary Tests: CalculatePrice Boundary ---

func TestCalculatePrice_LargeValues(t *testing.T) {
	tests := []struct {
		name       string
		pricePerKB uint64
		fileSize   uint64
		want       uint64
	}{
		{
			name:       "1 sat/KB for 1 GB",
			pricePerKB: 1,
			fileSize:   1 << 30, // 1 GiB = 1048576 KB
			want:       1 << 20, // 1048576 satoshis
		},
		{
			name:       "100 sat/KB for 100 MB",
			pricePerKB: 100,
			fileSize:   100 * 1024 * 1024, // 100 MiB = 102400 KB
			want:       100 * 102400,      // 10240000 satoshis
		},
		{
			name:       "max safe single product",
			pricePerKB: 1000,
			fileSize:   1 << 40, // 1 TiB
			want:       1000 * (1 << 30),
		},
		{
			name:       "1 sat/KB for single byte file",
			pricePerKB: 1,
			fileSize:   1, // 1 byte -> ceil(1/1024) = 1
			want:       1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePrice(tt.pricePerKB, tt.fileSize)
			assert.Equal(t, tt.want, got)
		})
	}
}
