package tx

import (
	"bytes"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- BuildP2PKHScript tests ---

func TestBuildP2PKHScript(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)

	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, scriptBytes)
	// P2PKH script is exactly 25 bytes:
	// OP_DUP(1) + OP_HASH160(1) + OP_DATA_20(1) + hash(20) + OP_EQUALVERIFY(1) + OP_CHECKSIG(1)
	assert.Len(t, scriptBytes, 25)
}

func TestBuildP2PKHScript_NilKey(t *testing.T) {
	_, err := BuildP2PKHScript(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- SignMetanetTx tests ---

func TestSignMetanetTx_NilMetanetTx(t *testing.T) {
	_, err := SignMetanetTx(nil, []*UTXO{{}})
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestSignMetanetTx_EmptyRawTx(t *testing.T) {
	mtx := &MetanetTx{RawTx: nil}
	_, err := SignMetanetTx(mtx, []*UTXO{{}})
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestSignMetanetTx_EmptyUTXOs(t *testing.T) {
	mtx := &MetanetTx{RawTx: []byte{0x01}}
	_, err := SignMetanetTx(mtx, nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestSignMetanetTx_NilUTXOElement(t *testing.T) {
	// Build a minimal valid unsigned transaction.
	privKey, pubKey := generateTestKeyPair(t)
	rawTx := buildTestUnsignedTx(t, privKey, pubKey)

	mtx := &MetanetTx{
		RawTx: rawTx,
		NodeUTXO: &UTXO{
			Vout:   1,
			Amount: DustLimit,
		},
	}

	_, err := SignMetanetTx(mtx, []*UTXO{nil})
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestSignMetanetTx_NilPrivateKey(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	rawTx := buildTestUnsignedTx(t, privKey, pubKey)

	mtx := &MetanetTx{RawTx: rawTx}
	utxo := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: scriptBytes,
		PrivateKey:   nil, // missing key
	}

	_, err = SignMetanetTx(mtx, []*UTXO{utxo})
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestSignMetanetTx_EmptyScriptPubKey(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	rawTx := buildTestUnsignedTx(t, privKey, pubKey)

	mtx := &MetanetTx{RawTx: rawTx}
	utxo := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: nil, // empty
		PrivateKey:   privKey,
	}

	_, err := SignMetanetTx(mtx, []*UTXO{utxo})
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestSignMetanetTx_InputCountMismatch(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	rawTx := buildTestUnsignedTx(t, privKey, pubKey)

	mtx := &MetanetTx{RawTx: rawTx}

	// Provide 2 UTXOs for a tx with 1 input.
	utxo1 := &UTXO{
		TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 0,
		Amount: 100000, ScriptPubKey: scriptBytes, PrivateKey: privKey,
	}
	utxo2 := &UTXO{
		TxID: bytes.Repeat([]byte{0x02}, 32), Vout: 0,
		Amount: 50000, ScriptPubKey: scriptBytes, PrivateKey: privKey,
	}

	_, err = SignMetanetTx(mtx, []*UTXO{utxo1, utxo2})
	assert.ErrorIs(t, err, ErrSigningFailed)
}

func TestSignMetanetTx_Success(t *testing.T) {
	// 1. Generate a random key pair.
	privKey, pubKey := generateTestKeyPair(t)

	// 2. Create a P2PKH locking script from the pubkey.
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	// 3. Create a mock UTXO with that script and key.
	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: scriptBytes,
		PrivateKey:   privKey,
	}

	// 4. Build an unsigned transaction (using BuildUnsignedCreateRootTx).
	payload := []byte("test metanet root payload")
	mtx, err := BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    payload,
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	})
	require.NoError(t, err)
	require.NotNil(t, mtx)
	require.NotEmpty(t, mtx.RawTx, "BuildUnsignedCreateRootTx should populate RawTx")

	unsignedLen := len(mtx.RawTx)

	// 5. Sign the transaction.
	signedHex, err := SignMetanetTx(mtx, []*UTXO{feeUTXO})
	require.NoError(t, err)

	// 6. Verify the signed hex is non-empty and larger than the unsigned raw tx.
	assert.NotEmpty(t, signedHex)
	assert.Greater(t, len(mtx.RawTx), unsignedLen,
		"signed tx should be larger than unsigned tx due to unlocking scripts")

	// Verify TxID was populated.
	assert.NotNil(t, mtx.TxID)
	assert.Len(t, mtx.TxID, TxIDLen)

	// Verify NodeUTXO got the TxID.
	assert.Equal(t, mtx.TxID, mtx.NodeUTXO.TxID)

	// Verify the signed hex can be parsed back.
	parsedTx, err := transaction.NewTransactionFromHex(signedHex)
	require.NoError(t, err)
	assert.Equal(t, 1, parsedTx.InputCount())
	assert.NotNil(t, parsedTx.Inputs[0].UnlockingScript)
	assert.Greater(t, len(*parsedTx.Inputs[0].UnlockingScript), 0,
		"unlocking script should be non-empty after signing")
}

func TestSignMetanetTx_UpdatesOutputUTXOs(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: scriptBytes,
		PrivateKey:   privKey,
	}

	mtx, err := BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    []byte("update utxo test payload"),
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	})
	require.NoError(t, err)

	_, err = SignMetanetTx(mtx, []*UTXO{feeUTXO})
	require.NoError(t, err)

	// NodeUTXO should have TxID set.
	require.NotNil(t, mtx.NodeUTXO)
	assert.Equal(t, mtx.TxID, mtx.NodeUTXO.TxID)
	assert.Equal(t, uint32(1), mtx.NodeUTXO.Vout)
	assert.Equal(t, DustLimit, mtx.NodeUTXO.Amount)

	// ChangeUTXO should have TxID set (100000 is large enough for change).
	if mtx.ChangeUTXO != nil {
		assert.Equal(t, mtx.TxID, mtx.ChangeUTXO.TxID)
		assert.Equal(t, uint32(2), mtx.ChangeUTXO.Vout)
	}
}

func TestSignMetanetTx_InvalidRawTx(t *testing.T) {
	mtx := &MetanetTx{RawTx: []byte{0xff, 0xfe, 0xfd}}
	utxo := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: bytes.Repeat([]byte{0x76}, 25),
		PrivateKey:   func() *ec.PrivateKey { k, _ := ec.NewPrivateKey(); return k }(),
	}

	_, err := SignMetanetTx(mtx, []*UTXO{utxo})
	assert.ErrorIs(t, err, ErrSigningFailed)
}

// --- BuildUnsignedCreateRootTx tests ---

func TestBuildUnsignedCreateRootTx(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: scriptBytes,
	}

	mtx, err := BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    []byte("test payload for unsigned root"),
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	})
	require.NoError(t, err)
	assert.NotNil(t, mtx)
	assert.NotEmpty(t, mtx.RawTx)

	// Parse and verify the transaction structure.
	sdkTx, err := transaction.NewTransactionFromBytes(mtx.RawTx)
	require.NoError(t, err)
	assert.Equal(t, 1, sdkTx.InputCount(), "root tx should have 1 input")
	assert.GreaterOrEqual(t, sdkTx.OutputCount(), 2,
		"root tx should have at least 2 outputs (OP_RETURN + P_node)")
}

func TestBuildUnsignedCreateRootTx_WithChangeAddr(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	_, changePub := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	// Use the change pubkey's hash160 as ChangeAddr.
	changeAddr := changePub.Hash()

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: scriptBytes,
	}

	mtx, err := BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    []byte("test payload with change addr"),
		FeeUTXO:    feeUTXO,
		ChangeAddr: changeAddr,
		FeeRate:    1,
	})
	require.NoError(t, err)
	assert.NotNil(t, mtx)
	assert.NotNil(t, mtx.ChangeUTXO, "should have change output with large fee UTXO")

	// Parse and verify 3 outputs (OP_RETURN + P_node + change).
	sdkTx, err := transaction.NewTransactionFromBytes(mtx.RawTx)
	require.NoError(t, err)
	assert.Equal(t, 3, sdkTx.OutputCount(), "root tx with change should have 3 outputs")
}

func TestBuildUnsignedCreateRootTx_NilParams(t *testing.T) {
	_, err := BuildUnsignedCreateRootTx(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBuildUnsignedCreateRootTx_InsufficientFunds(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       1, // too little
		ScriptPubKey: scriptBytes,
	}

	_, err = BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    []byte("test payload"),
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	})
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

// --- End-to-end: Build + Sign round trip ---

func TestSignMetanetTx_E2E_RoundTrip(t *testing.T) {
	// Full end-to-end: generate keys, build unsigned tx, sign, verify.
	privKey, pubKey := generateTestKeyPair(t)
	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0xab}, 32),
		Vout:         0,
		Amount:       50000,
		ScriptPubKey: scriptBytes,
		PrivateKey:   privKey,
	}

	// Build unsigned.
	mtx, err := BuildUnsignedCreateRootTx(&CreateRootParams{
		NodePubKey: pubKey,
		Payload:    []byte("e2e round trip test payload data"),
		FeeUTXO:    feeUTXO,
		FeeRate:    1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, mtx.RawTx)

	// Sign.
	hexStr, err := SignMetanetTx(mtx, []*UTXO{feeUTXO})
	require.NoError(t, err)
	assert.NotEmpty(t, hexStr)

	// Parse the signed transaction and verify structure.
	signedTx, err := transaction.NewTransactionFromHex(hexStr)
	require.NoError(t, err)

	// Version should be 1.
	assert.Equal(t, uint32(1), signedTx.Version)

	// Should have 1 input with an unlocking script.
	require.Equal(t, 1, signedTx.InputCount())
	assert.NotNil(t, signedTx.Inputs[0].UnlockingScript)
	assert.Greater(t, len(*signedTx.Inputs[0].UnlockingScript), 0)

	// Output 0 should be OP_RETURN (data output).
	assert.True(t, signedTx.Outputs[0].LockingScript.IsData(),
		"output 0 should be OP_RETURN data")
	assert.Equal(t, uint64(0), signedTx.Outputs[0].Satoshis,
		"OP_RETURN output should have 0 satoshis")

	// Output 1 should be P_node dust output.
	assert.Equal(t, DustLimit, signedTx.Outputs[1].Satoshis,
		"output 1 should be dust limit for P_node")
}

// --- buildOPReturnScript tests ---

func TestBuildOPReturnScript(t *testing.T) {
	pushes := [][]byte{
		MetaFlagBytes,
		bytes.Repeat([]byte{0x02}, CompressedPubKeyLen),
		{}, // empty parent TxID (root)
		[]byte("test payload"),
	}

	s, err := buildOPReturnScript(pushes)
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.True(t, s.IsData(), "should be a data (OP_RETURN) script")
}

// --- Helper ---

// buildTestUnsignedTx constructs a minimal unsigned transaction for testing.
// It creates a single-input, single-output transaction.
func buildTestUnsignedTx(t *testing.T, privKey *ec.PrivateKey, pubKey *ec.PublicKey) []byte {
	t.Helper()

	scriptBytes, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	sdkTx := transaction.NewTransaction()

	// Add a dummy input.
	fakeTxID := bytes.Repeat([]byte{0x01}, 32)
	sdkTx.AddInputWithOutput(
		&transaction.TransactionInput{
			SourceTXID:       func() *chainhash.Hash { h, _ := chainhash.NewHash(fakeTxID); return h }(),
			SourceTxOutIndex: 0,
			SequenceNumber:   transaction.DefaultSequenceNumber,
		},
		&transaction.TransactionOutput{
			Satoshis:      100000,
			LockingScript: script.NewFromBytes(scriptBytes),
		},
	)

	// Add a P2PKH output.
	addr, err := script.NewAddressFromPublicKey(pubKey, true)
	require.NoError(t, err)
	lockScript, err := p2pkh.Lock(addr)
	require.NoError(t, err)
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: lockScript,
	})

	return sdkTx.Bytes()
}
