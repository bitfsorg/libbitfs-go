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

func TestSignMetanetTx_Success_ViaBatch(t *testing.T) {
	// Use MutationBatch to build an unsigned tx, then sign it via batch.Sign().
	privKey, pubKey := generateTestKeyPair(t)
	feeScript, err := BuildP2PKHScript(pubKey)
	require.NoError(t, err)

	feeUTXO := &UTXO{
		TxID:         bytes.Repeat([]byte{0x01}, 32),
		Vout:         0,
		Amount:       100000,
		ScriptPubKey: feeScript,
		PrivateKey:   privKey,
	}

	batch := NewMutationBatch()
	batch.AddCreateRoot(pubKey, []byte("test metanet root payload"))
	batch.AddFeeInput(feeUTXO)

	result, err := batch.Build()
	require.NoError(t, err)
	require.NotEmpty(t, result.RawTx)

	signedHex, err := batch.Sign(result)
	require.NoError(t, err)
	assert.NotEmpty(t, signedHex)

	// Verify TxID was populated.
	assert.NotNil(t, result.TxID)
	assert.Len(t, result.TxID, TxIDLen)

	// Verify NodeUTXO got the TxID.
	require.Len(t, result.NodeOps, 1)
	assert.NotNil(t, result.NodeOps[0].NodeUTXO)
	assert.Equal(t, result.TxID, result.NodeOps[0].NodeUTXO.TxID)

	// Verify the signed hex can be parsed back.
	parsedTx, err := transaction.NewTransactionFromHex(signedHex)
	require.NoError(t, err)
	assert.Equal(t, 1, parsedTx.InputCount())
	assert.NotNil(t, parsedTx.Inputs[0].UnlockingScript)
	assert.Greater(t, len(*parsedTx.Inputs[0].UnlockingScript), 0,
		"unlocking script should be non-empty after signing")
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
