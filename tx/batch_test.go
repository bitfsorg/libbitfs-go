package tx

import (
	"bytes"
	"math"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMutationBatch_SingleOp(t *testing.T) {
	// Equivalent to a self-update: one op with existing UTXO.
	priv, pub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)
	payload := []byte("self-update payload data")

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     pub,
		ParentTxID: parentTxID,
		Payload:    payload,
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x11}, 32), Vout: 1, Amount: DustLimit, PrivateKey: priv},
		PrivateKey: priv,
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have exactly 1 node op result.
	require.Len(t, result.NodeOps, 1)
	assert.Equal(t, uint32(0), result.NodeOps[0].OpReturnVout)
	assert.Equal(t, uint32(1), result.NodeOps[0].NodeVout)
	assert.Equal(t, DustLimit, result.NodeOps[0].NodeUTXO.Amount)
	assert.NotNil(t, result.ChangeUTXO, "should have change with large fee input")
	assert.NotEmpty(t, result.RawTx)
}

func TestMutationBatch_ParentUpdatePlusChildCreate(t *testing.T) {
	// Two ops: parent update (has UTXO) + child create (no UTXO).
	parentPriv, parentPub := generateTestKeyPair(t)
	_, childPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)

	batch := NewMutationBatch()

	// Op 0: parent update (spending existing P_parent UTXO).
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     parentPub,
		ParentTxID: nil, // root dir has no parent
		Payload:    []byte("updated parent directory payload"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x22}, 32), Vout: 1, Amount: DustLimit},
		PrivateKey: parentPriv,
	})

	// Op 1: child create (no existing UTXO).
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpCreate,
		PubKey:     childPub,
		ParentTxID: parentTxID,
		Payload:    []byte("new child node payload"),
		InputUTXO:  nil, // new create — no existing UTXO
		PrivateKey: nil,
	})

	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	require.Len(t, result.NodeOps, 2)

	// Op 0 outputs: vout 0 (OP_RETURN), vout 1 (P2PKH).
	assert.Equal(t, uint32(0), result.NodeOps[0].OpReturnVout)
	assert.Equal(t, uint32(1), result.NodeOps[0].NodeVout)

	// Op 1 outputs: vout 2 (OP_RETURN), vout 3 (P2PKH).
	assert.Equal(t, uint32(2), result.NodeOps[1].OpReturnVout)
	assert.Equal(t, uint32(3), result.NodeOps[1].NodeVout)

	assert.NotNil(t, result.ChangeUTXO)
	assert.Equal(t, uint32(4), result.ChangeUTXO.Vout)
}

func TestMutationBatch_MultipleCreates(t *testing.T) {
	// Three child creates — none have existing UTXOs.
	parentTxID := bytes.Repeat([]byte{0xcc}, 32)

	batch := NewMutationBatch()

	for i := 0; i < 3; i++ {
		_, pub := generateTestKeyPair(t)
		batch.AddNodeOp(BatchNodeOp{
			Type:       OpCreate,
			PubKey:     pub,
			ParentTxID: parentTxID,
			Payload:    []byte("child create payload"),
		})
	}

	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xdd}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	require.Len(t, result.NodeOps, 3)

	// Verify sequential vout numbering.
	for i, nr := range result.NodeOps {
		assert.Equal(t, uint32(i*2), nr.OpReturnVout, "op %d OP_RETURN vout", i)
		assert.Equal(t, uint32(i*2+1), nr.NodeVout, "op %d P2PKH vout", i)
		assert.Equal(t, DustLimit, nr.NodeUTXO.Amount)
	}

	// Change at vout 6 (3 ops * 2 outputs = 6).
	assert.NotNil(t, result.ChangeUTXO)
	assert.Equal(t, uint32(6), result.ChangeUTXO.Vout)
}

func TestMutationBatch_NoOps_Error(t *testing.T) {
	batch := NewMutationBatch()
	batch.AddFeeInput(testFeeUTXO(t, 100000))

	_, err := batch.Build()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestMutationBatch_NoFeeInputs_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  pub,
		Payload: []byte("test payload"),
	})

	_, err := batch.Build()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMutationBatch_InsufficientFunds(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  pub,
		Payload: []byte("test payload"),
	})
	batch.AddFeeInput(testFeeUTXO(t, 1)) // way too little
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

func TestMutationBatch_NilPubKey_Error(t *testing.T) {
	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  nil,
		Payload: []byte("test"),
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMutationBatch_EmptyPayload_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  pub,
		Payload: []byte{},
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrInvalidPayload)
}

func TestMutationBatch_InvalidParentTxID_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpCreate,
		PubKey:     pub,
		ParentTxID: []byte{0x01, 0x02}, // wrong length
		Payload:    []byte("test"),
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrInvalidParentTxID)
}

func TestMutationBatch_InputUTXOWithoutPrivKey_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     pub,
		Payload:    []byte("test"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x11}, 32), Vout: 0, Amount: DustLimit},
		PrivateKey: nil, // missing
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMutationBatch_SetChangeAddr(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	changeAddr := bytes.Repeat([]byte{0xab}, 20)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  pub,
		Payload: []byte("test payload data"),
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(changeAddr)
	batch.SetFeeRate(1)

	result, err := batch.Build()
	require.NoError(t, err)
	assert.NotNil(t, result.ChangeUTXO)
}

func TestMutationBatch_ChangeUnderDust(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreate,
		PubKey:  pub,
		Payload: []byte("test payload data"),
	})

	// Calculate exact amount that leaves change below dust.
	// Use numOps=1 to match what Build() does internally.
	numOutputs := 3 // 1 OP_RETURN + 1 P2PKH + 1 potential change
	estSize := EstimateTxSize(1, numOutputs, len("test payload data"), 1)
	estFee := EstimateFee(estSize, 1)
	feeAmount := DustLimit + estFee + 1 // change = 1 sat <= dust

	batch.AddFeeInput(testFeeUTXO(t, feeAmount))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	assert.Nil(t, result.ChangeUTXO, "change below dust should be suppressed")
}

func TestMutationBatch_OpCreateRoot(t *testing.T) {
	// OpCreateRoot: no InputUTXO, produces OP_RETURN + P2PKH.
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpCreateRoot,
		PubKey:  pub,
		Payload: []byte("root-payload"),
		// No InputUTXO, no PrivateKey, no ParentTxID
	})
	batch.AddFeeInput(testFeeUTXO(t, 5000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	require.Len(t, result.NodeOps, 1)
	assert.Equal(t, uint32(0), result.NodeOps[0].OpReturnVout)
	assert.Equal(t, uint32(1), result.NodeOps[0].NodeVout)
	assert.NotNil(t, result.NodeOps[0].NodeUTXO)
}

func TestMutationBatch_OpDelete_NoRefresh(t *testing.T) {
	// OpDelete: has InputUTXO (spent), produces OP_RETURN but NO P2PKH (node dies).
	priv, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpDelete,
		PubKey:     pub,
		ParentTxID: bytes.Repeat([]byte{0xaa}, 32),
		Payload:    []byte("delete-payload"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 0, Amount: 1, PrivateKey: priv},
		PrivateKey: priv,
	})
	batch.AddFeeInput(testFeeUTXO(t, 5000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)
	require.Len(t, result.NodeOps, 1)
	assert.Equal(t, uint32(0), result.NodeOps[0].OpReturnVout)
	// DELETE: NodeUTXO should be nil (no P2PKH refresh produced).
	assert.Nil(t, result.NodeOps[0].NodeUTXO)
}

func TestMutationBatch_ParentDedup(t *testing.T) {
	// mkdir scenario: OpCreate(child) spends parent UTXO + OpUpdate(parent) refreshes it.
	// The parent UTXO should appear as ONE input, not two.
	_, childPub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xbb}, 32)

	parentUTXO := &UTXO{
		TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 1, Amount: 1,
	}

	batch := NewMutationBatch()

	// OpCreate for child — spends parent's UTXO as Metanet edge.
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpCreate,
		PubKey:     childPub,
		ParentTxID: parentTxID,
		Payload:    []byte("child-payload"),
		InputUTXO:  parentUTXO,
		PrivateKey: parentPriv,
	})

	// OpUpdate for parent — refreshes the same parent UTXO.
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     parentPub,
		ParentTxID: bytes.Repeat([]byte{0x00}, 32),
		Payload:    []byte("parent-updated-children"),
		InputUTXO:  parentUTXO, // same UTXO — should be deduped
		PrivateKey: parentPriv,
	})

	batch.AddFeeInput(testFeeUTXO(t, 5000))
	batch.SetChange(bytes.Repeat([]byte{0xee}, 20))
	result, err := batch.Build()
	require.NoError(t, err)

	// Parse the raw tx to count inputs.
	sdkTx, err := transaction.NewTransactionFromBytes(result.RawTx)
	require.NoError(t, err)

	// Should have 2 inputs (1 deduped parent + 1 fee), not 3.
	assert.Len(t, sdkTx.Inputs, 2, "parent UTXO should be deduped to one input")

	// Both ops should still produce their outputs.
	assert.Len(t, result.NodeOps, 2)
	assert.NotNil(t, result.NodeOps[0].NodeUTXO) // child P2PKH
	assert.NotNil(t, result.NodeOps[1].NodeUTXO) // parent refresh P2PKH
}

func TestMutationBatch_Sign_SingleOp(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	feePub := pub // use same key for simplicity

	nodeScript, err := BuildP2PKHScript(pub)
	require.NoError(t, err)
	feeScript, err := BuildP2PKHScript(feePub)
	require.NoError(t, err)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     pub,
		ParentTxID: bytes.Repeat([]byte{0xcc}, 32),
		Payload:    []byte("update-payload"),
		InputUTXO: &UTXO{
			TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 0, Amount: 1,
			ScriptPubKey: nodeScript, PrivateKey: priv,
		},
		PrivateKey: priv,
	})
	batch.AddFeeInput(&UTXO{
		TxID: bytes.Repeat([]byte{0x02}, 32), Vout: 0, Amount: 5000,
		ScriptPubKey: feeScript, PrivateKey: priv,
	})
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)

	txHex, err := batch.Sign(result)
	require.NoError(t, err)
	assert.NotEmpty(t, txHex)

	// TxID should be set on result and all NodeUTXOs.
	assert.NotNil(t, result.TxID)
	assert.NotNil(t, result.NodeOps[0].NodeUTXO.TxID)
}

func TestMutationBatch_Sign_MultiOp_WithDedup(t *testing.T) {
	// Two ops sharing the same InputUTXO (deduped), plus one fee input.
	_, childPub := generateTestKeyPair(t)
	parentPriv, parentPub := generateTestKeyPair(t)
	feePriv, feePub := generateTestKeyPair(t)

	parentScript, err := BuildP2PKHScript(parentPub)
	require.NoError(t, err)
	feeScript, err := BuildP2PKHScript(feePub)
	require.NoError(t, err)

	parentUTXO := &UTXO{
		TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 1, Amount: 1,
		ScriptPubKey: parentScript, PrivateKey: parentPriv,
	}

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpCreate,
		PubKey:     childPub,
		ParentTxID: bytes.Repeat([]byte{0xbb}, 32),
		Payload:    []byte("child-payload"),
		InputUTXO:  parentUTXO,
		PrivateKey: parentPriv,
	})
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     parentPub,
		ParentTxID: bytes.Repeat([]byte{0x00}, 32),
		Payload:    []byte("parent-updated"),
		InputUTXO:  parentUTXO, // same UTXO
		PrivateKey: parentPriv,
	})
	batch.AddFeeInput(&UTXO{
		TxID: bytes.Repeat([]byte{0x02}, 32), Vout: 0, Amount: 5000,
		ScriptPubKey: feeScript, PrivateKey: feePriv,
	})
	batch.SetChange(bytes.Repeat([]byte{0xff}, 20))

	result, err := batch.Build()
	require.NoError(t, err)

	txHex, err := batch.Sign(result)
	require.NoError(t, err)
	assert.NotEmpty(t, txHex)

	// Both NodeUTXOs should have TxID set.
	assert.NotNil(t, result.NodeOps[0].NodeUTXO.TxID)
	assert.NotNil(t, result.NodeOps[1].NodeUTXO.TxID)
	if result.ChangeUTXO != nil {
		assert.NotNil(t, result.ChangeUTXO.TxID)
	}
}

func TestMutationBatch_FeeInputDedup(t *testing.T) {
	// Fee input that overlaps with a node input should be deduped.
	priv, pub := generateTestKeyPair(t)
	sharedTxID := bytes.Repeat([]byte{0x01}, 32)

	nodeUTXO := &UTXO{TxID: sharedTxID, Vout: 1, Amount: 10000, PrivateKey: priv}

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     pub,
		ParentTxID: bytes.Repeat([]byte{0xaa}, 32),
		Payload:    []byte("payload"),
		InputUTXO:  nodeUTXO,
		PrivateKey: priv,
	})
	// Add the same UTXO as a fee input — should be deduped.
	batch.AddFeeInput(&UTXO{TxID: sharedTxID, Vout: 1, Amount: 10000})
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)

	sdkTx, err := transaction.NewTransactionFromBytes(result.RawTx)
	require.NoError(t, err)
	assert.Len(t, sdkTx.Inputs, 1, "overlapping fee input should be deduped to one input")
}

func TestEstimateFee_OverflowSaturation(t *testing.T) {
	// Very large size * feeRate should saturate to MaxUint64.
	result := EstimateFee(1<<62, 100)
	assert.Equal(t, uint64(math.MaxUint64), result)
}

func TestMutationBatch_MissingChangeAddr(t *testing.T) {
	// [Audit fix M-4] Any batch without change address should error when change > dust.
	t.Run("multi-op", func(t *testing.T) {
		_, pub1 := generateTestKeyPair(t)
		_, pub2 := generateTestKeyPair(t)

		batch := NewMutationBatch()
		batch.AddNodeOp(BatchNodeOp{
			Type:    OpCreate,
			PubKey:  pub1,
			Payload: []byte("payload1"),
		})
		batch.AddNodeOp(BatchNodeOp{
			Type:    OpCreate,
			PubKey:  pub2,
			Payload: []byte("payload2"),
		})
		batch.AddFeeInput(testFeeUTXO(t, 100000))

		_, err := batch.Build()
		assert.ErrorIs(t, err, ErrInvalidParams)
	})

	t.Run("single-op", func(t *testing.T) {
		_, pub := generateTestKeyPair(t)

		batch := NewMutationBatch()
		batch.AddNodeOp(BatchNodeOp{
			Type:    OpCreate,
			PubKey:  pub,
			Payload: []byte("payload"),
		})
		batch.AddFeeInput(testFeeUTXO(t, 100000))
		// No SetChange — should error now.

		_, err := batch.Build()
		assert.ErrorIs(t, err, ErrInvalidParams)
	})
}

func TestMutationBatch_ConvenienceBuilders(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	_, childPub := generateTestKeyPair(t)
	parentTxID := bytes.Repeat([]byte{0xaa}, 32)
	utxo := &UTXO{TxID: bytes.Repeat([]byte{0x01}, 32), Vout: 1, Amount: 1}

	t.Run("AddCreateChild", func(t *testing.T) {
		batch := NewMutationBatch()
		batch.AddCreateChild(childPub, parentTxID, []byte("payload"), utxo, priv)
		assert.Equal(t, 1, batch.OpCount())
	})

	t.Run("AddSelfUpdate", func(t *testing.T) {
		batch := NewMutationBatch()
		batch.AddSelfUpdate(pub, parentTxID, []byte("payload"), utxo, priv)
		assert.Equal(t, 1, batch.OpCount())
	})

	t.Run("AddDelete", func(t *testing.T) {
		batch := NewMutationBatch()
		batch.AddDelete(pub, parentTxID, []byte("payload"), utxo, priv)
		assert.Equal(t, 1, batch.OpCount())
	})

	t.Run("AddCreateRoot", func(t *testing.T) {
		batch := NewMutationBatch()
		batch.AddCreateRoot(pub, []byte("payload"))
		assert.Equal(t, 1, batch.OpCount())
	})

	t.Run("BuildWithConvenienceBuilders", func(t *testing.T) {
		batch := NewMutationBatch()
		batch.AddCreateRoot(pub, []byte("root-payload"))
		batch.AddFeeInput(testFeeUTXO(t, 5000))
		batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))
		result, err := batch.Build()
		require.NoError(t, err)
		assert.Len(t, result.NodeOps, 1)
		assert.NotNil(t, result.NodeOps[0].NodeUTXO)
	})
}

// ===========================================================================
// Audit fix tests
// ===========================================================================

// [Audit fix M-2] OpUpdate and OpDelete must have InputUTXO.
func TestMutationBatch_OpUpdateNilInputUTXO_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpUpdate,
		PubKey:  pub,
		Payload: []byte("test"),
		// InputUTXO: nil — required for OpUpdate
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrNilParam)
	assert.Contains(t, err.Error(), "OpUpdate requires InputUTXO")
}

func TestMutationBatch_OpDeleteNilInputUTXO_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    OpDelete,
		PubKey:  pub,
		Payload: []byte("test"),
		// InputUTXO: nil — required for OpDelete
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrNilParam)
	assert.Contains(t, err.Error(), "OpDelete requires InputUTXO")
}

// [Audit fix M-5] Backward compat: op.PrivateKey is copied to InputUTXO.PrivateKey.
func TestMutationBatch_PrivateKeyBackwardCompat(t *testing.T) {
	priv, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpUpdate,
		PubKey:     pub,
		Payload:    []byte("test"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x11}, 32), Vout: 0, Amount: DustLimit},
		PrivateKey: priv, // old-style: set on op, not on UTXO
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	// Build should succeed by copying PrivateKey to InputUTXO.
	result, err := batch.Build()
	require.NoError(t, err)
	require.NotNil(t, result)
}

// [Audit fix M-5] Both nil PrivateKeys should fail.
func TestMutationBatch_BothPrivateKeysNil_Error(t *testing.T) {
	_, pub := generateTestKeyPair(t)

	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:      OpUpdate,
		PubKey:    pub,
		Payload:   []byte("test"),
		InputUTXO: &UTXO{TxID: bytes.Repeat([]byte{0x11}, 32), Vout: 0, Amount: DustLimit},
		// Both PrivateKey and InputUTXO.PrivateKey are nil.
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrNilParam)
	assert.Contains(t, err.Error(), "InputUTXO has nil PrivateKey")
}

// [Audit fix M-6] MetaFlagBytes returns independent copies.
func TestMetaFlagBytes_ReturnsCopy(t *testing.T) {
	a := MetaFlagBytes()
	b := MetaFlagBytes()
	assert.Equal(t, a, b)
	// Mutate a — b should be unaffected.
	a[0] = 0xff
	assert.NotEqual(t, a, b, "MetaFlagBytes should return independent copies")
	// Verify the canonical value is not corrupted.
	assert.Equal(t, []byte{0x6d, 0x65, 0x74, 0x61}, MetaFlagBytes())
}

// [Audit fix M-3] EstimateTxSize with numOps.
func TestEstimateTxSize_MultiOps(t *testing.T) {
	// Single op
	size1 := EstimateTxSize(2, 5, 200, 1)
	// Three ops — should be larger due to extra OP_RETURN overhead.
	size3 := EstimateTxSize(2, 5, 200, 3)
	assert.Greater(t, size3, size1, "3-op estimate should be larger than 1-op")
}

// [Audit fix M-3] EstimateTxSize backward compat (no numOps arg).
func TestEstimateTxSize_BackwardCompat(t *testing.T) {
	// Old callers that don't pass numOps should still work.
	size := EstimateTxSize(1, 3, 100)
	assert.Greater(t, size, 0)
}
