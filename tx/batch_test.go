package tx

import (
	"bytes"
	"testing"

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
		Type:       BatchOpNodeUpdate,
		PubKey:     pub,
		ParentTxID: parentTxID,
		Payload:    payload,
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x11}, 32), Vout: 1, Amount: DustLimit},
		PrivateKey: priv,
	})
	batch.AddFeeInput(testFeeUTXO(t, 100000))

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
		Type:       BatchOpParentUpdate,
		PubKey:     parentPub,
		ParentTxID: nil, // root dir has no parent
		Payload:    []byte("updated parent directory payload"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x22}, 32), Vout: 1, Amount: DustLimit},
		PrivateKey: parentPriv,
	})

	// Op 1: child create (no existing UTXO).
	batch.AddNodeOp(BatchNodeOp{
		Type:       BatchOpChildCreate,
		PubKey:     childPub,
		ParentTxID: parentTxID,
		Payload:    []byte("new child node payload"),
		InputUTXO:  nil, // new create — no existing UTXO
		PrivateKey: nil,
	})

	batch.AddFeeInput(testFeeUTXO(t, 100000))

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
			Type:       BatchOpChildCreate,
			PubKey:     pub,
			ParentTxID: parentTxID,
			Payload:    []byte("child create payload"),
		})
	}

	batch.AddFeeInput(testFeeUTXO(t, 100000))

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
		Type:    BatchOpChildCreate,
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
		Type:    BatchOpChildCreate,
		PubKey:  pub,
		Payload: []byte("test payload"),
	})
	batch.AddFeeInput(testFeeUTXO(t, 10)) // way too little

	_, err := batch.Build()
	assert.ErrorIs(t, err, ErrInsufficientFunds)
}

func TestMutationBatch_NilPubKey_Error(t *testing.T) {
	batch := NewMutationBatch()
	batch.AddNodeOp(BatchNodeOp{
		Type:    BatchOpChildCreate,
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
		Type:    BatchOpChildCreate,
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
		Type:       BatchOpChildCreate,
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
		Type:       BatchOpNodeUpdate,
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
		Type:    BatchOpChildCreate,
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
		Type:    BatchOpChildCreate,
		PubKey:  pub,
		Payload: []byte("test payload data"),
	})

	// Calculate exact amount that leaves change below dust.
	numOutputs := 3 // 1 OP_RETURN + 1 P2PKH + 1 potential change
	estSize := EstimateTxSize(1, numOutputs, len("test payload data"))
	estFee := EstimateFee(estSize, 1)
	feeAmount := DustLimit + estFee + 100 // change = 100 sat < dust

	batch.AddFeeInput(testFeeUTXO(t, feeAmount))

	result, err := batch.Build()
	require.NoError(t, err)
	assert.Nil(t, result.ChangeUTXO, "change below dust should be suppressed")
}
