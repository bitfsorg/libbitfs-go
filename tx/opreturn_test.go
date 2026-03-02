package tx

import (
	"bytes"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestOPReturnOutput creates a TxOutput with an OP_RETURN script for testing.
func buildTestOPReturnOutput(t *testing.T, pNodeBytes []byte, parentTxID []byte, payload []byte) TxOutput {
	t.Helper()

	s := &script.Script{}
	*s = append(*s, script.Op0, script.OpRETURN)

	pushes := [][]byte{MetaFlagBytes(), pNodeBytes, parentTxID, payload}
	for _, push := range pushes {
		err := s.AppendPushData(push)
		require.NoError(t, err)
	}

	return TxOutput{
		Value:        0,
		ScriptPubKey: []byte(*s),
	}
}

// buildTestP2PKHOutput creates a TxOutput with a P2PKH script for testing.
func buildTestP2PKHOutput(t *testing.T, seed byte) TxOutput {
	t.Helper()

	// Build a fake P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
	pubKeyHash := bytes.Repeat([]byte{seed}, 20)
	s := &script.Script{}
	*s = append(*s, script.OpDUP, script.OpHASH160)
	err := s.AppendPushData(pubKeyHash)
	require.NoError(t, err)
	*s = append(*s, script.OpEQUALVERIFY, script.OpCHECKSIG)

	return TxOutput{
		Value:        DustLimit,
		ScriptPubKey: []byte(*s),
	}
}

func TestParseTxNodeOps_SingleLegacy(t *testing.T) {
	pNode := makePNode(0x02)
	parentTxID := bytes.Repeat([]byte{0xaa}, TxIDLen)
	payload := []byte("test payload")

	outputs := []TxOutput{
		buildTestOPReturnOutput(t, pNode, parentTxID, payload),
		buildTestP2PKHOutput(t, 0x02),
		{Value: 50000, ScriptPubKey: bytes.Repeat([]byte{0xff}, 25)}, // change
	}

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	require.Len(t, ops, 1)

	assert.Equal(t, pNode, ops[0].PNode)
	assert.Equal(t, parentTxID, ops[0].ParentTxID)
	assert.Equal(t, payload, ops[0].Payload)
	assert.Equal(t, uint32(0), ops[0].Vout)
	assert.Equal(t, uint32(1), ops[0].NodeVout)
}

func TestParseTxNodeOps_BatchThreeOps(t *testing.T) {
	type opData struct {
		pNode      []byte
		parentTxID []byte
		payload    []byte
	}

	testOps := []opData{
		{makePNode(0x02), bytes.Repeat([]byte{0xaa}, TxIDLen), []byte("payload-1")},
		{makePNode(0x03), bytes.Repeat([]byte{0xbb}, TxIDLen), []byte("payload-2")},
		{makePNode(0x04), nil, []byte("payload-3")}, // root node
	}

	var outputs []TxOutput
	for _, op := range testOps {
		outputs = append(outputs, buildTestOPReturnOutput(t, op.pNode, op.parentTxID, op.payload))
		outputs = append(outputs, buildTestP2PKHOutput(t, op.pNode[1]))
	}
	// Add change output at the end.
	outputs = append(outputs, TxOutput{Value: 50000, ScriptPubKey: bytes.Repeat([]byte{0xff}, 25)})

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	require.Len(t, ops, 3)

	for i, op := range ops {
		assert.Equal(t, testOps[i].pNode, op.PNode, "op %d PNode", i)
		assert.Equal(t, testOps[i].parentTxID, op.ParentTxID, "op %d ParentTxID", i)
		assert.Equal(t, testOps[i].payload, op.Payload, "op %d Payload", i)
		assert.Equal(t, uint32(i*2), op.Vout, "op %d Vout", i)
		assert.Equal(t, uint32(i*2+1), op.NodeVout, "op %d NodeVout", i)
	}
}

func TestParseTxNodeOps_OPReturnAtEnd_Delete(t *testing.T) {
	// [Audit fix M-1] OP_RETURN as the last output with no following P2PKH
	// is now treated as an OpDelete, not an error.
	pNode := makePNode(0x02)
	payload := []byte("test payload")

	outputs := []TxOutput{
		buildTestOPReturnOutput(t, pNode, nil, payload),
	}

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	require.Len(t, ops, 1)
	assert.True(t, ops[0].IsDelete, "lone OP_RETURN should be parsed as delete")
	assert.Equal(t, uint32(0), ops[0].Vout)
	assert.Equal(t, uint32(0), ops[0].NodeVout, "delete should have NodeVout=0")
	assert.Equal(t, pNode, ops[0].PNode)
	assert.Equal(t, payload, ops[0].Payload)
}

func TestParseTxNodeOps_NoOPReturn_Empty(t *testing.T) {
	outputs := []TxOutput{
		buildTestP2PKHOutput(t, 0x01),
		{Value: 50000, ScriptPubKey: bytes.Repeat([]byte{0xff}, 25)},
	}

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	assert.Empty(t, ops)
}

func TestParseTxNodeOps_EmptyOutputs(t *testing.T) {
	ops, err := ParseTxNodeOps(nil)
	require.NoError(t, err)
	assert.Empty(t, ops)
}

func TestParseTxNodeOps_NonMetanetOPReturn_Skipped(t *testing.T) {
	// An OP_RETURN that doesn't have MetaFlag should be skipped.
	s := &script.Script{}
	*s = append(*s, script.Op0, script.OpRETURN)
	_ = s.AppendPushData([]byte("not-metanet"))

	outputs := []TxOutput{
		{Value: 0, ScriptPubKey: []byte(*s)},
		buildTestP2PKHOutput(t, 0x01),
	}

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	assert.Empty(t, ops)
}

// [Audit fix M-1] OpDelete in the middle of a batch: OP_RETURN without following P2PKH.
func TestParseTxNodeOps_DeleteInMiddle(t *testing.T) {
	pNode1 := makePNode(0x02)
	pNode2 := makePNode(0x03) // delete
	pNode3 := makePNode(0x04)

	outputs := []TxOutput{
		// Op 0: create (OP_RETURN + P2PKH)
		buildTestOPReturnOutput(t, pNode1, bytes.Repeat([]byte{0xaa}, TxIDLen), []byte("payload-1")),
		buildTestP2PKHOutput(t, 0x02),
		// Op 1: delete (OP_RETURN only — next output is another OP_RETURN, not P2PKH)
		buildTestOPReturnOutput(t, pNode2, bytes.Repeat([]byte{0xbb}, TxIDLen), []byte("delete-payload")),
		// Op 2: create (OP_RETURN + P2PKH)
		buildTestOPReturnOutput(t, pNode3, bytes.Repeat([]byte{0xcc}, TxIDLen), []byte("payload-3")),
		buildTestP2PKHOutput(t, 0x04),
		// Change
		{Value: 50000, ScriptPubKey: bytes.Repeat([]byte{0xff}, 25)},
	}

	ops, err := ParseTxNodeOps(outputs)
	require.NoError(t, err)
	require.Len(t, ops, 3)

	// Op 0: create
	assert.False(t, ops[0].IsDelete)
	assert.Equal(t, uint32(0), ops[0].Vout)
	assert.Equal(t, uint32(1), ops[0].NodeVout)

	// Op 1: delete
	assert.True(t, ops[1].IsDelete)
	assert.Equal(t, uint32(2), ops[1].Vout)
	assert.Equal(t, pNode2, ops[1].PNode)

	// Op 2: create
	assert.False(t, ops[2].IsDelete)
	assert.Equal(t, uint32(3), ops[2].Vout)
	assert.Equal(t, uint32(4), ops[2].NodeVout)
}

// [Audit fix M-1] Build + Parse round-trip for a batch with OpDelete.
func TestParseTxNodeOps_BuildDeleteRoundTrip(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	_, createPub := generateTestKeyPair(t)

	batch := NewMutationBatch()

	// Op 0: create child.
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpCreate,
		PubKey:     createPub,
		ParentTxID: bytes.Repeat([]byte{0xaa}, 32),
		Payload:    []byte("create-payload"),
	})

	// Op 1: delete node.
	batch.AddNodeOp(BatchNodeOp{
		Type:       OpDelete,
		PubKey:     pub,
		ParentTxID: bytes.Repeat([]byte{0xbb}, 32),
		Payload:    []byte("delete-payload"),
		InputUTXO:  &UTXO{TxID: bytes.Repeat([]byte{0x02}, 32), Vout: 0, Amount: 1, PrivateKey: priv},
	})

	batch.AddFeeInput(testFeeUTXO(t, 100000))
	batch.SetChange(bytes.Repeat([]byte{0xcc}, 20))

	result, err := batch.Build()
	require.NoError(t, err)

	// Parse the outputs from the built transaction.
	sdkTx, err := transaction.NewTransactionFromBytes(result.RawTx)
	require.NoError(t, err)

	var txOutputs []TxOutput
	for _, out := range sdkTx.Outputs {
		txOutputs = append(txOutputs, TxOutput{
			Value:        out.Satoshis,
			ScriptPubKey: []byte(*out.LockingScript),
		})
	}

	ops, err := ParseTxNodeOps(txOutputs)
	require.NoError(t, err)
	require.Len(t, ops, 2)

	// Op 0: create (not delete).
	assert.False(t, ops[0].IsDelete)
	assert.Equal(t, []byte("create-payload"), ops[0].Payload)

	// Op 1: delete.
	assert.True(t, ops[1].IsDelete)
	assert.Equal(t, []byte("delete-payload"), ops[1].Payload)
}

// makePNode creates a fake 33-byte compressed public key for testing.
func makePNode(seed byte) []byte {
	pk := make([]byte, CompressedPubKeyLen)
	pk[0] = 0x02 // valid compressed key prefix
	for i := 1; i < CompressedPubKeyLen; i++ {
		pk[i] = seed
	}
	return pk
}
