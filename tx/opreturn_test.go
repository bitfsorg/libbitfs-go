package tx

import (
	"bytes"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestOPReturnOutput creates a TxOutput with an OP_RETURN script for testing.
func buildTestOPReturnOutput(t *testing.T, pNodeBytes []byte, parentTxID []byte, payload []byte) TxOutput {
	t.Helper()

	s := &script.Script{}
	*s = append(*s, script.Op0, script.OpRETURN)

	pushes := [][]byte{MetaFlagBytes, pNodeBytes, parentTxID, payload}
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

func TestParseTxNodeOps_OPReturnAtEnd_Error(t *testing.T) {
	pNode := makePNode(0x02)
	payload := []byte("test payload")

	// OP_RETURN as the last output with no following P2PKH.
	outputs := []TxOutput{
		buildTestOPReturnOutput(t, pNode, nil, payload),
	}

	_, err := ParseTxNodeOps(outputs)
	assert.ErrorIs(t, err, ErrInvalidOPReturn)
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

// makePNode creates a fake 33-byte compressed public key for testing.
func makePNode(seed byte) []byte {
	pk := make([]byte, CompressedPubKeyLen)
	pk[0] = 0x02 // valid compressed key prefix
	for i := 1; i < CompressedPubKeyLen; i++ {
		pk[i] = seed
	}
	return pk
}
