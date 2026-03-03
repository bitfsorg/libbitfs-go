package metanet

import (
	"testing"

	"github.com/bitfsorg/libbitfs-go/tx"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestOPReturnScript builds an OP_FALSE OP_RETURN script from push data.
func buildTestOPReturnScript(pushes [][]byte) []byte {
	s := &script.Script{}
	_ = s.AppendOpcodes(script.Op0, script.OpRETURN)
	for _, push := range pushes {
		_ = s.AppendPushData(push)
	}
	return *s
}

// makeDustP2PKH builds a 25-byte P2PKH script: DUP HASH160 <20 bytes> EQUALVERIFY CHECKSIG.
func makeDustP2PKH() []byte {
	s := make([]byte, 25)
	s[0] = script.OpDUP
	s[1] = script.OpHASH160
	s[2] = 0x14 // OP_DATA_20
	// bytes 3-22 are zero (hash160)
	s[23] = script.OpEQUALVERIFY
	s[24] = script.OpCHECKSIG
	return s
}

func TestParseNodeFromPushesWithOutpoint(t *testing.T) {
	// Build a minimal valid node payload.
	node := &Node{
		Version: 1,
		Type:    NodeTypeFile,
		Op:      OpCreate,
	}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pNode := make([]byte, CompressedPubKeyLen)
	pNode[0] = 0x02
	for i := 1; i < CompressedPubKeyLen; i++ {
		pNode[i] = byte(i)
	}
	pushes := [][]byte{
		tx.MetaFlagBytes(),
		pNode,
		make([]byte, TxIDLen), // parentTxID
		payload,
	}

	txID := make([]byte, TxIDLen)
	txID[0] = 0xAA

	// Parse with outpoint (TxID + Vout).
	parsed, err := ParseNodeFromPushesWithOutpoint(pushes, txID, 3)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), parsed.Vout)
	assert.Equal(t, txID, parsed.TxID)
}

func TestNode_Vout_ZeroDefault(t *testing.T) {
	// Existing ParseNodeFromPushesWithTxID sets Vout=0 (backward compat).
	node := &Node{Version: 1, Type: NodeTypeFile, Op: OpCreate}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pNode := make([]byte, CompressedPubKeyLen)
	pNode[0] = 0x02
	pushes := [][]byte{tx.MetaFlagBytes(), pNode, nil, payload}

	parsed, err := ParseNodeFromPushesWithTxID(pushes, make([]byte, TxIDLen))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), parsed.Vout)
}

func TestParseTxToNodes_MultiOp(t *testing.T) {
	// Create two node payloads.
	file1 := &Node{Version: 1, Type: NodeTypeFile, Op: OpCreate}
	file2 := &Node{Version: 1, Type: NodeTypeDir, Op: OpCreate}
	p1, err := SerializePayload(file1)
	require.NoError(t, err)
	p2, err := SerializePayload(file2)
	require.NoError(t, err)

	pNode1 := make([]byte, CompressedPubKeyLen)
	pNode1[0] = 0x02
	pNode2 := make([]byte, CompressedPubKeyLen)
	pNode2[0] = 0x03

	parentTxID := make([]byte, TxIDLen)
	parentTxID[0] = 0x11

	// Build OP_RETURN scripts for two ops (interleaved layout).
	opReturn1 := buildTestOPReturnScript([][]byte{tx.MetaFlagBytes(), pNode1, parentTxID, p1})
	opReturn2 := buildTestOPReturnScript([][]byte{tx.MetaFlagBytes(), pNode2, parentTxID, p2})
	dustScript := makeDustP2PKH()

	outputs := []tx.TxOutput{
		{Value: 0, ScriptPubKey: opReturn1},  // vout 0: OP_RETURN (file1)
		{Value: 1, ScriptPubKey: dustScript}, // vout 1: P2PKH (file1)
		{Value: 0, ScriptPubKey: opReturn2},  // vout 2: OP_RETURN (file2)
		{Value: 1, ScriptPubKey: dustScript}, // vout 3: P2PKH (file2)
	}

	txID := make([]byte, TxIDLen)
	txID[0] = 0xFF

	nodes, err := ParseTxToNodes(outputs, txID)
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	// Node 0: file, vout=1 (P2PKH position)
	assert.Equal(t, NodeTypeFile, nodes[0].Type)
	assert.Equal(t, txID, nodes[0].TxID)
	assert.Equal(t, uint32(1), nodes[0].Vout)

	// Node 1: dir, vout=3
	assert.Equal(t, NodeTypeDir, nodes[1].Type)
	assert.Equal(t, txID, nodes[1].TxID)
	assert.Equal(t, uint32(3), nodes[1].Vout)
}

func TestParseTxToNodes_DeleteOp(t *testing.T) {
	del := &Node{Version: 1, Type: NodeTypeFile, Op: OpDelete}
	p, err := SerializePayload(del)
	require.NoError(t, err)

	pNode := make([]byte, CompressedPubKeyLen)
	pNode[0] = 0x02

	opReturn := buildTestOPReturnScript([][]byte{tx.MetaFlagBytes(), pNode, nil, p})
	outputs := []tx.TxOutput{
		{Value: 0, ScriptPubKey: opReturn}, // vout 0: delete OP_RETURN, no P2PKH follows
	}
	txID := make([]byte, TxIDLen)

	nodes, err := ParseTxToNodes(outputs, txID)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, uint32(0), nodes[0].Vout) // Deletes use OP_RETURN position
	assert.Equal(t, OpDelete, nodes[0].Op)
}

func TestParseTxToNodes_Empty(t *testing.T) {
	// No OP_RETURN outputs → no nodes.
	outputs := []tx.TxOutput{
		{Value: 1000, ScriptPubKey: makeDustP2PKH()},
	}
	nodes, err := ParseTxToNodes(outputs, make([]byte, TxIDLen))
	require.NoError(t, err)
	assert.Empty(t, nodes)
}
