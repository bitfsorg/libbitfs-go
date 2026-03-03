package metanet

import (
	"testing"

	"github.com/bitfsorg/libbitfs-go/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
