package metanet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOutpointStore implements both NodeStore and OutpointStore.
type mockOutpointStore struct {
	nodes []*Node
}

func (m *mockOutpointStore) GetNodeByPubKey(pNode []byte) (*Node, error) {
	for _, n := range m.nodes {
		if len(n.PNode) > 0 && len(pNode) > 0 && n.PNode[0] == pNode[0] {
			return n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (m *mockOutpointStore) GetNodeByTxID(txID []byte) (*Node, error) {
	for _, n := range m.nodes {
		if len(n.TxID) > 0 && len(txID) > 0 && n.TxID[0] == txID[0] {
			return n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func (m *mockOutpointStore) GetNodeVersions(_ []byte) ([]*Node, error) { return nil, nil }
func (m *mockOutpointStore) GetChildNodes(_ *Node) ([]*Node, error)    { return nil, nil }

func (m *mockOutpointStore) GetNodeByOutpoint(txID []byte, vout uint32) (*Node, error) {
	for _, n := range m.nodes {
		if len(n.TxID) > 0 && len(txID) > 0 && n.TxID[0] == txID[0] && n.Vout == vout {
			return n, nil
		}
	}
	return nil, ErrNodeNotFound
}

func TestOutpointStore_Interface(t *testing.T) {
	txID := make([]byte, 32)
	txID[0] = 0xBB

	store := &mockOutpointStore{
		nodes: []*Node{
			{TxID: txID, Vout: 1, PNode: []byte{0x02}},
			{TxID: txID, Vout: 3, PNode: []byte{0x03}},
		},
	}

	// Verify it satisfies both interfaces.
	var _ NodeStore = store
	var _ OutpointStore = store

	// GetNodeByOutpoint distinguishes by vout.
	n1, err := store.GetNodeByOutpoint(txID, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), n1.Vout)
	assert.Equal(t, byte(0x02), n1.PNode[0])

	n3, err := store.GetNodeByOutpoint(txID, 3)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), n3.Vout)
	assert.Equal(t, byte(0x03), n3.PNode[0])

	// Non-existent vout returns error.
	_, err = store.GetNodeByOutpoint(txID, 99)
	assert.ErrorIs(t, err, ErrNodeNotFound)
}
