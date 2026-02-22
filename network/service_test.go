package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockImplementsInterface(t *testing.T) {
	var _ BlockchainService = (*MockBlockchainService)(nil)
}

func TestUTXOAmountSatoshis(t *testing.T) {
	u := &UTXO{
		TxID:   "abc123",
		Vout:   0,
		Amount: 100000,
	}
	assert.Equal(t, uint64(100000), u.Amount)
	assert.Equal(t, "abc123", u.TxID)
}

func TestTxStatusConfirmed(t *testing.T) {
	s := &TxStatus{Confirmed: true, BlockHeight: 100, TxIndex: 3}
	assert.True(t, s.Confirmed)
	assert.Equal(t, uint64(100), s.BlockHeight)
	assert.Equal(t, 3, s.TxIndex)
}

func TestMerkleProofFields(t *testing.T) {
	p := &MerkleProof{
		TxID:      "deadbeef",
		BlockHash: "cafebabe",
		Branches:  [][]byte{{0x01}, {0x02}},
		Index:     5,
	}
	assert.Len(t, p.Branches, 2)
	assert.Equal(t, 5, p.Index)
}
