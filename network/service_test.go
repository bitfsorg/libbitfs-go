package network

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockBlockchainService is a test double for BlockchainService.
type MockBlockchainService struct {
	ListUnspentFn        func(ctx context.Context, address string) ([]*UTXO, error)
	GetUTXOFn            func(ctx context.Context, txid string, vout uint32) (*UTXO, error)
	BroadcastTxFn        func(ctx context.Context, rawTxHex string) (string, error)
	GetRawTxFn           func(ctx context.Context, txid string) ([]byte, error)
	GetTxStatusFn        func(ctx context.Context, txid string) (*TxStatus, error)
	GetBlockHeaderFn     func(ctx context.Context, blockHash string) ([]byte, error)
	GetMerkleProofFn     func(ctx context.Context, txid string) (*MerkleProof, error)
	GetBestBlockHeightFn func(ctx context.Context) (uint64, error)
}

func (m *MockBlockchainService) ListUnspent(ctx context.Context, address string) ([]*UTXO, error) {
	return m.ListUnspentFn(ctx, address)
}
func (m *MockBlockchainService) GetUTXO(ctx context.Context, txid string, vout uint32) (*UTXO, error) {
	return m.GetUTXOFn(ctx, txid, vout)
}
func (m *MockBlockchainService) BroadcastTx(ctx context.Context, rawTxHex string) (string, error) {
	return m.BroadcastTxFn(ctx, rawTxHex)
}
func (m *MockBlockchainService) GetRawTx(ctx context.Context, txid string) ([]byte, error) {
	return m.GetRawTxFn(ctx, txid)
}
func (m *MockBlockchainService) GetTxStatus(ctx context.Context, txid string) (*TxStatus, error) {
	return m.GetTxStatusFn(ctx, txid)
}
func (m *MockBlockchainService) GetBlockHeader(ctx context.Context, blockHash string) ([]byte, error) {
	return m.GetBlockHeaderFn(ctx, blockHash)
}
func (m *MockBlockchainService) GetMerkleProof(ctx context.Context, txid string) (*MerkleProof, error) {
	return m.GetMerkleProofFn(ctx, txid)
}
func (m *MockBlockchainService) GetBestBlockHeight(ctx context.Context) (uint64, error) {
	return m.GetBestBlockHeightFn(ctx)
}

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
