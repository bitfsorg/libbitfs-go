package network

import "context"

// MockBlockchainService is a test double for BlockchainService.
// All function fields must be set before the corresponding method is called.
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
