package vault

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/network"
	"github.com/bitfsorg/libbitfs-go/spv"
)

func TestEngineVerifyTx_Offline(t *testing.T) {
	eng := &Vault{} // no Chain, no SPV
	_, err := eng.VerifyTx(context.Background(), "sometxid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no blockchain service")
}

func TestEngineVerifyTx_Unconfirmed(t *testing.T) {
	mock := &network.MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*network.TxStatus, error) {
			return &network.TxStatus{Confirmed: false}, nil
		},
	}

	store := spv.NewMemHeaderStore()
	eng := &Vault{
		Chain: mock,
		SPV:   network.NewSPVClient(mock, store),
	}

	result, err := eng.VerifyTx(context.Background(), "sometxid")
	require.NoError(t, err)
	assert.False(t, result.Confirmed)
}

// confirmedTestSetup creates a mock chain, header store, and engine for testing
// confirmed tx verification. Returns (engine, txid display hex, block hash display hex).
func confirmedTestSetup(t *testing.T) (*Vault, string, string, *spv.BlockHeader) {
	t.Helper()
	txHash := spv.DoubleHash([]byte("test-tx"))
	merkleRoot := txHash

	header := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  make([]byte, 32),
		MerkleRoot: merkleRoot,
		Timestamp:  1700000000,
		Bits:       0x207fffff,
		Nonce:      0,
		Height:     100,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	store := spv.NewMemHeaderStore()
	require.NoError(t, store.PutHeader(header))

	blockHash := hex.EncodeToString(reverseBytes(header.Hash))
	txidHex := hex.EncodeToString(reverseBytes(txHash))

	mock := &network.MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*network.TxStatus, error) {
			return &network.TxStatus{
				Confirmed:   true,
				BlockHash:   blockHash,
				BlockHeight: 100,
			}, nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*network.MerkleProof, error) {
			return &network.MerkleProof{
				TxID:      txidHex,
				BlockHash: blockHash,
				Branches:  [][]byte{},
				Index:     0,
			}, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return spv.SerializeHeader(header), nil
		},
	}

	eng := &Vault{
		Chain: mock,
		SPV:   network.NewSPVClient(mock, store),
	}

	return eng, txidHex, blockHash, header
}

func TestEngineVerifyTx_Confirmed(t *testing.T) {
	eng, txidHex, blockHash, _ := confirmedTestSetup(t)

	result, err := eng.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, uint64(100), result.BlockHeight)
	assert.Equal(t, blockHash, result.BlockHash)
}

func TestEngineVerifyTx_ProofBackfill(t *testing.T) {
	eng, txidHex, _, _ := confirmedTestSetup(t)

	// Attach BoltStore for proof backfill.
	dir := t.TempDir()
	boltStore, err := spv.OpenBoltStore(filepath.Join(dir, "spv.db"))
	require.NoError(t, err)
	defer boltStore.Close()
	eng.SPVStore = boltStore

	// First verify — fetches from network and backfills.
	result, err := eng.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)

	// Check that the tx was stored with a proof.
	txidBytes := displayHexToInternal(txidHex)
	stored, err := boltStore.Txs().GetTx(txidBytes)
	require.NoError(t, err)
	require.NotNil(t, stored.Proof, "proof should be backfilled")
	assert.Equal(t, uint32(100), stored.BlockHeight)
}

func TestEngineVerifyTx_CachedProof(t *testing.T) {
	eng, txidHex, blockHash, _ := confirmedTestSetup(t)

	// Attach BoltStore and pre-populate with a cached proof.
	dir := t.TempDir()
	boltStore, err := spv.OpenBoltStore(filepath.Join(dir, "spv.db"))
	require.NoError(t, err)
	defer boltStore.Close()
	eng.SPVStore = boltStore

	txidBytes := displayHexToInternal(txidHex)
	blockHashBytes := displayHexToInternal(blockHash)
	preStored := &spv.StoredTx{
		TxID:        txidBytes,
		BlockHeight: 100,
		Proof: &spv.MerkleProof{
			TxID:      txidBytes,
			BlockHash: blockHashBytes,
		},
	}
	require.NoError(t, boltStore.Txs().PutTx(preStored))

	// Replace the mock with one that panics — we should NOT hit the network.
	eng.Chain = &network.MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*network.TxStatus, error) {
			t.Fatal("should not call GetTxStatus when proof is cached")
			return nil, nil
		},
	}
	eng.SPV = network.NewSPVClient(eng.Chain, spv.NewMemHeaderStore())

	result, err := eng.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, uint64(100), result.BlockHeight)
}

func TestEngineBroadcastTx_StoresTx(t *testing.T) {
	broadcastedTxID := "aabbccddee112233aabbccddee112233aabbccddee112233aabbccddee112233"
	mock := &network.MockBlockchainService{
		BroadcastTxFn: func(ctx context.Context, rawTxHex string) (string, error) {
			return broadcastedTxID, nil
		},
	}

	dir := t.TempDir()
	boltStore, err := spv.OpenBoltStore(filepath.Join(dir, "spv.db"))
	require.NoError(t, err)
	defer boltStore.Close()

	eng := &Vault{
		Chain:    mock,
		SPVStore: boltStore,
	}

	rawTxHex := hex.EncodeToString([]byte("fake-raw-tx-bytes"))
	txid, err := eng.BroadcastTx(context.Background(), rawTxHex)
	require.NoError(t, err)
	assert.Equal(t, broadcastedTxID, txid)

	// Verify the tx was stored.
	txidBytes := displayHexToInternal(txid)
	stored, err := boltStore.Txs().GetTx(txidBytes)
	require.NoError(t, err)
	assert.Equal(t, txidBytes, stored.TxID)
	assert.Equal(t, []byte("fake-raw-tx-bytes"), stored.RawTx)
	assert.Nil(t, stored.Proof, "proof should be nil (unconfirmed)")
}

func TestEngineBroadcastTx_NoStoreWhenOffline(t *testing.T) {
	// BroadcastTx without SPVStore should still work (no panic).
	mock := &network.MockBlockchainService{
		BroadcastTxFn: func(ctx context.Context, rawTxHex string) (string, error) {
			return "txid123", nil
		},
	}

	eng := &Vault{Chain: mock} // no SPVStore
	txid, err := eng.BroadcastTx(context.Background(), "aabb")
	require.NoError(t, err)
	assert.Equal(t, "txid123", txid)
}

func TestEngineInitSPV_NilChain(t *testing.T) {
	eng := &Vault{}
	err := eng.InitSPV()
	require.NoError(t, err)
	assert.Nil(t, eng.SPV)
	assert.Nil(t, eng.SPVStore)
}

func TestEngineInitSPV_WithChain(t *testing.T) {
	dir := t.TempDir()
	mock := &network.MockBlockchainService{}
	eng := &Vault{
		Chain:   mock,
		DataDir: dir,
	}

	err := eng.InitSPV()
	require.NoError(t, err)
	assert.NotNil(t, eng.SPV)
	assert.NotNil(t, eng.SPVStore)

	// Verify the database file was created.
	dbPath := filepath.Join(dir, "spv", "spv.db")
	assert.FileExists(t, dbPath)

	// Close properly.
	eng.SPVStore.Close()
}

// reverseBytes returns a reversed copy of b.
func reverseBytes(b []byte) []byte {
	c := make([]byte, len(b))
	for i, v := range b {
		c[len(b)-1-i] = v
	}
	return c
}
