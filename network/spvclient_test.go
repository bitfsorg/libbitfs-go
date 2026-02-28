package network

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/spv"
)

func TestSPVClientVerifyTxConfirmed(t *testing.T) {
	// Build a valid Merkle tree with one tx.
	txHash := spv.DoubleHash([]byte("test-tx"))
	merkleRoot := txHash // single tx = root

	// Build a header containing this Merkle root.
	header := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  make([]byte, 32),
		MerkleRoot: merkleRoot,
		Timestamp:  1700000000,
		Bits:       0x207fffff,
		Nonce:      0,
		Height:     1,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	// Store header.
	store := spv.NewMemHeaderStore()
	require.NoError(t, store.PutHeader(header))

	// Use display hex (reversed byte order), matching real Bitcoin RPC convention.
	blockHash := hex.EncodeToString(reverseBytesCopy(header.Hash))
	txidHex := hex.EncodeToString(reverseBytesCopy(txHash))

	mock := &MockBlockchainService{
		GetRawTxFn: func(ctx context.Context, txid string) ([]byte, error) {
			return []byte("test-tx"), nil
		},
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*MerkleProof, error) {
			return &MerkleProof{
				TxID:      txidHex,
				BlockHash: blockHash,
				Branches:  [][]byte{}, // single tx, no branches
				Index:     0,
			}, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return spv.SerializeHeader(header), nil
		},
	}

	client := NewSPVClient(mock, store)
	result, err := client.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)
}

func TestSPVClientVerifyTxUnconfirmed(t *testing.T) {
	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: false}, nil
		},
	}

	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	result, err := client.VerifyTx(context.Background(), "sometxid")
	require.NoError(t, err)
	assert.False(t, result.Confirmed)
}

func TestSyncHeaders_RejectsDisconnectedHeader(t *testing.T) {
	// header0 is valid genesis.
	header0 := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  make([]byte, 32),
		MerkleRoot: make([]byte, 32),
		Timestamp:  1000,
		Bits:       0x207fffff,
		Nonce:      0,
		Height:     0,
	}
	header0.Hash = spv.ComputeHeaderHash(header0)

	// header1 has PrevBlock that does NOT match header0.Hash.
	badPrevBlock := make([]byte, 32)
	badPrevBlock[0] = 0xFF
	header1 := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  badPrevBlock,
		MerkleRoot: make([]byte, 32),
		Timestamp:  2000,
		Bits:       0x207fffff,
		Nonce:      0,
		Height:     1,
	}
	header1.Hash = spv.ComputeHeaderHash(header1)

	headers := []*spv.BlockHeader{header0, header1}
	hashes := []string{
		hex.EncodeToString(header0.Hash),
		hex.EncodeToString(header1.Hash),
	}

	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 1, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, blockHash string) ([]byte, error) {
			for _, h := range headers {
				if hex.EncodeToString(h.Hash) == blockHash {
					return spv.SerializeHeader(h), nil
				}
			}
			return nil, ErrTxNotFound
		},
	}

	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, height uint64) (string, error) {
		if int(height) < len(hashes) {
			return hashes[height], nil
		}
		return "", ErrTxNotFound
	}

	err := client.SyncHeaders(context.Background())
	assert.Error(t, err, "disconnected header must be rejected")
	assert.Contains(t, err.Error(), "chain break")
}

func TestSPVClientVerifyTx_GetTxStatusError(t *testing.T) {
	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return nil, fmt.Errorf("rpc timeout")
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)

	_, err := client.VerifyTx(context.Background(), "sometxid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get tx status")
}

func TestSPVClientVerifyTx_InvalidBlockHash(t *testing.T) {
	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: "zzz-not-hex", BlockHeight: 1}, nil
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)

	_, err := client.VerifyTx(context.Background(), "sometxid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block hash")
}

func TestSPVClientVerifyTx_GetBlockHeaderError(t *testing.T) {
	// Header not in store AND fetch fails.
	blockHash := hex.EncodeToString(make([]byte, 32))
	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return nil, fmt.Errorf("rpc error")
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)

	_, err := client.VerifyTx(context.Background(), "sometxid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch block header")
}

func TestSPVClientVerifyTx_GetMerkleProofError(t *testing.T) {
	txHash := spv.DoubleHash([]byte("test-tx"))
	merkleRoot := txHash

	header := &spv.BlockHeader{
		Version: 1, PrevBlock: make([]byte, 32), MerkleRoot: merkleRoot,
		Timestamp: 1700000000, Bits: 0x207fffff, Height: 1,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	store := spv.NewMemHeaderStore()
	require.NoError(t, store.PutHeader(header))

	blockHash := hex.EncodeToString(reverseBytesCopy(header.Hash))
	txidHex := hex.EncodeToString(reverseBytesCopy(txHash))

	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*MerkleProof, error) {
			return nil, fmt.Errorf("rpc error")
		},
	}
	client := NewSPVClient(mock, store)

	_, err := client.VerifyTx(context.Background(), txidHex)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch merkle proof")
}

func TestSPVClientVerifyTx_MerkleRootMismatch(t *testing.T) {
	// Single-tx block but txid doesn't match merkle root → verification failure.
	txHash := spv.DoubleHash([]byte("test-tx"))
	badRoot := spv.DoubleHash([]byte("different"))

	header := &spv.BlockHeader{
		Version: 1, PrevBlock: make([]byte, 32), MerkleRoot: badRoot,
		Timestamp: 1700000000, Bits: 0x207fffff, Height: 1,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	store := spv.NewMemHeaderStore()
	require.NoError(t, store.PutHeader(header))

	blockHash := hex.EncodeToString(reverseBytesCopy(header.Hash))
	txidHex := hex.EncodeToString(reverseBytesCopy(txHash))

	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*MerkleProof, error) {
			return &MerkleProof{TxID: txidHex, Branches: nil, Index: 0}, nil
		},
	}
	client := NewSPVClient(mock, store)

	_, err := client.VerifyTx(context.Background(), txidHex)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "merkle proof verification failed")
}

func TestSPVClientVerifyTx_MultiBranch(t *testing.T) {
	// Two-tx block — verified via branch proof.
	tx0 := spv.DoubleHash([]byte("coinbase"))
	tx1 := spv.DoubleHash([]byte("our-tx"))

	combined := make([]byte, 64)
	copy(combined[:32], tx0)
	copy(combined[32:], tx1)
	merkleRoot := spv.DoubleHash(combined)

	header := &spv.BlockHeader{
		Version: 1, PrevBlock: make([]byte, 32), MerkleRoot: merkleRoot,
		Timestamp: 1700000000, Bits: 0x207fffff, Height: 1,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	store := spv.NewMemHeaderStore()
	require.NoError(t, store.PutHeader(header))

	blockHash := hex.EncodeToString(reverseBytesCopy(header.Hash))
	txidHex := hex.EncodeToString(reverseBytesCopy(tx1))

	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*MerkleProof, error) {
			return &MerkleProof{
				TxID:     txidHex,
				Branches: [][]byte{tx0}, // sibling is tx0
				Index:    1,
			}, nil
		},
	}
	client := NewSPVClient(mock, store)

	result, err := client.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, uint64(1), result.BlockHeight)
}

func TestSPVClientVerifyTx_HeaderNotInStore_FetchAndStore(t *testing.T) {
	// Header NOT in store; client fetches, deserializes, and stores it.
	txHash := spv.DoubleHash([]byte("test-tx"))
	merkleRoot := txHash

	header := &spv.BlockHeader{
		Version: 1, PrevBlock: make([]byte, 32), MerkleRoot: merkleRoot,
		Timestamp: 1700000000, Bits: 0x207fffff, Height: 1,
	}
	header.Hash = spv.ComputeHeaderHash(header)

	store := spv.NewMemHeaderStore() // empty — no header stored

	blockHash := hex.EncodeToString(reverseBytesCopy(header.Hash))
	txidHex := hex.EncodeToString(reverseBytesCopy(txHash))

	mock := &MockBlockchainService{
		GetTxStatusFn: func(ctx context.Context, txid string) (*TxStatus, error) {
			return &TxStatus{Confirmed: true, BlockHash: blockHash, BlockHeight: 1}, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return spv.SerializeHeader(header), nil
		},
		GetMerkleProofFn: func(ctx context.Context, txid string) (*MerkleProof, error) {
			return &MerkleProof{TxID: txidHex, Branches: nil, Index: 0}, nil
		},
	}
	client := NewSPVClient(mock, store)

	result, err := client.VerifyTx(context.Background(), txidHex)
	require.NoError(t, err)
	assert.True(t, result.Confirmed)

	// Verify header was stored.
	count, _ := store.GetHeaderCount()
	assert.Equal(t, uint64(1), count)
}

func TestNewSPVClient_WithRPCClient(t *testing.T) {
	rpc := NewRPCClient(RPCConfig{URL: "http://localhost:18332"})
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(rpc, store)

	// getBlockHash should be wired up.
	assert.NotNil(t, client.getBlockHash)
}

func TestNewSPVClient_WithMock(t *testing.T) {
	mock := &MockBlockchainService{}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)

	// Mock is not an RPCClient, so getBlockHash should be nil.
	assert.Nil(t, client.getBlockHash)
}

// --- SyncHeaders error paths ---

func TestSyncHeaders_NoGetBlockHash(t *testing.T) {
	mock := &MockBlockchainService{}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	// getBlockHash is nil for mock.

	err := client.SyncHeaders(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getBlockHash not configured")
}

func TestSyncHeaders_GetBestBlockHeightError(t *testing.T) {
	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 0, fmt.Errorf("rpc timeout")
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, h uint64) (string, error) {
		return "", nil
	}

	err := client.SyncHeaders(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get best block height")
}

func TestSyncHeaders_GetBlockHashError(t *testing.T) {
	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 1, nil
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, h uint64) (string, error) {
		return "", fmt.Errorf("block not found")
	}

	err := client.SyncHeaders(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get block hash")
}

func TestSyncHeaders_GetBlockHeaderError(t *testing.T) {
	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 0, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return nil, fmt.Errorf("header fetch error")
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, h uint64) (string, error) {
		return "hash0", nil
	}

	err := client.SyncHeaders(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get header at 0")
}

func TestSyncHeaders_DeserializeError(t *testing.T) {
	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 0, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, bh string) ([]byte, error) {
			return []byte("too-short"), nil // not 80 bytes
		},
	}
	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, h uint64) (string, error) {
		return "hash0", nil
	}

	err := client.SyncHeaders(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deserialize header")
}

// --- bytesEqual tests ---

func TestBytesEqual(t *testing.T) {
	assert.True(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 3}))
	assert.False(t, bytesEqual([]byte{1, 2, 3}, []byte{1, 2, 4}))
	assert.False(t, bytesEqual([]byte{1, 2}, []byte{1, 2, 3}))
	assert.True(t, bytesEqual(nil, nil))
	assert.True(t, bytesEqual([]byte{}, []byte{}))
}

// --- Mock method tests ---

func TestMockBlockchainService_BroadcastTx(t *testing.T) {
	mock := &MockBlockchainService{
		BroadcastTxFn: func(ctx context.Context, rawTxHex string) (string, error) {
			return "txid-abc", nil
		},
	}
	txid, err := mock.BroadcastTx(context.Background(), "raw-hex")
	require.NoError(t, err)
	assert.Equal(t, "txid-abc", txid)
}

func TestMockBlockchainService_GetRawTx(t *testing.T) {
	mock := &MockBlockchainService{
		GetRawTxFn: func(ctx context.Context, txid string) ([]byte, error) {
			return []byte("raw-bytes"), nil
		},
	}
	data, err := mock.GetRawTx(context.Background(), "txid123")
	require.NoError(t, err)
	assert.Equal(t, []byte("raw-bytes"), data)
}

func TestMockBlockchainService_ImportAddress(t *testing.T) {
	// Default (nil fn) returns nil.
	mock := &MockBlockchainService{}
	err := mock.ImportAddress(context.Background(), "addr")
	require.NoError(t, err)

	// With fn set.
	mock.ImportAddressFn = func(ctx context.Context, address string) error {
		return fmt.Errorf("import error")
	}
	err = mock.ImportAddress(context.Background(), "addr")
	require.Error(t, err)
}

func TestMockBlockchainService_GetUTXO(t *testing.T) {
	mock := &MockBlockchainService{
		GetUTXOFn: func(ctx context.Context, txid string, vout uint32) (*UTXO, error) {
			return &UTXO{TxID: txid, Vout: vout, Amount: 1000}, nil
		},
	}
	utxo, err := mock.GetUTXO(context.Background(), "txid", 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(1000), utxo.Amount)
}

func TestSPVClientSyncHeaders(t *testing.T) {
	// Create a chain of 2 headers.
	genesis := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  make([]byte, 32),
		MerkleRoot: make([]byte, 32),
		Timestamp:  1000,
		Bits:       0x207fffff,
		Height:     0,
	}
	genesis.Hash = spv.ComputeHeaderHash(genesis)

	block1 := &spv.BlockHeader{
		Version:    1,
		PrevBlock:  genesis.Hash,
		MerkleRoot: make([]byte, 32),
		Timestamp:  2000,
		Bits:       0x207fffff,
		Height:     1,
	}
	block1.Hash = spv.ComputeHeaderHash(block1)

	headers := []*spv.BlockHeader{genesis, block1}
	hashes := []string{
		hex.EncodeToString(genesis.Hash),
		hex.EncodeToString(block1.Hash),
	}

	mock := &MockBlockchainService{
		GetBestBlockHeightFn: func(ctx context.Context) (uint64, error) {
			return 1, nil
		},
		GetBlockHeaderFn: func(ctx context.Context, blockHash string) ([]byte, error) {
			for _, h := range headers {
				if hex.EncodeToString(h.Hash) == blockHash {
					return spv.SerializeHeader(h), nil
				}
			}
			return nil, ErrTxNotFound
		},
	}

	store := spv.NewMemHeaderStore()
	client := NewSPVClient(mock, store)
	client.getBlockHash = func(ctx context.Context, height uint64) (string, error) {
		if int(height) < len(hashes) {
			return hashes[height], nil
		}
		return "", ErrTxNotFound
	}

	err := client.SyncHeaders(context.Background())
	require.NoError(t, err)

	count, _ := store.GetHeaderCount()
	assert.Equal(t, uint64(2), count)
}
