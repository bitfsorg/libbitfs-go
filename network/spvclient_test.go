package network

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tongxiaofeng/libbitfs-go/spv"
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
