package spv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tempBoltStore(t *testing.T) *BoltStore {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenBoltStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func testHeader(height uint32) *BlockHeader {
	h := &BlockHeader{
		Version:    1,
		PrevBlock:  make([]byte, HashSize),
		MerkleRoot: make([]byte, HashSize),
		Timestamp:  1700000000 + height,
		Bits:       0x207fffff,
		Nonce:      height,
		Height:     height,
	}
	h.Hash = ComputeHeaderHash(h)
	return h
}

func testTx(seed byte) *StoredTx {
	txid := DoubleHash([]byte{seed})
	return &StoredTx{
		TxID:        txid,
		RawTx:       []byte{seed, seed + 1, seed + 2},
		BlockHeight: uint32(seed),
		Timestamp:   uint64(seed) * 1000,
	}
}

// ---------------------------------------------------------------------------
// HeaderStore tests
// ---------------------------------------------------------------------------

func TestBoltHeaderStore_PutAndGet(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	h := testHeader(100)
	require.NoError(t, headers.PutHeader(h))

	got, err := headers.GetHeader(h.Hash)
	require.NoError(t, err)
	assert.Equal(t, h.Height, got.Height)
	assert.Equal(t, h.Hash, got.Hash)
	assert.Equal(t, h.MerkleRoot, got.MerkleRoot)
	assert.Equal(t, h.PrevBlock, got.PrevBlock)
	assert.Equal(t, h.Timestamp, got.Timestamp)
}

func TestBoltHeaderStore_GetByHeight(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	h := testHeader(42)
	require.NoError(t, headers.PutHeader(h))

	got, err := headers.GetHeaderByHeight(42)
	require.NoError(t, err)
	assert.Equal(t, h.Hash, got.Hash)
}

func TestBoltHeaderStore_GetTip(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	// Empty store.
	_, err := headers.GetTip()
	assert.ErrorIs(t, err, ErrHeaderNotFound)

	// Add headers in non-sequential order.
	h1 := testHeader(5)
	h2 := testHeader(10)
	h3 := testHeader(3)
	require.NoError(t, headers.PutHeader(h1))
	require.NoError(t, headers.PutHeader(h2))
	require.NoError(t, headers.PutHeader(h3))

	tip, err := headers.GetTip()
	require.NoError(t, err)
	assert.Equal(t, uint32(10), tip.Height, "tip should be highest stored height")
}

func TestBoltHeaderStore_GetHeaderCount(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	count, err := headers.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	require.NoError(t, headers.PutHeader(testHeader(1)))
	require.NoError(t, headers.PutHeader(testHeader(2)))

	count, err = headers.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), count)
}

func TestBoltHeaderStore_DuplicateHeader(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	h := testHeader(1)
	require.NoError(t, headers.PutHeader(h))
	err := headers.PutHeader(h)
	assert.ErrorIs(t, err, ErrDuplicateHeader)
}

func TestBoltHeaderStore_NotFound(t *testing.T) {
	store := tempBoltStore(t)
	headers := store.Headers()

	_, err := headers.GetHeader(make([]byte, HashSize))
	assert.ErrorIs(t, err, ErrHeaderNotFound)

	_, err = headers.GetHeaderByHeight(999)
	assert.ErrorIs(t, err, ErrHeaderNotFound)
}

func TestBoltHeaderStore_NilHeader(t *testing.T) {
	store := tempBoltStore(t)
	err := store.Headers().PutHeader(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBoltHeaderStore_InvalidHashLength(t *testing.T) {
	store := tempBoltStore(t)
	_, err := store.Headers().GetHeader([]byte{1, 2, 3})
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

func TestBoltHeaderStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")

	// Write a header.
	store1, err := OpenBoltStore(dbPath)
	require.NoError(t, err)
	h := testHeader(7)
	require.NoError(t, store1.Headers().PutHeader(h))
	store1.Close()

	// Reopen and read.
	store2, err := OpenBoltStore(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	got, err := store2.Headers().GetHeader(h.Hash)
	require.NoError(t, err)
	assert.Equal(t, h.Height, got.Height)
}

// ---------------------------------------------------------------------------
// TxStore tests
// ---------------------------------------------------------------------------

func TestBoltTxStore_PutAndGet(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	tx := testTx(1)
	require.NoError(t, txs.PutTx(tx))

	got, err := txs.GetTx(tx.TxID)
	require.NoError(t, err)
	assert.Equal(t, tx.TxID, got.TxID)
	assert.Equal(t, tx.RawTx, got.RawTx)
	assert.Equal(t, tx.BlockHeight, got.BlockHeight)
}

func TestBoltTxStore_DuplicateTx(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	tx := testTx(2)
	require.NoError(t, txs.PutTx(tx))
	err := txs.PutTx(tx)
	assert.ErrorIs(t, err, ErrDuplicateTx)
}

func TestBoltTxStore_NotFound(t *testing.T) {
	store := tempBoltStore(t)
	_, err := store.Txs().GetTx(make([]byte, HashSize))
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestBoltTxStore_Delete(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	tx := testTx(3)
	require.NoError(t, txs.PutTx(tx))
	require.NoError(t, txs.DeleteTx(tx.TxID))

	_, err := txs.GetTx(tx.TxID)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestBoltTxStore_DeleteNotFound(t *testing.T) {
	store := tempBoltStore(t)
	err := store.Txs().DeleteTx(make([]byte, HashSize))
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestBoltTxStore_ListTxs(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	tx1 := testTx(10)
	tx2 := testTx(20)
	require.NoError(t, txs.PutTx(tx1))
	require.NoError(t, txs.PutTx(tx2))

	all, err := txs.ListTxs()
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestBoltTxStore_PutTxWithPubKey(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	pNode := DoubleHash([]byte("pubkey1"))
	tx1 := testTx(30)
	tx2 := testTx(31)
	tx3 := testTx(32) // different pubkey

	require.NoError(t, txs.PutTxWithPubKey(tx1, pNode))
	require.NoError(t, txs.PutTxWithPubKey(tx2, pNode))

	otherPNode := DoubleHash([]byte("pubkey2"))
	require.NoError(t, txs.PutTxWithPubKey(tx3, otherPNode))

	// Query by first pubkey.
	got, err := txs.GetTxsByPubKey(pNode)
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// Query by second pubkey.
	got2, err := txs.GetTxsByPubKey(otherPNode)
	require.NoError(t, err)
	assert.Len(t, got2, 1)
	assert.Equal(t, tx3.TxID, got2[0].TxID)
}

func TestBoltTxStore_GetTxsByPubKey_Empty(t *testing.T) {
	store := tempBoltStore(t)
	pNode := DoubleHash([]byte("nobody"))
	got, err := store.Txs().GetTxsByPubKey(pNode)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestBoltTxStore_UpdateTx(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	tx := testTx(50)
	require.NoError(t, txs.PutTx(tx))

	// Backfill proof.
	proof := &MerkleProof{
		TxID:      tx.TxID,
		Index:     3,
		Nodes:     [][]byte{make([]byte, 32), make([]byte, 32)},
		BlockHash: make([]byte, 32),
	}
	tx.Proof = proof
	tx.BlockHeight = 100
	require.NoError(t, txs.UpdateTx(tx))

	got, err := txs.GetTx(tx.TxID)
	require.NoError(t, err)
	require.NotNil(t, got.Proof)
	assert.Equal(t, uint32(3), got.Proof.Index)
	assert.Equal(t, uint32(100), got.BlockHeight)
}

func TestBoltTxStore_UpdateTxNotFound(t *testing.T) {
	store := tempBoltStore(t)
	tx := testTx(99)
	err := store.Txs().UpdateTx(tx)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestBoltTxStore_NilTx(t *testing.T) {
	store := tempBoltStore(t)
	err := store.Txs().PutTx(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestBoltTxStore_InvalidTxIDLength(t *testing.T) {
	store := tempBoltStore(t)
	_, err := store.Txs().GetTx([]byte{1, 2, 3})
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestBoltTxStore_DeleteCleansPubKeyIndex(t *testing.T) {
	store := tempBoltStore(t)
	txs := store.Txs()

	pNode := DoubleHash([]byte("pubkey_del"))
	tx := testTx(60)
	require.NoError(t, txs.PutTxWithPubKey(tx, pNode))

	require.NoError(t, txs.DeleteTx(tx.TxID))

	got, err := txs.GetTxsByPubKey(pNode)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestBoltStore_CreateDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	dbPath := filepath.Join(nested, "spv.db")

	store, err := OpenBoltStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	_, err = os.Stat(nested)
	assert.NoError(t, err, "nested directory should be created")
}

func TestBoltTxStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")

	store1, err := OpenBoltStore(dbPath)
	require.NoError(t, err)
	tx := testTx(70)
	require.NoError(t, store1.Txs().PutTx(tx))
	store1.Close()

	store2, err := OpenBoltStore(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	got, err := store2.Txs().GetTx(tx.TxID)
	require.NoError(t, err)
	assert.Equal(t, tx.TxID, got.TxID)
}
