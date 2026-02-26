package spv

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helper functions ---

func makeHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

func makeTxHash(seed byte) []byte {
	data := []byte{seed}
	return DoubleHash(data)
}

// buildTestProof builds a valid Merkle proof for a single-tx block.
func buildTestProof(txHash []byte) (*MerkleProof, []byte) {
	// For a block with 2 txs, proof for tx at index 0 needs the other tx as the only node
	otherTx := makeTxHash(0x99)
	combined := make([]byte, 64)
	copy(combined[:32], txHash)
	copy(combined[32:], otherTx)
	merkleRoot := DoubleHash(combined)

	proof := &MerkleProof{
		TxID:      txHash,
		Index:     0,
		Nodes:     [][]byte{otherTx},
		BlockHash: makeHash(0xBB),
	}

	return proof, merkleRoot
}

func buildTestHeader(height uint32, prevBlock, merkleRoot []byte) *BlockHeader {
	h := &BlockHeader{
		Version:    1,
		PrevBlock:  prevBlock,
		MerkleRoot: merkleRoot,
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      12345,
		Height:     height,
	}
	h.Hash = ComputeHeaderHash(h)
	return h
}

// --- DoubleHash tests ---

func TestDoubleHash(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"single byte", []byte{0x42}},
		{"32 bytes", bytes.Repeat([]byte{0xAA}, 32)},
		{"large data", bytes.Repeat([]byte{0xFF}, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DoubleHash(tt.data)
			assert.Len(t, result, 32)

			// Verify manually: SHA256(SHA256(data))
			first := sha256.Sum256(tt.data)
			second := sha256.Sum256(first[:])
			assert.Equal(t, second[:], result)
		})
	}
}

func TestDoubleHash_Deterministic(t *testing.T) {
	data := []byte("bitcoin transaction data")
	h1 := DoubleHash(data)
	h2 := DoubleHash(data)
	assert.Equal(t, h1, h2, "DoubleHash should be deterministic")
}

func TestDoubleHash_DifferentInputs(t *testing.T) {
	h1 := DoubleHash([]byte("data1"))
	h2 := DoubleHash([]byte("data2"))
	assert.NotEqual(t, h1, h2, "different inputs should produce different hashes")
}

// --- SerializeHeader / DeserializeHeader tests ---

func TestSerializeHeader(t *testing.T) {
	h := &BlockHeader{
		Version:    2,
		PrevBlock:  makeHash(0xAA),
		MerkleRoot: makeHash(0xBB),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}

	data := SerializeHeader(h)
	assert.Len(t, data, BlockHeaderSize)

	// Verify version
	version := int32(binary.LittleEndian.Uint32(data[0:4]))
	assert.Equal(t, int32(2), version)

	// Verify prevBlock
	assert.Equal(t, makeHash(0xAA), data[4:36])

	// Verify merkleRoot
	assert.Equal(t, makeHash(0xBB), data[36:68])

	// Verify timestamp
	ts := binary.LittleEndian.Uint32(data[68:72])
	assert.Equal(t, uint32(1700000000), ts)

	// Verify bits
	bits := binary.LittleEndian.Uint32(data[72:76])
	assert.Equal(t, uint32(0x1d00ffff), bits)

	// Verify nonce
	nonce := binary.LittleEndian.Uint32(data[76:80])
	assert.Equal(t, uint32(42), nonce)
}

func TestSerializeHeader_Nil(t *testing.T) {
	result := SerializeHeader(nil)
	assert.Nil(t, result)
}

func TestDeserializeHeader(t *testing.T) {
	original := &BlockHeader{
		Version:    536870912,
		PrevBlock:  makeHash(0x11),
		MerkleRoot: makeHash(0x22),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      987654321,
	}

	data := SerializeHeader(original)
	decoded, err := DeserializeHeader(data)
	require.NoError(t, err)

	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.PrevBlock, decoded.PrevBlock)
	assert.Equal(t, original.MerkleRoot, decoded.MerkleRoot)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.Bits, decoded.Bits)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Len(t, decoded.Hash, 32, "Hash should be computed")
}

func TestDeserializeHeader_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 79)},
		{"too long", make([]byte, 81)},
		{"half", make([]byte, 40)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeHeader(tt.data)
			assert.ErrorIs(t, err, ErrInvalidHeader)
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	h := &BlockHeader{
		Version:    1,
		PrevBlock:  makeTxHash(0x01),
		MerkleRoot: makeTxHash(0x02),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      0xdeadbeef,
	}

	data := SerializeHeader(h)
	decoded, err := DeserializeHeader(data)
	require.NoError(t, err)

	assert.Equal(t, h.Version, decoded.Version)
	assert.Equal(t, h.PrevBlock, decoded.PrevBlock)
	assert.Equal(t, h.MerkleRoot, decoded.MerkleRoot)
	assert.Equal(t, h.Timestamp, decoded.Timestamp)
	assert.Equal(t, h.Bits, decoded.Bits)
	assert.Equal(t, h.Nonce, decoded.Nonce)
}

func TestComputeHeaderHash(t *testing.T) {
	h := &BlockHeader{
		Version:    1,
		PrevBlock:  makeHash(0x00),
		MerkleRoot: makeHash(0x11),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}

	hash := ComputeHeaderHash(h)
	assert.Len(t, hash, 32)

	// Same header should produce same hash
	hash2 := ComputeHeaderHash(h)
	assert.Equal(t, hash, hash2)
}

func TestComputeHeaderHash_Nil(t *testing.T) {
	hash := ComputeHeaderHash(nil)
	assert.Nil(t, hash)
}

// --- ComputeMerkleRoot tests ---

func TestComputeMerkleRoot_SingleProofNode(t *testing.T) {
	txHash := makeTxHash(0x01)
	sibling := makeTxHash(0x02)

	// Index 0: txHash is on the left
	root := ComputeMerkleRoot(txHash, 0, [][]byte{sibling})
	assert.Len(t, root, 32)

	// Manual computation
	combined := make([]byte, 64)
	copy(combined[:32], txHash)
	copy(combined[32:], sibling)
	expected := DoubleHash(combined)
	assert.Equal(t, expected, root)
}

func TestComputeMerkleRoot_IndexOnRight(t *testing.T) {
	txHash := makeTxHash(0x01)
	sibling := makeTxHash(0x02)

	// Index 1: txHash is on the right
	root := ComputeMerkleRoot(txHash, 1, [][]byte{sibling})
	assert.Len(t, root, 32)

	combined := make([]byte, 64)
	copy(combined[:32], sibling)
	copy(combined[32:], txHash)
	expected := DoubleHash(combined)
	assert.Equal(t, expected, root)
}

func TestComputeMerkleRoot_TwoLevels(t *testing.T) {
	// Build a 4-tx tree and verify proof for tx at index 2
	tx0 := makeTxHash(0x10)
	tx1 := makeTxHash(0x11)
	tx2 := makeTxHash(0x12) // target
	tx3 := makeTxHash(0x13)

	// Level 0 pairs: (tx0, tx1) and (tx2, tx3)
	pair01 := make([]byte, 64)
	copy(pair01[:32], tx0)
	copy(pair01[32:], tx1)
	h01 := DoubleHash(pair01)

	pair23 := make([]byte, 64)
	copy(pair23[:32], tx2)
	copy(pair23[32:], tx3)
	h23 := DoubleHash(pair23)

	// Root = hash(h01, h23)
	rootPair := make([]byte, 64)
	copy(rootPair[:32], h01)
	copy(rootPair[32:], h23)
	expectedRoot := DoubleHash(rootPair)

	// Proof for tx2 (index 2 = binary 10):
	// Level 0: tx2 is left in its pair (bit 0 of index is 0), sibling = tx3
	// Level 1: h23 is right in root pair (bit 1 of index is 1), sibling = h01
	proofNodes := [][]byte{tx3, h01}
	computedRoot := ComputeMerkleRoot(tx2, 2, proofNodes)

	assert.Equal(t, expectedRoot, computedRoot)
}

func TestComputeMerkleRoot_InvalidTxHash(t *testing.T) {
	result := ComputeMerkleRoot([]byte{0x01}, 0, [][]byte{makeHash(0xAA)})
	assert.Nil(t, result, "should return nil for invalid txHash length")
}

func TestComputeMerkleRoot_InvalidProofNode(t *testing.T) {
	txHash := makeHash(0x01)
	result := ComputeMerkleRoot(txHash, 0, [][]byte{{0x01, 0x02}})
	assert.Nil(t, result, "should return nil for invalid proof node length")
}

func TestComputeMerkleRoot_EmptyProofNodes(t *testing.T) {
	txHash := makeHash(0x01)
	result := ComputeMerkleRoot(txHash, 0, nil)
	// With no proof nodes, the root is just the txHash itself
	assert.Equal(t, txHash, result)
}

// --- BuildMerkleTree tests ---

func TestBuildMerkleTree_SingleTx(t *testing.T) {
	txHash := makeTxHash(0x01)
	tree := BuildMerkleTree([][]byte{txHash})
	require.NotNil(t, tree)
	// Single tx: tree is just the tx itself (no hashing needed since it's odd, it duplicates)
	// Actually: single element, odd pad -> [txHash, txHash] -> hash(txHash || txHash) = root
	// Wait: BuildMerkleTree returns final level. Let me check.
	// For single tx: len(level)=1 which is >1 false, so it returns [txHash]
	assert.Len(t, tree, 1)
	assert.Equal(t, txHash, tree[0])
}

func TestBuildMerkleTree_TwoTx(t *testing.T) {
	tx0 := makeTxHash(0x01)
	tx1 := makeTxHash(0x02)

	tree := BuildMerkleTree([][]byte{tx0, tx1})
	require.NotNil(t, tree)
	assert.Len(t, tree, 1) // Single root

	// Manual: root = hash(tx0 || tx1)
	combined := make([]byte, 64)
	copy(combined[:32], tx0)
	copy(combined[32:], tx1)
	expected := DoubleHash(combined)
	assert.Equal(t, expected, tree[0])
}

func TestBuildMerkleTree_FourTx(t *testing.T) {
	txs := make([][]byte, 4)
	for i := range txs {
		txs[i] = makeTxHash(byte(i))
	}

	tree := BuildMerkleTree(txs)
	require.NotNil(t, tree)
	assert.Len(t, tree, 1)

	// Compute expected root manually
	p01 := make([]byte, 64)
	copy(p01[:32], txs[0])
	copy(p01[32:], txs[1])
	h01 := DoubleHash(p01)

	p23 := make([]byte, 64)
	copy(p23[:32], txs[2])
	copy(p23[32:], txs[3])
	h23 := DoubleHash(p23)

	rootPair := make([]byte, 64)
	copy(rootPair[:32], h01)
	copy(rootPair[32:], h23)
	expected := DoubleHash(rootPair)

	assert.Equal(t, expected, tree[0])
}

func TestBuildMerkleTree_ThreeTx_OddPadding(t *testing.T) {
	txs := make([][]byte, 3)
	for i := range txs {
		txs[i] = makeTxHash(byte(i + 10))
	}

	tree := BuildMerkleTree(txs)
	require.NotNil(t, tree)
	assert.Len(t, tree, 1)

	// With 3 txs, the 4th is a duplicate of the 3rd
	p01 := make([]byte, 64)
	copy(p01[:32], txs[0])
	copy(p01[32:], txs[1])
	h01 := DoubleHash(p01)

	p23 := make([]byte, 64)
	copy(p23[:32], txs[2])
	copy(p23[32:], txs[2]) // duplicated
	h23 := DoubleHash(p23)

	rootPair := make([]byte, 64)
	copy(rootPair[:32], h01)
	copy(rootPair[32:], h23)
	expected := DoubleHash(rootPair)

	assert.Equal(t, expected, tree[0])
}

func TestBuildMerkleTree_Empty(t *testing.T) {
	tree := BuildMerkleTree(nil)
	assert.Nil(t, tree)
}

func TestComputeMerkleRootFromTxList(t *testing.T) {
	txs := make([][]byte, 4)
	for i := range txs {
		txs[i] = makeTxHash(byte(i))
	}

	root := ComputeMerkleRootFromTxList(txs)
	assert.Len(t, root, 32)

	// Should match BuildMerkleTree result
	tree := BuildMerkleTree(txs)
	assert.Equal(t, tree[0], root)
}

func TestComputeMerkleRootFromTxList_Empty(t *testing.T) {
	root := ComputeMerkleRootFromTxList(nil)
	assert.Nil(t, root)
}

// --- VerifyMerkleProof tests ---

func TestVerifyMerkleProof_Valid(t *testing.T) {
	txHash := makeTxHash(0x42)
	proof, merkleRoot := buildTestProof(txHash)

	valid, err := VerifyMerkleProof(proof, merkleRoot)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyMerkleProof_InvalidRoot(t *testing.T) {
	txHash := makeTxHash(0x42)
	proof, _ := buildTestProof(txHash)

	wrongRoot := makeHash(0xFF)
	valid, err := VerifyMerkleProof(proof, wrongRoot)
	assert.ErrorIs(t, err, ErrMerkleProofInvalid)
	assert.False(t, valid)
}

func TestVerifyMerkleProof_NilProof(t *testing.T) {
	_, err := VerifyMerkleProof(nil, makeHash(0x00))
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestVerifyMerkleProof_InvalidTxIDLength(t *testing.T) {
	proof := &MerkleProof{
		TxID:  []byte{0x01, 0x02}, // too short
		Index: 0,
		Nodes: [][]byte{makeHash(0xAA)},
	}
	_, err := VerifyMerkleProof(proof, makeHash(0x00))
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestVerifyMerkleProof_SingleTxBlock(t *testing.T) {
	// In a single-tx block, the tx hash IS the merkle root. Proof has zero nodes.
	txHash := makeHash(0x42)
	proof := &MerkleProof{
		TxID:  txHash,
		Index: 0,
		Nodes: nil, // No sibling nodes in a single-tx block
	}
	valid, err := VerifyMerkleProof(proof, txHash)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyMerkleProof_SingleTxBlock_Mismatch(t *testing.T) {
	// Empty proof with wrong expected root should fail.
	txHash := makeHash(0x42)
	proof := &MerkleProof{
		TxID:  txHash,
		Index: 0,
		Nodes: nil,
	}
	valid, err := VerifyMerkleProof(proof, makeHash(0xFF))
	assert.ErrorIs(t, err, ErrMerkleProofInvalid)
	assert.False(t, valid)
}

func TestVerifyMerkleProof_InvalidExpectedRootLength(t *testing.T) {
	proof := &MerkleProof{
		TxID:  makeHash(0x01),
		Index: 0,
		Nodes: [][]byte{makeHash(0xAA)},
	}
	_, err := VerifyMerkleProof(proof, []byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- VerifyHeaderChain tests ---

func TestVerifyHeaderChain_Valid(t *testing.T) {
	h1 := buildTestHeader(1, makeHash(0x00), makeHash(0x11))
	h2 := buildTestHeader(2, h1.Hash, makeHash(0x22))
	h3 := buildTestHeader(3, h2.Hash, makeHash(0x33))

	err := VerifyHeaderChain([]*BlockHeader{h1, h2, h3})
	assert.NoError(t, err)
}

func TestVerifyHeaderChain_Broken(t *testing.T) {
	h1 := buildTestHeader(1, makeHash(0x00), makeHash(0x11))
	h2 := buildTestHeader(2, makeHash(0xFF), makeHash(0x22)) // wrong prevBlock

	err := VerifyHeaderChain([]*BlockHeader{h1, h2})
	assert.ErrorIs(t, err, ErrChainBroken)
}

func TestVerifyHeaderChain_Empty(t *testing.T) {
	err := VerifyHeaderChain(nil)
	assert.NoError(t, err)
}

func TestVerifyHeaderChain_Single(t *testing.T) {
	h := buildTestHeader(1, makeHash(0x00), makeHash(0x11))
	err := VerifyHeaderChain([]*BlockHeader{h})
	assert.NoError(t, err)
}

func TestVerifyHeaderChain_NilHeader(t *testing.T) {
	h1 := buildTestHeader(1, makeHash(0x00), makeHash(0x11))
	err := VerifyHeaderChain([]*BlockHeader{h1, nil})
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- VerifyTransaction tests ---

func TestVerifyTransaction_Valid(t *testing.T) {
	txHash := makeTxHash(0x42)
	proof, merkleRoot := buildTestProof(txHash)

	header := buildTestHeader(100, makeHash(0x00), merkleRoot)

	// Update proof block hash to match header hash
	proof.BlockHash = header.Hash

	headerStore := NewMemHeaderStore()
	err := headerStore.PutHeader(header)
	require.NoError(t, err)

	storedTx := &StoredTx{
		TxID:        txHash,
		RawTx:       []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof:       proof,
		BlockHeight: 100,
	}

	err = VerifyTransaction(storedTx, headerStore)
	assert.NoError(t, err)
}

func TestVerifyTransaction_NilTx(t *testing.T) {
	err := VerifyTransaction(nil, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestVerifyTransaction_NilHeaderStore(t *testing.T) {
	tx := &StoredTx{TxID: makeHash(0x01)}
	err := VerifyTransaction(tx, nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestVerifyTransaction_InvalidTxID(t *testing.T) {
	tx := &StoredTx{TxID: []byte{0x01}}
	err := VerifyTransaction(tx, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestVerifyTransaction_Unconfirmed(t *testing.T) {
	tx := &StoredTx{
		TxID:  makeHash(0x01),
		Proof: nil, // unconfirmed
	}
	err := VerifyTransaction(tx, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrUnconfirmed)
}

func TestVerifyTransaction_MismatchTxID(t *testing.T) {
	tx := &StoredTx{
		TxID: makeHash(0x01),
		Proof: &MerkleProof{
			TxID:      makeHash(0x02), // different from StoredTx.TxID
			Index:     0,
			Nodes:     [][]byte{makeHash(0xAA)},
			BlockHash: makeHash(0xBB),
		},
	}
	err := VerifyTransaction(tx, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrMerkleProofInvalid)
}

func TestVerifyTransaction_HeaderNotFound(t *testing.T) {
	txHash := makeTxHash(0x42)

	tx := &StoredTx{
		TxID:  txHash,
		RawTx: []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof: &MerkleProof{
			TxID:      txHash,
			Index:     0,
			Nodes:     [][]byte{makeHash(0xAA)},
			BlockHash: makeHash(0xBB),
		},
	}
	err := VerifyTransaction(tx, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrHeaderNotFound)
}

// --- MemHeaderStore tests ---

func TestMemHeaderStore_PutAndGet(t *testing.T) {
	store := NewMemHeaderStore()
	h := buildTestHeader(100, makeHash(0x00), makeHash(0x11))

	err := store.PutHeader(h)
	require.NoError(t, err)

	got, err := store.GetHeader(h.Hash)
	require.NoError(t, err)
	assert.Equal(t, h, got)
}

func TestMemHeaderStore_GetByHeight(t *testing.T) {
	store := NewMemHeaderStore()
	h := buildTestHeader(42, makeHash(0x00), makeHash(0x11))

	err := store.PutHeader(h)
	require.NoError(t, err)

	got, err := store.GetHeaderByHeight(42)
	require.NoError(t, err)
	assert.Equal(t, h, got)
}

func TestMemHeaderStore_GetByHeight_NotFound(t *testing.T) {
	store := NewMemHeaderStore()
	_, err := store.GetHeaderByHeight(999)
	assert.ErrorIs(t, err, ErrHeaderNotFound)
}

func TestMemHeaderStore_GetTip(t *testing.T) {
	store := NewMemHeaderStore()

	h1 := buildTestHeader(10, makeHash(0x01), makeHash(0x11))
	h2 := buildTestHeader(20, makeHash(0x02), makeHash(0x22))
	h3 := buildTestHeader(15, makeHash(0x03), makeHash(0x33))

	require.NoError(t, store.PutHeader(h1))
	require.NoError(t, store.PutHeader(h2))
	require.NoError(t, store.PutHeader(h3))

	tip, err := store.GetTip()
	require.NoError(t, err)
	assert.Equal(t, uint32(20), tip.Height)
}

func TestMemHeaderStore_GetTip_Empty(t *testing.T) {
	store := NewMemHeaderStore()
	_, err := store.GetTip()
	assert.ErrorIs(t, err, ErrHeaderNotFound)
}

func TestMemHeaderStore_GetHeaderCount(t *testing.T) {
	store := NewMemHeaderStore()
	count, err := store.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	require.NoError(t, store.PutHeader(buildTestHeader(1, makeHash(0x01), makeHash(0x11))))
	require.NoError(t, store.PutHeader(buildTestHeader(2, makeHash(0x02), makeHash(0x22))))

	count, err = store.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), count)
}

func TestMemHeaderStore_PutNil(t *testing.T) {
	store := NewMemHeaderStore()
	err := store.PutHeader(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMemHeaderStore_Duplicate(t *testing.T) {
	store := NewMemHeaderStore()
	h := buildTestHeader(1, makeHash(0x01), makeHash(0x11))

	require.NoError(t, store.PutHeader(h))
	err := store.PutHeader(h)
	assert.ErrorIs(t, err, ErrDuplicateHeader)
}

func TestMemHeaderStore_GetInvalidHashLength(t *testing.T) {
	store := NewMemHeaderStore()
	_, err := store.GetHeader([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- MemTxStore tests ---

func TestMemTxStore_PutAndGet(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{
		TxID:  makeHash(0x01),
		RawTx: []byte("raw transaction data"),
	}

	err := store.PutTx(tx)
	require.NoError(t, err)

	got, err := store.GetTx(tx.TxID)
	require.NoError(t, err)
	assert.Equal(t, tx, got)
}

func TestMemTxStore_GetNotFound(t *testing.T) {
	store := NewMemTxStore()
	_, err := store.GetTx(makeHash(0xFF))
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestMemTxStore_PutNilTx(t *testing.T) {
	store := NewMemTxStore()
	err := store.PutTx(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMemTxStore_PutInvalidTxID(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{TxID: []byte{0x01}}
	err := store.PutTx(tx)
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestMemTxStore_Duplicate(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{
		TxID:  makeHash(0x01),
		RawTx: []byte("data"),
	}

	require.NoError(t, store.PutTx(tx))
	err := store.PutTx(tx)
	assert.ErrorIs(t, err, ErrDuplicateTx)
}

func TestMemTxStore_Delete(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{
		TxID:  makeHash(0x01),
		RawTx: []byte("data"),
	}

	require.NoError(t, store.PutTx(tx))
	err := store.DeleteTx(tx.TxID)
	require.NoError(t, err)

	_, err = store.GetTx(tx.TxID)
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestMemTxStore_DeleteNotFound(t *testing.T) {
	store := NewMemTxStore()
	err := store.DeleteTx(makeHash(0xFF))
	assert.ErrorIs(t, err, ErrTxNotFound)
}

func TestMemTxStore_DeleteInvalidTxID(t *testing.T) {
	store := NewMemTxStore()
	err := store.DeleteTx([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestMemTxStore_ListTxs(t *testing.T) {
	store := NewMemTxStore()

	tx1 := &StoredTx{TxID: makeHash(0x01), RawTx: []byte("tx1")}
	tx2 := &StoredTx{TxID: makeHash(0x02), RawTx: []byte("tx2")}

	require.NoError(t, store.PutTx(tx1))
	require.NoError(t, store.PutTx(tx2))

	txs, err := store.ListTxs()
	require.NoError(t, err)
	assert.Len(t, txs, 2)
}

func TestMemTxStore_ListTxs_Empty(t *testing.T) {
	store := NewMemTxStore()
	txs, err := store.ListTxs()
	require.NoError(t, err)
	assert.Empty(t, txs)
}

func TestMemTxStore_PutWithPubKey(t *testing.T) {
	store := NewMemTxStore()
	pNode := makeHash(0xAA)

	tx1 := &StoredTx{TxID: makeHash(0x01), RawTx: []byte("tx1")}
	tx2 := &StoredTx{TxID: makeHash(0x02), RawTx: []byte("tx2")}

	require.NoError(t, store.PutTxWithPubKey(tx1, pNode))
	require.NoError(t, store.PutTxWithPubKey(tx2, pNode))

	txs, err := store.GetTxsByPubKey(pNode)
	require.NoError(t, err)
	assert.Len(t, txs, 2)
}

func TestMemTxStore_GetTxsByPubKey_NotFound(t *testing.T) {
	store := NewMemTxStore()
	txs, err := store.GetTxsByPubKey(makeHash(0xFF))
	require.NoError(t, err)
	assert.Nil(t, txs)
}

func TestMemTxStore_GetTxsByPubKey_EmptyPNode(t *testing.T) {
	store := NewMemTxStore()
	_, err := store.GetTxsByPubKey(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestMemTxStore_GetInvalidTxIDLength(t *testing.T) {
	store := NewMemTxStore()
	_, err := store.GetTx([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

func TestMemTxStore_DeleteWithPubKeyIndex(t *testing.T) {
	store := NewMemTxStore()
	pNode := makeHash(0xAA)

	tx := &StoredTx{TxID: makeHash(0x01), RawTx: []byte("tx")}
	require.NoError(t, store.PutTxWithPubKey(tx, pNode))

	require.NoError(t, store.DeleteTx(tx.TxID))

	txs, err := store.GetTxsByPubKey(pNode)
	require.NoError(t, err)
	assert.Empty(t, txs)
}

// =============================================================================
// Supplementary tests — covering gaps identified in AUDIT.md
// =============================================================================

// --- Gap 1: VerifyTransaction -- invalid proof BlockHash length (verify.go line 54) ---

func TestVerifyTransaction_InvalidBlockHashLength(t *testing.T) {
	txHash := makeTxHash(0x42)

	tx := &StoredTx{
		TxID:  txHash,
		RawTx: []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof: &MerkleProof{
			TxID:      txHash,
			Index:     0,
			Nodes:     [][]byte{makeHash(0xAA)},
			BlockHash: []byte{0x01, 0x02, 0x03}, // 3 bytes, not 32
		},
	}

	err := VerifyTransaction(tx, NewMemHeaderStore())
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- Gap 2: VerifyTransaction -- HeaderStore returns (nil, nil) (verify.go line 62-63) ---

// mockNilHeaderStore returns (nil, nil) from GetHeader to test the defensive nil check.
type mockNilHeaderStore struct{}

func (m *mockNilHeaderStore) PutHeader(_ *BlockHeader) error                   { return nil }
func (m *mockNilHeaderStore) GetHeader(_ []byte) (*BlockHeader, error)         { return nil, nil }
func (m *mockNilHeaderStore) GetHeaderByHeight(_ uint32) (*BlockHeader, error) { return nil, nil }
func (m *mockNilHeaderStore) GetTip() (*BlockHeader, error)                    { return nil, nil }
func (m *mockNilHeaderStore) GetHeaderCount() (uint64, error)                  { return 0, nil }

func TestVerifyTransaction_HeaderStoreReturnsNilNil(t *testing.T) {
	txHash := makeTxHash(0x42)

	tx := &StoredTx{
		TxID:  txHash,
		RawTx: []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof: &MerkleProof{
			TxID:      txHash,
			Index:     0,
			Nodes:     [][]byte{makeHash(0xAA)},
			BlockHash: makeHash(0xBB),
		},
	}

	err := VerifyTransaction(tx, &mockNilHeaderStore{})
	assert.ErrorIs(t, err, ErrHeaderNotFound)
}

// --- Gap 3: VerifyTransaction -- Merkle root mismatch (wrong proof nodes) ---

func TestVerifyTransaction_MerkleRootMismatch(t *testing.T) {
	txHash := makeTxHash(0x42)

	// Build a valid proof structure but use wrong proof nodes
	// so the computed root will not match the header's MerkleRoot.
	wrongSibling := makeHash(0xDE) // arbitrary, won't produce the right root

	// Create a header with a specific MerkleRoot
	realMerkleRoot := makeHash(0xCC)
	header := buildTestHeader(100, makeHash(0x00), realMerkleRoot)

	headerStore := NewMemHeaderStore()
	err := headerStore.PutHeader(header)
	require.NoError(t, err)

	tx := &StoredTx{
		TxID:  txHash,
		RawTx: []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof: &MerkleProof{
			TxID:      txHash,
			Index:     0,
			Nodes:     [][]byte{wrongSibling}, // computes to wrong root
			BlockHash: header.Hash,
		},
	}

	err = VerifyTransaction(tx, headerStore)
	assert.ErrorIs(t, err, ErrMerkleProofInvalid)
}

// --- Gap 4: VerifyHeaderChain -- invalid PrevBlock length ---

func TestVerifyHeaderChain_InvalidPrevBlockLength(t *testing.T) {
	h1 := buildTestHeader(1, makeHash(0x00), makeHash(0x11))
	h2 := &BlockHeader{
		Version:    1,
		PrevBlock:  []byte{0x01, 0x02, 0x03, 0x04}, // 4 bytes, not 32
		MerkleRoot: makeHash(0x22),
		Timestamp:  1700000001,
		Bits:       0x1d00ffff,
		Nonce:      99,
		Height:     2,
	}
	h2.Hash = ComputeHeaderHash(h2)

	err := VerifyHeaderChain([]*BlockHeader{h1, h2})
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- Gap 5: VerifyHeaderChain -- empty Hash auto-recomputation ---

func TestVerifyHeaderChain_EmptyHashAutoRecompute(t *testing.T) {
	// Build h1 with all valid fields but Hash=nil.
	// VerifyHeaderChain should recompute the hash and still validate.
	h1 := &BlockHeader{
		Version:    1,
		PrevBlock:  makeHash(0x00),
		MerkleRoot: makeHash(0x11),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      12345,
		Height:     1,
		Hash:       nil, // intentionally nil
	}

	// Compute what the hash should be for building h2's PrevBlock
	expectedHash := ComputeHeaderHash(h1)

	h2 := buildTestHeader(2, expectedHash, makeHash(0x22))

	err := VerifyHeaderChain([]*BlockHeader{h1, h2})
	assert.NoError(t, err, "chain should validate when prev header's Hash is recomputed")
}

// --- Gap 6: VerifyHeaderChain -- invalid recomputed hash ---

func TestVerifyHeaderChain_InvalidRecomputedHash(t *testing.T) {
	// Create a header where Hash is nil and ComputeHeaderHash returns nil.
	// ComputeHeaderHash calls SerializeHeader which returns nil for nil input.
	// However, the header itself is not nil; we need SerializeHeader to return
	// a non-nil result. The only way ComputeHeaderHash returns nil is if
	// SerializeHeader returns nil, which only happens for a nil header.
	// Since VerifyHeaderChain already checks for nil headers before
	// computing the hash, we cannot easily trigger this path without
	// a header that somehow produces a non-32-byte hash. Since
	// ComputeHeaderHash always returns either nil (for nil header) or
	// 32 bytes, the only feasible trigger is a nil first header which
	// is caught by the nil check.

	// Instead, test the case where the first header is nil and triggers
	// ErrNilParam before the hash computation. The second header in the chain
	// sees prev==nil and returns ErrNilParam.
	h2 := buildTestHeader(2, makeHash(0x00), makeHash(0x22))

	err := VerifyHeaderChain([]*BlockHeader{nil, h2})
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- Gap 7: PutTxWithPubKey -- nil tx ---

func TestMemTxStore_PutWithPubKey_NilTx(t *testing.T) {
	store := NewMemTxStore()
	err := store.PutTxWithPubKey(nil, makeHash(0xAA))
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- Gap 8: PutTxWithPubKey -- invalid TxID ---

func TestMemTxStore_PutWithPubKey_InvalidTxID(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{TxID: []byte{0x01}} // 1 byte, not 32
	err := store.PutTxWithPubKey(tx, makeHash(0xAA))
	assert.ErrorIs(t, err, ErrInvalidTxID)
}

// --- Gap 9: PutTxWithPubKey -- empty pNode (tx stored but not indexed) ---

func TestMemTxStore_PutWithPubKey_EmptyPNode(t *testing.T) {
	store := NewMemTxStore()
	tx := &StoredTx{TxID: makeHash(0x01), RawTx: []byte("data")}

	// Store with nil pNode -- tx should be stored but not indexed
	err := store.PutTxWithPubKey(tx, nil)
	require.NoError(t, err)

	// Tx should be retrievable by TxID
	got, err := store.GetTx(tx.TxID)
	require.NoError(t, err)
	assert.Equal(t, tx, got)

	// No pubkey index should exist -- there is no way to query by nil pNode
	// (GetTxsByPubKey returns ErrNilParam for nil), so we verify the internal
	// state is clean by querying with an arbitrary pNode.
	txs, err := store.GetTxsByPubKey(makeHash(0xFF))
	require.NoError(t, err)
	assert.Nil(t, txs)
}

// --- Gap 10: BuildMerkleTree -- deep tree (8+ transactions, 3+ levels) ---

func TestBuildMerkleTree_DeepTree(t *testing.T) {
	// Build a tree with 8 transactions (3 levels: 8 -> 4 -> 2 -> 1)
	txs := make([][]byte, 8)
	for i := range txs {
		txs[i] = makeTxHash(byte(i + 0x20))
	}

	tree := BuildMerkleTree(txs)
	require.NotNil(t, tree)
	assert.Len(t, tree, 1)

	// Manually compute the expected root bottom-up
	// Level 0 pairs
	combine := func(a, b []byte) []byte {
		c := make([]byte, 64)
		copy(c[:32], a)
		copy(c[32:], b)
		return DoubleHash(c)
	}

	h01 := combine(txs[0], txs[1])
	h23 := combine(txs[2], txs[3])
	h45 := combine(txs[4], txs[5])
	h67 := combine(txs[6], txs[7])

	// Level 1 pairs
	h0123 := combine(h01, h23)
	h4567 := combine(h45, h67)

	// Root
	expectedRoot := combine(h0123, h4567)

	assert.Equal(t, expectedRoot, tree[0])

	// Also verify that ComputeMerkleRoot works correctly for a deep proof.
	// Build proof for tx at index 5 (binary 101):
	// Level 0: bit 0 of 5 is 1 -> tx5 is right, sibling=tx4
	// Level 1: bit 1 of 5 is 0 -> h45 is left, sibling=h67
	//   Wait: after level 0, the pair is h45. Index>>1 = 2, bit 0 of 2 is 0 -> h45 is left, sibling=h67
	//   Actually, let's think about it: index=5, binary=101
	//   Level 0: bit 0 = 1 -> sibling is txs[4]
	//   Level 1: bit 1 = 0 -> sibling is h67
	//   Level 2: bit 2 = 1 -> sibling is h0123
	proofNodes := [][]byte{txs[4], h67, h0123}
	computedRoot := ComputeMerkleRoot(txs[5], 5, proofNodes)
	assert.Equal(t, expectedRoot, computedRoot, "Merkle proof for index 5 in 8-tx tree")
}

// --- Gap 11: DoubleHash -- known BSV genesis block hash ---

func TestDoubleHash_KnownBSVGenesisBlock(t *testing.T) {
	// The BSV (and BTC) genesis block header is 80 bytes.
	// We construct it from known values and verify DoubleHash
	// produces the known genesis block hash.
	//
	// Genesis block header fields:
	//   Version:    1
	//   PrevBlock:  0000...0000 (32 zero bytes)
	//   MerkleRoot: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
	//   Timestamp:  1231006505 (0x495FAB29)
	//   Bits:       0x1d00ffff
	//   Nonce:      2083236893 (0x7C2BAC1D)
	//
	// Known genesis block hash (internal byte order, little-endian):
	//   000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f

	header := make([]byte, 80)

	// Version = 1 (little-endian)
	binary.LittleEndian.PutUint32(header[0:4], 1)

	// PrevBlock = all zeros (already zero)

	// MerkleRoot (little-endian byte order, as stored in the block header)
	merkleRoot := []byte{
		0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2,
		0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
		0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
		0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
	}
	copy(header[36:68], merkleRoot)

	// Timestamp = 1231006505
	binary.LittleEndian.PutUint32(header[68:72], 1231006505)

	// Bits = 0x1d00ffff
	binary.LittleEndian.PutUint32(header[72:76], 0x1d00ffff)

	// Nonce = 2083236893
	binary.LittleEndian.PutUint32(header[76:80], 2083236893)

	hash := DoubleHash(header)
	require.Len(t, hash, 32)

	// The genesis block hash in internal byte order (little-endian, as Bitcoin uses):
	// 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
	expectedHash := []byte{
		0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
		0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
		0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
		0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	assert.Equal(t, expectedHash, hash, "DoubleHash of genesis block header should match known hash")
}

// --- Gap 12: VerifyMerkleProof -- invalid proof node triggers ComputeMerkleRoot nil ---

func TestVerifyMerkleProof_InvalidProofNodeLength(t *testing.T) {
	proof := &MerkleProof{
		TxID:  makeHash(0x01),
		Index: 0,
		Nodes: [][]byte{{0x01, 0x02, 0x03}}, // 3 bytes, not 32
	}

	valid, err := VerifyMerkleProof(proof, makeHash(0xAA))
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrMerkleProofInvalid)
}

// --- Gap 13: PutTxWithPubKey -- overwrite existing (no duplicate error) ---

func TestMemTxStore_PutWithPubKey_OverwriteExisting(t *testing.T) {
	store := NewMemTxStore()
	pNode := makeHash(0xAA)

	txID := makeHash(0x01)
	tx1 := &StoredTx{TxID: txID, RawTx: []byte("version1")}
	tx2 := &StoredTx{TxID: txID, RawTx: []byte("version2")}

	// First put succeeds
	err := store.PutTxWithPubKey(tx1, pNode)
	require.NoError(t, err)

	// Second put with same TxID also succeeds (overwrites, no ErrDuplicateTx)
	err = store.PutTxWithPubKey(tx2, pNode)
	require.NoError(t, err)

	// GetTx should return the second version
	got, err := store.GetTx(txID)
	require.NoError(t, err)
	assert.Equal(t, []byte("version2"), got.RawTx)
}

// --- Gap 7 (store.go): MemHeaderStore.PutHeader auto-computes hash ---

func TestMemHeaderStore_PutAutoComputesHash(t *testing.T) {
	store := NewMemHeaderStore()

	h := &BlockHeader{
		Version:    1,
		PrevBlock:  makeHash(0x00),
		MerkleRoot: makeHash(0x11),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
		Height:     100,
		Hash:       nil, // intentionally nil
	}

	err := store.PutHeader(h)
	require.NoError(t, err)

	// Hash should now be computed and set
	assert.Len(t, h.Hash, 32, "PutHeader should auto-compute Hash when nil")

	// Should be retrievable by the computed hash
	got, err := store.GetHeader(h.Hash)
	require.NoError(t, err)
	assert.Equal(t, h, got)

	// Should be retrievable by height
	got, err = store.GetHeaderByHeight(100)
	require.NoError(t, err)
	assert.Len(t, got.Hash, 32)
}

// --- Gap 8 (store.go): MemHeaderStore.PutHeader with pre-set invalid hash length ---

func TestMemHeaderStore_PutInvalidHashLength(t *testing.T) {
	store := NewMemHeaderStore()

	h := &BlockHeader{
		Version:    1,
		PrevBlock:  makeHash(0x00),
		MerkleRoot: makeHash(0x11),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
		Height:     100,
		Hash:       []byte{0x01, 0x02, 0x03}, // 3 bytes, not 32
	}

	err := store.PutHeader(h)
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- Gap 15: Concurrent access safety ---

func TestMemHeaderStore_ConcurrentPutAndGet(t *testing.T) {
	store := NewMemHeaderStore()
	const n = 50

	// Pre-build headers to avoid races on buildTestHeader
	headers := make([]*BlockHeader, n)
	for i := 0; i < n; i++ {
		seed := byte(i)
		headers[i] = buildTestHeader(uint32(i), makeHash(seed), makeHash(seed+100))
	}

	var wg sync.WaitGroup

	// Concurrent puts
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = store.PutHeader(headers[idx])
		}(i)
	}
	wg.Wait()

	// Concurrent gets
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = store.GetHeader(headers[idx].Hash)
			_, _ = store.GetHeaderByHeight(uint32(idx))
			_, _ = store.GetTip()
			_, _ = store.GetHeaderCount()
		}(i)
	}
	wg.Wait()

	count, err := store.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(n), count)
}

func TestMemTxStore_ConcurrentPutAndGet(t *testing.T) {
	store := NewMemTxStore()
	const n = 50

	// Pre-build transactions
	txs := make([]*StoredTx, n)
	for i := 0; i < n; i++ {
		txs[i] = &StoredTx{
			TxID:  makeTxHash(byte(i)),
			RawTx: []byte(fmt.Sprintf("tx%d", i)),
		}
	}

	var wg sync.WaitGroup

	// Concurrent puts
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = store.PutTx(txs[idx])
		}(i)
	}
	wg.Wait()

	// Concurrent reads and list
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _ = store.GetTx(txs[idx].TxID)
			_, _ = store.ListTxs()
		}(i)
	}
	wg.Wait()

	listed, err := store.ListTxs()
	require.NoError(t, err)
	assert.Len(t, listed, n)
}

// --- Edge case: DeserializeHeader with explicit nil input ---

func TestDeserializeHeader_NilInput(t *testing.T) {
	_, err := DeserializeHeader(nil)
	assert.ErrorIs(t, err, ErrInvalidHeader)
}

// --- Edge case: ComputeMerkleRoot with high index (boundary bit-shifting) ---

func TestComputeMerkleRoot_HighIndex(t *testing.T) {
	// Build a proof for index=7 in an 8-tx block (binary 111)
	// All 3 bits are 1, so at every level the current hash is on the right.
	txs := make([][]byte, 8)
	for i := range txs {
		txs[i] = makeTxHash(byte(i + 0x40))
	}

	combine := func(a, b []byte) []byte {
		c := make([]byte, 64)
		copy(c[:32], a)
		copy(c[32:], b)
		return DoubleHash(c)
	}

	h01 := combine(txs[0], txs[1])
	h23 := combine(txs[2], txs[3])
	h45 := combine(txs[4], txs[5])
	h67 := combine(txs[6], txs[7])
	h0123 := combine(h01, h23)
	h4567 := combine(h45, h67)
	expectedRoot := combine(h0123, h4567)

	// Proof for index=7 (binary 111):
	// Level 0: bit 0 = 1 -> tx7 is right, sibling = tx6
	// Level 1: bit 1 = 1 -> h67 is right, sibling = h45
	// Level 2: bit 2 = 1 -> h4567 is right, sibling = h0123
	proofNodes := [][]byte{txs[6], h45, h0123}
	computedRoot := ComputeMerkleRoot(txs[7], 7, proofNodes)
	assert.Equal(t, expectedRoot, computedRoot, "Merkle proof for index 7 (all right) in 8-tx tree")
}

// --- Edge case: MemHeaderStore height collision ---

func TestMemHeaderStore_HeightCollision(t *testing.T) {
	store := NewMemHeaderStore()

	h1 := buildTestHeader(100, makeHash(0x01), makeHash(0x11))
	h2 := buildTestHeader(100, makeHash(0x02), makeHash(0x22)) // same height, different hash

	require.NoError(t, store.PutHeader(h1))
	require.NoError(t, store.PutHeader(h2))

	// Both should be retrievable by hash
	got1, err := store.GetHeader(h1.Hash)
	require.NoError(t, err)
	assert.Equal(t, h1, got1)

	got2, err := store.GetHeader(h2.Hash)
	require.NoError(t, err)
	assert.Equal(t, h2, got2)

	// By height, the second one should overwrite the first
	gotByHeight, err := store.GetHeaderByHeight(100)
	require.NoError(t, err)
	assert.Equal(t, h2, gotByHeight, "later PutHeader at same height should overwrite in byHeight map")

	// Count should be 2 (both in byHash)
	count, err := store.GetHeaderCount()
	require.NoError(t, err)
	assert.Equal(t, uint64(2), count)
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkDoubleHash(b *testing.B) {
	data := bytes.Repeat([]byte{0x42}, 32)
	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DoubleHash(data)
	}
}

func BenchmarkComputeMerkleRoot(b *testing.B) {
	b.Run("depth_1", func(b *testing.B) {
		txHash := makeTxHash(0x01)
		sibling := makeTxHash(0x02)
		proofNodes := [][]byte{sibling}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ComputeMerkleRoot(txHash, 0, proofNodes)
		}
	})

	b.Run("depth_3", func(b *testing.B) {
		// Simulate proof for an 8-tx block
		txHash := makeTxHash(0x01)
		proofNodes := [][]byte{
			makeTxHash(0x02),
			makeTxHash(0x03),
			makeTxHash(0x04),
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ComputeMerkleRoot(txHash, 5, proofNodes)
		}
	})

	b.Run("depth_10", func(b *testing.B) {
		txHash := makeTxHash(0x01)
		proofNodes := make([][]byte, 10)
		for i := range proofNodes {
			proofNodes[i] = makeTxHash(byte(i + 0x10))
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ComputeMerkleRoot(txHash, 42, proofNodes)
		}
	})
}

func BenchmarkVerifyMerkleProof(b *testing.B) {
	txHash := makeTxHash(0x42)
	proof, merkleRoot := buildTestProof(txHash)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := VerifyMerkleProof(proof, merkleRoot)
		if err != nil || !valid {
			b.Fatal("proof verification failed")
		}
	}
}

func BenchmarkBuildMerkleTree(b *testing.B) {
	b.Run("4_txs", func(b *testing.B) {
		txs := make([][]byte, 4)
		for i := range txs {
			txs[i] = makeTxHash(byte(i))
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			BuildMerkleTree(txs)
		}
	})

	b.Run("64_txs", func(b *testing.B) {
		txs := make([][]byte, 64)
		for i := range txs {
			txs[i] = makeTxHash(byte(i))
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			BuildMerkleTree(txs)
		}
	})

	b.Run("1024_txs", func(b *testing.B) {
		txs := make([][]byte, 1024)
		for i := range txs {
			txs[i] = makeTxHash(byte(i % 256))
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			BuildMerkleTree(txs)
		}
	})
}

func BenchmarkSerializeHeader(b *testing.B) {
	h := &BlockHeader{
		Version:    2,
		PrevBlock:  makeHash(0xAA),
		MerkleRoot: makeHash(0xBB),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SerializeHeader(h)
	}
}

func BenchmarkDeserializeHeader(b *testing.B) {
	h := &BlockHeader{
		Version:    2,
		PrevBlock:  makeHash(0xAA),
		MerkleRoot: makeHash(0xBB),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}
	data := SerializeHeader(h)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DeserializeHeader(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTransaction(b *testing.B) {
	txHash := makeTxHash(0x42)
	proof, merkleRoot := buildTestProof(txHash)

	header := buildTestHeader(100, makeHash(0x00), merkleRoot)
	proof.BlockHash = header.Hash

	headerStore := NewMemHeaderStore()
	if err := headerStore.PutHeader(header); err != nil {
		b.Fatal(err)
	}

	storedTx := &StoredTx{
		TxID:        txHash,
		RawTx:       []byte{0x42}, // DoubleHash([]byte{0x42}) == makeTxHash(0x42)
		Proof:       proof,
		BlockHeight: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := VerifyTransaction(storedTx, headerStore)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeHeaderHash(b *testing.B) {
	h := &BlockHeader{
		Version:    1,
		PrevBlock:  makeHash(0x00),
		MerkleRoot: makeHash(0x11),
		Timestamp:  1700000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeHeaderHash(h)
	}
}
