package metanet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tongxiaofeng/libbitfs/spv"
)

func TestComputeChildLeafHash(t *testing.T) {
	entry := ChildEntry{
		Index:    0,
		Name:     "hello.txt",
		Type:     NodeTypeFile,
		PubKey:   makePubKey(0x01),
		Hardened: false,
	}

	hash := ComputeChildLeafHash(&entry)
	require.Len(t, hash, 32)

	// Must equal DoubleHash of the serialized ChildEntry
	serialized := serializeChildEntry(&entry)
	expected := spv.DoubleHash(serialized)
	assert.Equal(t, expected, hash)
}

func TestComputeChildLeafHash_Deterministic(t *testing.T) {
	entry := ChildEntry{
		Index:    5,
		Name:     "doc.pdf",
		Type:     NodeTypeDir,
		PubKey:   makePubKey(0x42),
		Hardened: true,
	}

	h1 := ComputeChildLeafHash(&entry)
	h2 := ComputeChildLeafHash(&entry)
	assert.Equal(t, h1, h2, "same entry must produce same hash")
}

func TestComputeChildLeafHash_DifferentEntries(t *testing.T) {
	e1 := ChildEntry{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)}
	e2 := ChildEntry{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)}

	h1 := ComputeChildLeafHash(&e1)
	h2 := ComputeChildLeafHash(&e2)
	assert.NotEqual(t, h1, h2, "different entries must produce different hashes")
}

func TestComputeDirectoryMerkleRoot_Empty(t *testing.T) {
	root := ComputeDirectoryMerkleRoot(nil)
	assert.Nil(t, root, "empty children → nil")

	root2 := ComputeDirectoryMerkleRoot([]ChildEntry{})
	assert.Nil(t, root2, "zero-length children → nil")
}

func TestComputeDirectoryMerkleRoot_SingleChild(t *testing.T) {
	child := ChildEntry{
		Index:  0,
		Name:   "only.txt",
		Type:   NodeTypeFile,
		PubKey: makePubKey(0x01),
	}

	root := ComputeDirectoryMerkleRoot([]ChildEntry{child})
	require.Len(t, root, 32)

	// Single child: root = leaf hash
	leafHash := ComputeChildLeafHash(&child)
	assert.Equal(t, leafHash, root, "single child: root equals leaf hash")
}

func TestComputeDirectoryMerkleRoot_TwoChildren(t *testing.T) {
	c1 := ChildEntry{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)}
	c2 := ChildEntry{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)}

	root := ComputeDirectoryMerkleRoot([]ChildEntry{c1, c2})
	require.Len(t, root, 32)

	// Manual verification: root = DoubleHash(leaf1 || leaf2)
	leaf1 := ComputeChildLeafHash(&c1)
	leaf2 := ComputeChildLeafHash(&c2)
	combined := make([]byte, 64)
	copy(combined[:32], leaf1)
	copy(combined[32:], leaf2)
	expected := spv.DoubleHash(combined)
	assert.Equal(t, expected, root)
}

func TestComputeDirectoryMerkleRoot_ThreeChildren_OddPadding(t *testing.T) {
	c1 := ChildEntry{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)}
	c2 := ChildEntry{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)}
	c3 := ChildEntry{Index: 2, Name: "c.txt", Type: NodeTypeDir, PubKey: makePubKey(0x03)}

	root := ComputeDirectoryMerkleRoot([]ChildEntry{c1, c2, c3})
	require.Len(t, root, 32)

	// Manual: 3 leaves → pad to 4 by duplicating last
	leaf1 := ComputeChildLeafHash(&c1)
	leaf2 := ComputeChildLeafHash(&c2)
	leaf3 := ComputeChildLeafHash(&c3)

	combined12 := make([]byte, 64)
	copy(combined12[:32], leaf1)
	copy(combined12[32:], leaf2)
	h12 := spv.DoubleHash(combined12)

	combined33 := make([]byte, 64)
	copy(combined33[:32], leaf3)
	copy(combined33[32:], leaf3)
	h33 := spv.DoubleHash(combined33)

	combinedRoot := make([]byte, 64)
	copy(combinedRoot[:32], h12)
	copy(combinedRoot[32:], h33)
	expected := spv.DoubleHash(combinedRoot)

	assert.Equal(t, expected, root)
}

func TestComputeDirectoryMerkleRoot_Deterministic(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "x.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10)},
		{Index: 1, Name: "y.txt", Type: NodeTypeFile, PubKey: makePubKey(0x20)},
	}

	r1 := ComputeDirectoryMerkleRoot(children)
	r2 := ComputeDirectoryMerkleRoot(children)
	assert.Equal(t, r1, r2, "same children → same root")
}

func TestComputeDirectoryMerkleRoot_CrossVerifyWithSPV(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
		{Index: 2, Name: "c.txt", Type: NodeTypeDir, PubKey: makePubKey(0x03)},
		{Index: 3, Name: "d.txt", Type: NodeTypeFile, PubKey: makePubKey(0x04)},
	}

	leafHashes := make([][]byte, len(children))
	for i := range children {
		leafHashes[i] = ComputeChildLeafHash(&children[i])
	}

	spvTree := spv.BuildMerkleTree(leafHashes)
	require.NotNil(t, spvTree)
	spvRoot := spvTree[0]

	dirRoot := ComputeDirectoryMerkleRoot(children)
	assert.Equal(t, spvRoot, dirRoot, "directory Merkle root must match spv.BuildMerkleTree")
}
