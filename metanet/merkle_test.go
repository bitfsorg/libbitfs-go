package metanet

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bitfsorg/libbitfs-go/spv"
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

func TestBuildDirectoryMerkleProof_InvalidIndex(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
	}

	_, err := BuildDirectoryMerkleProof(children, -1)
	assert.Error(t, err)

	_, err = BuildDirectoryMerkleProof(children, 1)
	assert.Error(t, err)

	_, err = BuildDirectoryMerkleProof(nil, 0)
	assert.Error(t, err)
}

func TestBuildDirectoryMerkleProof_SingleChild(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "only.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
	}

	proof, err := BuildDirectoryMerkleProof(children, 0)
	require.NoError(t, err)
	assert.Empty(t, proof, "single child: proof is empty (leaf IS the root)")
}

func TestBuildAndVerify_TwoChildren(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	for idx := 0; idx < 2; idx++ {
		proof, err := BuildDirectoryMerkleProof(children, idx)
		require.NoError(t, err)
		assert.Len(t, proof, 1, "two children: proof has 1 sibling")

		ok := VerifyChildMembership(&children[idx], proof, idx, merkleRoot)
		assert.True(t, ok, "valid proof for child %d", idx)
	}
}

func TestBuildAndVerify_FourChildren(t *testing.T) {
	children := make([]ChildEntry, 4)
	for i := range children {
		children[i] = ChildEntry{
			Index:  uint32(i),
			Name:   fmt.Sprintf("file%d.txt", i),
			Type:   NodeTypeFile,
			PubKey: makePubKey(byte(i + 1)),
		}
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	for idx := 0; idx < 4; idx++ {
		proof, err := BuildDirectoryMerkleProof(children, idx)
		require.NoError(t, err)
		assert.Len(t, proof, 2, "4 children: proof depth is 2")

		ok := VerifyChildMembership(&children[idx], proof, idx, merkleRoot)
		assert.True(t, ok, "valid proof for child %d", idx)
	}
}

func TestBuildAndVerify_FiveChildren_OddPadding(t *testing.T) {
	children := make([]ChildEntry, 5)
	for i := range children {
		children[i] = ChildEntry{
			Index:  uint32(i),
			Name:   fmt.Sprintf("f%d", i),
			Type:   NodeTypeFile,
			PubKey: makePubKey(byte(i + 1)),
		}
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	for idx := 0; idx < 5; idx++ {
		proof, err := BuildDirectoryMerkleProof(children, idx)
		require.NoError(t, err)

		ok := VerifyChildMembership(&children[idx], proof, idx, merkleRoot)
		assert.True(t, ok, "valid proof for child %d", idx)
	}
}

func TestVerifyChildMembership_TamperedEntry(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	proof, err := BuildDirectoryMerkleProof(children, 0)
	require.NoError(t, err)

	tampered := children[0]
	tampered.Name = "evil.txt"
	ok := VerifyChildMembership(&tampered, proof, 0, merkleRoot)
	assert.False(t, ok, "tampered entry must fail verification")
}

func TestVerifyChildMembership_WrongProof(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
		{Index: 2, Name: "c.txt", Type: NodeTypeFile, PubKey: makePubKey(0x03)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	proof0, err := BuildDirectoryMerkleProof(children, 0)
	require.NoError(t, err)

	ok := VerifyChildMembership(&children[1], proof0, 0, merkleRoot)
	assert.False(t, ok, "wrong proof must fail")
}

func TestVerifyChildMembership_WrongIndex(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	proof, err := BuildDirectoryMerkleProof(children, 0)
	require.NoError(t, err)

	ok := VerifyChildMembership(&children[0], proof, 1, merkleRoot)
	assert.False(t, ok, "wrong index must fail")
}

func TestVerifyChildMembership_WrongMerkleRoot(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)
	_ = merkleRoot // ensure setup is valid; tests below use fakeRoot and nil

	proof, err := BuildDirectoryMerkleProof(children, 0)
	require.NoError(t, err)

	fakeRoot := make([]byte, 32)
	fakeRoot[0] = 0xFF
	ok := VerifyChildMembership(&children[0], proof, 0, fakeRoot)
	assert.False(t, ok, "wrong merkle root must fail")

	ok = VerifyChildMembership(&children[0], proof, 0, nil)
	assert.False(t, ok, "nil merkle root must fail")
}

func TestSerializePayload_MerkleRoot(t *testing.T) {
	node := &Node{
		Type: NodeTypeDir,
		Children: []ChildEntry{
			{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
			{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
		},
		MerkleRoot: ComputeDirectoryMerkleRoot([]ChildEntry{
			{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
			{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
		}),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	// Tag 0x1A should be present in the serialized output
	found := false
	offset := 0
	for offset < len(payload) {
		if offset >= len(payload) {
			break
		}
		tag := payload[offset]
		offset++
		length, n := binary.Uvarint(payload[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if tag == 0x1A {
			found = true
			assert.Equal(t, uint64(32), length, "MerkleRoot TLV length must be 32")
			assert.Equal(t, node.MerkleRoot, payload[offset:offset+int(length)])
		}
		offset += int(length)
	}
	assert.True(t, found, "tag 0x1A must be present in serialized payload")
}

func TestSerializePayload_MerkleRoot_NilSkipped(t *testing.T) {
	node := &Node{
		Type: NodeTypeDir,
		// No children, MerkleRoot is nil
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	// Tag 0x1A should NOT be present
	offset := 0
	for offset < len(payload) {
		if offset+3 > len(payload) {
			break
		}
		tag := payload[offset]
		length := int(payload[offset+1]) | int(payload[offset+2])<<8
		offset += 3
		assert.NotEqual(t, byte(0x1A), tag, "tag 0x1A must not appear when MerkleRoot is nil")
		offset += length
	}
}

func TestSerializeDeserialize_MerkleRoot_RoundTrip(t *testing.T) {
	children := []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)},
		{Index: 2, Name: "c/", Type: NodeTypeDir, PubKey: makePubKey(0x03)},
	}
	merkleRoot := ComputeDirectoryMerkleRoot(children)

	original := &Node{
		Type:       NodeTypeDir,
		Children:   children,
		MerkleRoot: merkleRoot,
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, original.MerkleRoot, parsed.MerkleRoot, "MerkleRoot must survive round-trip")
	assert.Len(t, parsed.MerkleRoot, 32)
}

func TestDeserializePayload_NoMerkleRoot_BackwardCompat(t *testing.T) {
	// Simulate old node without tag 0x1A: just version + type
	node := &Node{
		Type: NodeTypeDir,
	}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Nil(t, parsed.MerkleRoot, "old nodes without tag 0x1A must have nil MerkleRoot")
}

func TestAddChild_UpdatesMerkleRoot(t *testing.T) {
	dir := &Node{
		Type:     NodeTypeDir,
		PNode:    makePubKey(0xAA),
		Children: nil,
	}

	// Initially nil
	assert.Nil(t, dir.MerkleRoot)

	// Add first child
	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x01), false)
	require.NoError(t, err)
	require.Len(t, dir.MerkleRoot, 32, "MerkleRoot must be set after AddChild")

	// Must match manual computation
	expected := ComputeDirectoryMerkleRoot(dir.Children)
	assert.Equal(t, expected, dir.MerkleRoot)

	// Add second child — root changes
	oldRoot := make([]byte, 32)
	copy(oldRoot, dir.MerkleRoot)

	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x02), false)
	require.NoError(t, err)
	assert.NotEqual(t, oldRoot, dir.MerkleRoot, "MerkleRoot must change when children change")

	expected = ComputeDirectoryMerkleRoot(dir.Children)
	assert.Equal(t, expected, dir.MerkleRoot)
}

func TestRemoveChild_UpdatesMerkleRoot(t *testing.T) {
	dir := &Node{
		Type:  NodeTypeDir,
		PNode: makePubKey(0xAA),
	}

	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x01), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x02), false)
	require.NoError(t, err)

	rootBefore := make([]byte, 32)
	copy(rootBefore, dir.MerkleRoot)

	// Remove one child
	err = RemoveChild(dir, "a.txt")
	require.NoError(t, err)
	assert.NotEqual(t, rootBefore, dir.MerkleRoot, "MerkleRoot must change after removal")

	expected := ComputeDirectoryMerkleRoot(dir.Children)
	assert.Equal(t, expected, dir.MerkleRoot)

	// Remove last child — MerkleRoot becomes nil
	err = RemoveChild(dir, "b.txt")
	require.NoError(t, err)
	assert.Nil(t, dir.MerkleRoot, "empty dir has nil MerkleRoot")
}

func TestRenameChild_UpdatesMerkleRoot(t *testing.T) {
	dir := &Node{
		Type:  NodeTypeDir,
		PNode: makePubKey(0xAA),
	}

	_, err := AddChild(dir, "old.txt", NodeTypeFile, makePubKey(0x01), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "other.txt", NodeTypeFile, makePubKey(0x02), false)
	require.NoError(t, err)

	rootBefore := make([]byte, 32)
	copy(rootBefore, dir.MerkleRoot)

	err = RenameChild(dir, "old.txt", "new.txt")
	require.NoError(t, err)
	assert.NotEqual(t, rootBefore, dir.MerkleRoot, "MerkleRoot must change after rename")

	expected := ComputeDirectoryMerkleRoot(dir.Children)
	assert.Equal(t, expected, dir.MerkleRoot)
}

func TestMerkleRoot_EndToEnd(t *testing.T) {
	// Simulate a realistic directory lifecycle:
	// 1. Create dir, add children
	// 2. Verify MerkleRoot is set and correct
	// 3. Build proof for each child and verify membership
	// 4. Serialize and deserialize — MerkleRoot preserved
	// 5. Remove a child — MerkleRoot updates, old proof fails

	dir := &Node{
		Type:  NodeTypeDir,
		PNode: makePubKey(0xDD),
	}

	// Add 3 children
	_, err := AddChild(dir, "readme.md", NodeTypeFile, makePubKey(0x01), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "src", NodeTypeDir, makePubKey(0x02), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "go.mod", NodeTypeFile, makePubKey(0x03), false)
	require.NoError(t, err)

	require.Len(t, dir.MerkleRoot, 32)
	assert.Equal(t, ComputeDirectoryMerkleRoot(dir.Children), dir.MerkleRoot)

	// Build and verify proofs for each child
	for idx, child := range dir.Children {
		proof, err := BuildDirectoryMerkleProof(dir.Children, idx)
		require.NoError(t, err)

		ok := VerifyChildMembership(&child, proof, idx, dir.MerkleRoot)
		assert.True(t, ok, "proof for %q at index %d", child.Name, idx)
	}

	// Serialize round-trip
	payload, err := SerializePayload(dir)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)
	assert.Equal(t, dir.MerkleRoot, parsed.MerkleRoot)

	// Save proof for child 0 before removal
	proof0, err := BuildDirectoryMerkleProof(dir.Children, 0)
	require.NoError(t, err)
	child0 := dir.Children[0]
	oldRoot := make([]byte, 32)
	copy(oldRoot, dir.MerkleRoot)

	// Remove child 1 ("src") — MerkleRoot changes
	err = RemoveChild(dir, "src")
	require.NoError(t, err)
	assert.NotEqual(t, oldRoot, dir.MerkleRoot, "root must change after removal")

	// Old proof for child 0 against the OLD root still works
	ok := VerifyChildMembership(&child0, proof0, 0, oldRoot)
	assert.True(t, ok, "old proof against old root still valid")

	// Old proof for child 0 against the NEW root does NOT work
	ok = VerifyChildMembership(&child0, proof0, 0, dir.MerkleRoot)
	assert.False(t, ok, "old proof against new root must fail")
}
