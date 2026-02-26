package metanet

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// --- Helper types and functions ---

// mockNodeStore is a simple in-memory NodeStore for testing.
type mockNodeStore struct {
	byPubKey map[string]*Node
	byTxID   map[string]*Node
	versions map[string][]*Node
}

func newMockStore() *mockNodeStore {
	return &mockNodeStore{
		byPubKey: make(map[string]*Node),
		byTxID:   make(map[string]*Node),
		versions: make(map[string][]*Node),
	}
}

func (m *mockNodeStore) addNode(node *Node) {
	if len(node.PNode) > 0 {
		key := string(node.PNode)
		m.byPubKey[key] = node
		m.versions[key] = append(m.versions[key], node)
	}
	if len(node.TxID) > 0 {
		m.byTxID[string(node.TxID)] = node
	}
}

func (m *mockNodeStore) GetNodeByPubKey(pNode []byte) (*Node, error) {
	n, ok := m.byPubKey[string(pNode)]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return n, nil
}

func (m *mockNodeStore) GetNodeByTxID(txID []byte) (*Node, error) {
	n, ok := m.byTxID[string(txID)]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return n, nil
}

func (m *mockNodeStore) GetNodeVersions(pNode []byte) ([]*Node, error) {
	v := m.versions[string(pNode)]
	if len(v) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return v, nil
}

func (m *mockNodeStore) GetChildNodes(dirNode *Node) ([]*Node, error) {
	var result []*Node
	for _, child := range dirNode.Children {
		n, ok := m.byPubKey[string(child.PubKey)]
		if ok {
			result = append(result, n)
		}
	}
	return result, nil
}

func makePubKey(seed byte) []byte {
	pk := make([]byte, CompressedPubKeyLen)
	pk[0] = 0x02 // valid compressed key prefix
	for i := 1; i < CompressedPubKeyLen; i++ {
		pk[i] = seed
	}
	return pk
}

func makeTxID(seed byte) []byte {
	id := make([]byte, TxIDLen)
	for i := range id {
		id[i] = seed
	}
	return id
}

func makeRootDir(pNode []byte) *Node {
	return &Node{
		TxID:           makeTxID(0x01),
		PNode:          pNode,
		Type:           NodeTypeDir,
		Children:       []ChildEntry{},
		NextChildIndex: 0,
		Metadata:       make(map[string]string),
	}
}

func makeFileNode(pNode, parentPNode []byte, txID []byte) *Node {
	return &Node{
		TxID:     txID,
		PNode:    pNode,
		Type:     NodeTypeFile,
		Parent:   parentPNode,
		MimeType: "text/plain",
		FileSize: 1024,
		KeyHash:  bytes.Repeat([]byte{0xAA}, 32),
		Metadata: make(map[string]string),
	}
}

func makeDirNode(pNode, parentPNode []byte, txID []byte) *Node {
	return &Node{
		TxID:           txID,
		PNode:          pNode,
		Type:           NodeTypeDir,
		Parent:         parentPNode,
		Children:       []ChildEntry{},
		NextChildIndex: 0,
		Metadata:       make(map[string]string),
	}
}

func makeLinkNode(pNode, target []byte, linkType LinkType) *Node {
	return &Node{
		TxID:       makeTxID(0xCC),
		PNode:      pNode,
		Type:       NodeTypeLink,
		LinkTarget: target,
		LinkType:   linkType,
		Metadata:   make(map[string]string),
	}
}

// --- NodeType tests ---

func TestNodeType_String(t *testing.T) {
	tests := []struct {
		nt       NodeType
		expected string
	}{
		{NodeTypeFile, "FILE"},
		{NodeTypeDir, "DIR"},
		{NodeTypeLink, "LINK"},
		{NodeType(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.nt.String())
		})
	}
}

func TestOpType_String(t *testing.T) {
	tests := []struct {
		op       OpType
		expected string
	}{
		{OpCreate, "CREATE"},
		{OpUpdate, "UPDATE"},
		{OpDelete, "DELETE"},
		{OpType(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.op.String())
		})
	}
}

// --- Node method tests ---

func TestNode_IsRoot(t *testing.T) {
	root := &Node{ParentTxID: nil}
	assert.True(t, root.IsRoot())

	child := &Node{ParentTxID: makeTxID(0x01)}
	assert.False(t, child.IsRoot())
}

func TestNode_IsDir(t *testing.T) {
	dir := &Node{Type: NodeTypeDir}
	assert.True(t, dir.IsDir())
	assert.False(t, dir.IsFile())
	assert.False(t, dir.IsLink())
}

func TestNode_IsFile(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	assert.True(t, file.IsFile())
	assert.False(t, file.IsDir())
	assert.False(t, file.IsLink())
}

func TestNode_IsLink(t *testing.T) {
	link := &Node{Type: NodeTypeLink}
	assert.True(t, link.IsLink())
	assert.False(t, link.IsDir())
	assert.False(t, link.IsFile())
}

// --- Serialization round-trip tests ---

func TestSerializePayload_RoundTrip_File(t *testing.T) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeFile,
		Op:         OpCreate,
		MimeType:   "application/pdf",
		FileSize:   4096,
		KeyHash:    bytes.Repeat([]byte{0xBB}, 32),
		Access:     AccessPaid,
		PricePerKB: 100,
		Timestamp:  1700000000,
		Parent:     makePubKey(0x01),
		Index:      5,
		Encrypted:  true,
		Metadata:   make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)

	// Deserialize back
	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, node.Version, decoded.Version)
	assert.Equal(t, node.Type, decoded.Type)
	assert.Equal(t, node.Op, decoded.Op)
	assert.Equal(t, node.MimeType, decoded.MimeType)
	assert.Equal(t, node.FileSize, decoded.FileSize)
	assert.Equal(t, node.KeyHash, decoded.KeyHash)
	assert.Equal(t, node.Access, decoded.Access)
	assert.Equal(t, node.PricePerKB, decoded.PricePerKB)
	assert.Equal(t, node.Timestamp, decoded.Timestamp)
	assert.Equal(t, node.Parent, decoded.Parent)
	assert.Equal(t, node.Index, decoded.Index)
	assert.Equal(t, node.Encrypted, decoded.Encrypted)
}

func TestSerializePayload_RoundTrip_Dir(t *testing.T) {
	node := &Node{
		Version: 1,
		Type:    NodeTypeDir,
		Op:      OpCreate,
		Children: []ChildEntry{
			{Index: 0, Name: "readme.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10), Hardened: false},
			{Index: 1, Name: "docs", Type: NodeTypeDir, PubKey: makePubKey(0x20), Hardened: true},
		},
		NextChildIndex: 2,
		Domain:         "example.com",
		Description:    "Test directory",
		Metadata:       make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, node.Type, decoded.Type)
	assert.Len(t, decoded.Children, 2)
	assert.Equal(t, "readme.txt", decoded.Children[0].Name)
	assert.Equal(t, NodeTypeFile, decoded.Children[0].Type)
	assert.Equal(t, "docs", decoded.Children[1].Name)
	assert.Equal(t, NodeTypeDir, decoded.Children[1].Type)
	assert.True(t, decoded.Children[1].Hardened)
	assert.Equal(t, uint32(2), decoded.NextChildIndex)
	assert.Equal(t, "example.com", decoded.Domain)
	assert.Equal(t, "Test directory", decoded.Description)
}

func TestSerializePayload_RoundTrip_Link(t *testing.T) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeLink,
		Op:         OpCreate,
		LinkTarget: makePubKey(0x42),
		LinkType:   LinkTypeSoft,
		Metadata:   make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeLink, decoded.Type)
	assert.Equal(t, node.LinkTarget, decoded.LinkTarget)
	assert.Equal(t, LinkTypeSoft, decoded.LinkType)
}

func TestSerializePayload_Nil(t *testing.T) {
	_, err := SerializePayload(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestSerializePayload_OnChainContent(t *testing.T) {
	node := &Node{
		Version: 1,
		Type:    NodeTypeFile,
		OnChain: true,
		ContentTxIDs: [][]byte{
			makeTxID(0x01),
			makeTxID(0x02),
		},
		Compression: 1,
		Metadata:    make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.True(t, decoded.OnChain)
	assert.Len(t, decoded.ContentTxIDs, 2)
	assert.Equal(t, makeTxID(0x01), decoded.ContentTxIDs[0])
	assert.Equal(t, int32(1), decoded.Compression)
}

func TestSerializePayload_WithAllOptionalFields(t *testing.T) {
	node := &Node{
		Version:      1,
		Type:         NodeTypeFile,
		Op:           OpUpdate,
		MimeType:     "image/png",
		FileSize:     1048576,
		KeyHash:      bytes.Repeat([]byte{0xCC}, 32),
		Access:       AccessFree,
		PricePerKB:   50,
		Timestamp:    1700000000,
		Parent:       makePubKey(0x99),
		Index:        3,
		Keywords:     "test,image,png",
		Description:  "A test image",
		Encrypted:    true,
		OnChain:      true,
		ContentTxIDs: [][]byte{makeTxID(0xAA)},
		Compression:  2,
		CltvHeight:   100000,
		RevenueShare: 25,
		NetworkName:  "mainnet",
		Metadata:     make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, "image/png", decoded.MimeType)
	assert.Equal(t, uint64(1048576), decoded.FileSize)
	assert.Equal(t, AccessFree, decoded.Access)
	assert.Equal(t, "test,image,png", decoded.Keywords)
	assert.Equal(t, uint32(100000), decoded.CltvHeight)
	assert.Equal(t, uint32(25), decoded.RevenueShare)
	assert.Equal(t, "mainnet", decoded.NetworkName)
}

// --- ParseNode tests (using tx.BuildOPReturnData + ParseNode) ---

func TestParseNode_ValidFile(t *testing.T) {
	pNode := makePubKey(0x01)
	parentTxID := makeTxID(0x02)

	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Op:       OpCreate,
		MimeType: "text/plain",
		FileSize: 256,
		KeyHash:  bytes.Repeat([]byte{0xDD}, 32),
		Metadata: make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	// Use tx package to build OP_RETURN data
	// We need an ec.PublicKey - since we can't easily construct one from raw bytes
	// in tests, we'll construct the pushes manually matching the format
	pushes := [][]byte{
		tx.MetaFlagBytes,
		pNode,
		parentTxID,
		payload,
	}

	parsed, err := ParseNode(pushes)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, pNode, parsed.PNode)
	assert.Equal(t, parentTxID, parsed.ParentTxID)
	assert.Equal(t, NodeTypeFile, parsed.Type)
	assert.Equal(t, "text/plain", parsed.MimeType)
	assert.Equal(t, uint64(256), parsed.FileSize)
}

func TestParseNode_ValidDir(t *testing.T) {
	pNode := makePubKey(0x01)

	node := &Node{
		Version: 1,
		Type:    NodeTypeDir,
		Op:      OpCreate,
		Children: []ChildEntry{
			{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10)},
		},
		NextChildIndex: 1,
		Metadata:       make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pushes := [][]byte{tx.MetaFlagBytes, pNode, nil, payload}

	parsed, err := ParseNode(pushes)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeDir, parsed.Type)
	assert.Len(t, parsed.Children, 1)
	assert.Equal(t, "file.txt", parsed.Children[0].Name)
}

func TestParseNode_ValidLink(t *testing.T) {
	pNode := makePubKey(0x01)
	target := makePubKey(0x42)

	node := &Node{
		Version:    1,
		Type:       NodeTypeLink,
		LinkTarget: target,
		LinkType:   LinkTypeSoft,
		Metadata:   make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pushes := [][]byte{tx.MetaFlagBytes, pNode, nil, payload}
	parsed, err := ParseNode(pushes)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeLink, parsed.Type)
	assert.Equal(t, target, parsed.LinkTarget)
}

func TestParseNode_InvalidPushes(t *testing.T) {
	_, err := ParseNode([][]byte{{0x01}})
	assert.Error(t, err)
}

func TestParseNode_WrongMetaFlag(t *testing.T) {
	pushes := [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF},
		makePubKey(0x01),
		makeTxID(0x02),
		[]byte("payload"),
	}
	_, err := ParseNode(pushes)
	assert.Error(t, err)
}

func TestParseNodeFromPushesWithTxID(t *testing.T) {
	pNode := makePubKey(0x01)
	txID := makeTxID(0xAB)

	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Metadata: make(map[string]string),
	}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pushes := [][]byte{tx.MetaFlagBytes, pNode, nil, payload}
	parsed, err := ParseNodeFromPushesWithTxID(pushes, txID)
	require.NoError(t, err)
	assert.Equal(t, txID, parsed.TxID)
}

// --- Directory operations tests ---

func TestListDirectory(t *testing.T) {
	root := makeRootDir(makePubKey(0x01))
	root.Children = []ChildEntry{
		{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10)},
		{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x11)},
	}

	entries, err := ListDirectory(root)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "a.txt", entries[0].Name)
	assert.Equal(t, "b.txt", entries[1].Name)
}

func TestListDirectory_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	_, err := ListDirectory(file)
	assert.ErrorIs(t, err, ErrNotDirectory)
}

func TestListDirectory_Nil(t *testing.T) {
	_, err := ListDirectory(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestListDirectory_Empty(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	entries, err := ListDirectory(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestListDirectory_ReturnsCopy(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	dir.Children = []ChildEntry{
		{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10)},
	}

	entries, err := ListDirectory(dir)
	require.NoError(t, err)
	entries[0].Name = "modified"
	assert.Equal(t, "file.txt", dir.Children[0].Name, "original should not be modified")
}

func TestFindChild(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	dir.Children = []ChildEntry{
		{Index: 0, Name: "readme.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10)},
		{Index: 1, Name: "docs", Type: NodeTypeDir, PubKey: makePubKey(0x20)},
	}

	entry, found := FindChild(dir, "readme.txt")
	assert.True(t, found)
	assert.Equal(t, "readme.txt", entry.Name)
	assert.Equal(t, NodeTypeFile, entry.Type)

	entry, found = FindChild(dir, "docs")
	assert.True(t, found)
	assert.Equal(t, NodeTypeDir, entry.Type)
}

func TestFindChild_NotFound(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, found := FindChild(dir, "nonexistent")
	assert.False(t, found)
}

func TestFindChild_NilNode(t *testing.T) {
	_, found := FindChild(nil, "test")
	assert.False(t, found)
}

func TestFindChild_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	_, found := FindChild(file, "test")
	assert.False(t, found)
}

func TestAddChild(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))

	entry, err := AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)
	assert.Equal(t, "file.txt", entry.Name)
	assert.Equal(t, uint32(0), entry.Index)
	assert.Equal(t, NodeTypeFile, entry.Type)
	assert.False(t, entry.Hardened)
	assert.Len(t, dir.Children, 1)
	assert.Equal(t, uint32(1), dir.NextChildIndex)
}

func TestAddChild_MultipleChildren(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))

	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x11), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "subdir", NodeTypeDir, makePubKey(0x20), true)
	require.NoError(t, err)

	assert.Len(t, dir.Children, 3)
	assert.Equal(t, uint32(0), dir.Children[0].Index)
	assert.Equal(t, uint32(1), dir.Children[1].Index)
	assert.Equal(t, uint32(2), dir.Children[2].Index)
	assert.Equal(t, uint32(3), dir.NextChildIndex)
}

func TestAddChild_DuplicateName(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))

	_, err := AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)

	_, err = AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x11), false)
	assert.ErrorIs(t, err, ErrChildExists)
}

func TestAddChild_InvalidName(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))

	tests := []struct {
		name string
		err  error
	}{
		{"", ErrInvalidName},
		{"/", ErrInvalidName},
		{".", ErrInvalidName},
		{"..", ErrInvalidName},
		{"path/to/file", ErrInvalidName},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("name=%q", tt.name), func(t *testing.T) {
			_, err := AddChild(dir, tt.name, NodeTypeFile, makePubKey(0x10), false)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestAddChild_InvalidPubKey(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "file.txt", NodeTypeFile, []byte{0x01}, false)
	assert.ErrorIs(t, err, ErrInvalidPubKey)
}

func TestAddChild_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	_, err := AddChild(file, "child", NodeTypeFile, makePubKey(0x10), false)
	assert.ErrorIs(t, err, ErrNotDirectory)
}

func TestAddChild_NilDir(t *testing.T) {
	_, err := AddChild(nil, "child", NodeTypeFile, makePubKey(0x10), false)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestAddChild_Hardened(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	entry, err := AddChild(dir, "secret.txt", NodeTypeFile, makePubKey(0x10), true)
	require.NoError(t, err)
	assert.True(t, entry.Hardened)
}

func TestRemoveChild(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)

	err = RemoveChild(dir, "file.txt")
	require.NoError(t, err)
	assert.Empty(t, dir.Children)
	// NextChildIndex should NOT decrease
	assert.Equal(t, uint32(1), dir.NextChildIndex)
}

func TestRemoveChild_NotFound(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	err := RemoveChild(dir, "nonexistent")
	assert.ErrorIs(t, err, ErrChildNotFound)
}

func TestRemoveChild_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	err := RemoveChild(file, "child")
	assert.ErrorIs(t, err, ErrNotDirectory)
}

func TestRemoveChild_NilDir(t *testing.T) {
	err := RemoveChild(nil, "child")
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestRemoveChild_IndexNotReused(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x11), false)
	require.NoError(t, err)

	err = RemoveChild(dir, "a.txt")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), dir.NextChildIndex, "index should not be reused")

	entry, err := AddChild(dir, "c.txt", NodeTypeFile, makePubKey(0x12), false)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), entry.Index, "new child gets next available index")
}

func TestRenameChild(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "old.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)

	err = RenameChild(dir, "old.txt", "new.txt")
	require.NoError(t, err)

	_, found := FindChild(dir, "old.txt")
	assert.False(t, found)

	entry, found := FindChild(dir, "new.txt")
	assert.True(t, found)
	assert.Equal(t, "new.txt", entry.Name)
}

func TestRenameChild_TargetExists(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x11), false)
	require.NoError(t, err)

	err = RenameChild(dir, "a.txt", "b.txt")
	assert.ErrorIs(t, err, ErrChildExists)
}

func TestRenameChild_SourceNotFound(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	err := RenameChild(dir, "nonexistent", "new.txt")
	assert.ErrorIs(t, err, ErrChildNotFound)
}

func TestRenameChild_InvalidNewName(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)

	err = RenameChild(dir, "file.txt", "")
	assert.ErrorIs(t, err, ErrInvalidName)

	err = RenameChild(dir, "file.txt", "path/name")
	assert.ErrorIs(t, err, ErrInvalidName)
}

func TestRenameChild_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	err := RenameChild(file, "a", "b")
	assert.ErrorIs(t, err, ErrNotDirectory)
}

func TestNextChildIndex_Normal(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	dir.NextChildIndex = 5

	idx, err := NextChildIndex(dir)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), idx)
}

func TestNextChildIndex_NotDir(t *testing.T) {
	file := &Node{Type: NodeTypeFile}
	_, err := NextChildIndex(file)
	assert.ErrorIs(t, err, ErrNotDirectory)
}

// --- FollowLink tests ---

func TestFollowLink_SoftLink(t *testing.T) {
	store := newMockStore()

	targetPK := makePubKey(0x42)
	target := makeFileNode(targetPK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(target)

	link := makeLinkNode(makePubKey(0x30), targetPK, LinkTypeSoft)

	resolved, err := FollowLink(store, link, MaxLinkDepth)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, resolved.Type)
	assert.Equal(t, targetPK, resolved.PNode)
}

func TestFollowLink_ChainedLinks(t *testing.T) {
	store := newMockStore()

	// link1 -> link2 -> file
	filePK := makePubKey(0x42)
	file := makeFileNode(filePK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(file)

	link2PK := makePubKey(0x30)
	link2 := makeLinkNode(link2PK, filePK, LinkTypeSoft)
	store.addNode(link2)

	link1 := makeLinkNode(makePubKey(0x20), link2PK, LinkTypeSoft)

	resolved, err := FollowLink(store, link1, MaxLinkDepth)
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, resolved.Type)
}

func TestFollowLink_DepthExceeded(t *testing.T) {
	store := newMockStore()

	// Create a chain of 12 links, each pointing to the next
	var links []*Node
	for i := 0; i < 12; i++ {
		pk := makePubKey(byte(i + 1))
		var target []byte
		if i < 11 {
			target = makePubKey(byte(i + 2))
		} else {
			target = makePubKey(0xFF)
		}
		link := makeLinkNode(pk, target, LinkTypeSoft)
		links = append(links, link)
		store.addNode(link)
	}

	_, err := FollowLink(store, links[0], MaxLinkDepth)
	assert.ErrorIs(t, err, ErrLinkDepthExceeded)
}

func TestFollowLink_RemoteLink(t *testing.T) {
	store := newMockStore()
	link := &Node{
		Type:     NodeTypeLink,
		LinkType: LinkTypeSoftRemote,
		Domain:   "example.com/path",
		Metadata: make(map[string]string),
	}

	_, err := FollowLink(store, link, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrRemoteLinkNotSupported)
}

func TestFollowLink_NotLink(t *testing.T) {
	store := newMockStore()
	file := &Node{Type: NodeTypeFile, Metadata: make(map[string]string)}

	_, err := FollowLink(store, file, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrNotLink)
}

func TestFollowLink_NilStore(t *testing.T) {
	link := makeLinkNode(makePubKey(0x01), makePubKey(0x02), LinkTypeSoft)
	_, err := FollowLink(nil, link, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestFollowLink_NilNode(t *testing.T) {
	store := newMockStore()
	_, err := FollowLink(store, nil, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestFollowLink_TargetNotFound(t *testing.T) {
	store := newMockStore()
	link := makeLinkNode(makePubKey(0x01), makePubKey(0xFF), LinkTypeSoft)

	_, err := FollowLink(store, link, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrNodeNotFound)
}

func TestFollowLink_EmptyTarget(t *testing.T) {
	store := newMockStore()
	link := &Node{
		Type:       NodeTypeLink,
		LinkTarget: nil,
		Metadata:   make(map[string]string),
	}

	_, err := FollowLink(store, link, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrNodeNotFound)
}

// --- LatestVersion tests ---

func TestLatestVersion_SingleNode(t *testing.T) {
	node := &Node{BlockHeight: 100, TxID: makeTxID(0x01)}
	result := LatestVersion([]*Node{node})
	assert.Equal(t, node, result)
}

func TestLatestVersion_DifferentHeights(t *testing.T) {
	n1 := &Node{BlockHeight: 100, TxID: makeTxID(0x01)}
	n2 := &Node{BlockHeight: 200, TxID: makeTxID(0x02)}
	n3 := &Node{BlockHeight: 150, TxID: makeTxID(0x03)}

	result := LatestVersion([]*Node{n1, n2, n3})
	assert.Equal(t, n2, result, "highest block height should win")
}

func TestLatestVersion_SameHeight_DifferentTimestamp(t *testing.T) {
	n1 := &Node{BlockHeight: 100, Timestamp: 1000, TxID: makeTxID(0x01)}
	n2 := &Node{BlockHeight: 100, Timestamp: 2000, TxID: makeTxID(0x02)}

	result := LatestVersion([]*Node{n1, n2})
	assert.Equal(t, n2, result, "higher timestamp should win in same block")
}

func TestLatestVersion_SameHeightSameTimestamp_TxIDTiebreak(t *testing.T) {
	n1 := &Node{BlockHeight: 100, Timestamp: 1000, TxID: makeTxID(0x01)}
	n2 := &Node{BlockHeight: 100, Timestamp: 1000, TxID: makeTxID(0xFF)}

	result := LatestVersion([]*Node{n1, n2})
	assert.Equal(t, n2, result, "higher TxID should win as tiebreaker")
}

func TestLatestVersion_Empty(t *testing.T) {
	result := LatestVersion(nil)
	assert.Nil(t, result)
}

func TestLatestVersion_WithNils(t *testing.T) {
	n1 := &Node{BlockHeight: 100, TxID: makeTxID(0x01)}
	result := LatestVersion([]*Node{nil, n1, nil})
	assert.Equal(t, n1, result)
}

// --- InheritPricePerKB tests ---

func TestInheritPricePerKB_NodeHasPrice(t *testing.T) {
	store := newMockStore()
	node := &Node{PricePerKB: 100, Metadata: make(map[string]string)}

	price, err := InheritPricePerKB(store, node)
	require.NoError(t, err)
	assert.Equal(t, uint64(100), price)
}

func TestInheritPricePerKB_InheritFromParent(t *testing.T) {
	store := newMockStore()

	parentPK := makePubKey(0x01)
	parent := &Node{
		PNode:      parentPK,
		PricePerKB: 50,
		Metadata:   make(map[string]string),
	}
	store.addNode(parent)

	child := &Node{
		Parent:     parentPK,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}

	price, err := InheritPricePerKB(store, child)
	require.NoError(t, err)
	assert.Equal(t, uint64(50), price)
}

func TestInheritPricePerKB_InheritFromGrandparent(t *testing.T) {
	store := newMockStore()

	grandparentPK := makePubKey(0x01)
	grandparent := &Node{
		PNode:      grandparentPK,
		PricePerKB: 200,
		Metadata:   make(map[string]string),
	}
	store.addNode(grandparent)

	parentPK := makePubKey(0x02)
	parent := &Node{
		PNode:      parentPK,
		Parent:     grandparentPK,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}
	store.addNode(parent)

	child := &Node{
		Parent:     parentPK,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}

	price, err := InheritPricePerKB(store, child)
	require.NoError(t, err)
	assert.Equal(t, uint64(200), price)
}

func TestInheritPricePerKB_NoPriceAnywhere(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	root := &Node{
		PNode:      rootPK,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}
	store.addNode(root)

	child := &Node{
		Parent:     rootPK,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}

	price, err := InheritPricePerKB(store, child)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), price)
}

func TestInheritPricePerKB_NilNode(t *testing.T) {
	store := newMockStore()
	_, err := InheritPricePerKB(store, nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestInheritPricePerKB_NilStore(t *testing.T) {
	node := &Node{Metadata: make(map[string]string)}
	_, err := InheritPricePerKB(nil, node)
	assert.ErrorIs(t, err, ErrNilParam)
}

// --- ResolvePath tests ---

func TestResolvePath_EmptyPath(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	result, err := ResolvePath(store, root, []string{})
	require.NoError(t, err)
	assert.Equal(t, root, result.Node)
	assert.Empty(t, result.Path)
}

func TestResolvePath_SingleComponent(t *testing.T) {
	store := newMockStore()

	childPK := makePubKey(0x10)
	child := makeFileNode(childPK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(child)

	root := makeRootDir(makePubKey(0x01))
	root.Children = []ChildEntry{
		{Index: 0, Name: "readme.txt", Type: NodeTypeFile, PubKey: childPK},
	}

	result, err := ResolvePath(store, root, []string{"readme.txt"})
	require.NoError(t, err)
	assert.Equal(t, child, result.Node)
	assert.Equal(t, "readme.txt", result.Entry.Name)
	assert.Equal(t, root, result.Parent)
	assert.Equal(t, []string{"readme.txt"}, result.Path)
}

func TestResolvePath_NestedPath(t *testing.T) {
	store := newMockStore()

	// root/docs/report.pdf
	rootPK := makePubKey(0x01)
	docsPK := makePubKey(0x20)
	filePK := makePubKey(0x30)

	docsNode := makeDirNode(docsPK, rootPK, makeTxID(0x22))
	docsNode.Children = []ChildEntry{
		{Index: 0, Name: "report.pdf", Type: NodeTypeFile, PubKey: filePK},
	}
	store.addNode(docsNode)

	fileNode := makeFileNode(filePK, docsPK, makeTxID(0x33))
	store.addNode(fileNode)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "docs", Type: NodeTypeDir, PubKey: docsPK},
	}

	result, err := ResolvePath(store, root, []string{"docs", "report.pdf"})
	require.NoError(t, err)
	assert.Equal(t, fileNode, result.Node)
	assert.Equal(t, []string{"docs", "report.pdf"}, result.Path)
}

func TestResolvePath_DotNavigation(t *testing.T) {
	store := newMockStore()

	childPK := makePubKey(0x10)
	child := makeFileNode(childPK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(child)

	root := makeRootDir(makePubKey(0x01))
	root.Children = []ChildEntry{
		{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: childPK},
	}

	// "." should be a no-op
	result, err := ResolvePath(store, root, []string{".", "file.txt"})
	require.NoError(t, err)
	assert.Equal(t, child, result.Node)
}

func TestResolvePath_DotDotNavigation(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	subPK := makePubKey(0x10)
	filePK := makePubKey(0x20)

	subDir := makeDirNode(subPK, rootPK, makeTxID(0x11))
	store.addNode(subDir)

	file := makeFileNode(filePK, rootPK, makeTxID(0x22))
	store.addNode(file)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "sub", Type: NodeTypeDir, PubKey: subPK},
		{Index: 1, Name: "file.txt", Type: NodeTypeFile, PubKey: filePK},
	}

	// sub/../file.txt should resolve to file.txt
	result, err := ResolvePath(store, root, []string{"sub", "..", "file.txt"})
	require.NoError(t, err)
	assert.Equal(t, file, result.Node)
}

func TestResolvePath_DotDotAtRoot(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	// ".." at root should stay at root
	result, err := ResolvePath(store, root, []string{"..", ".."})
	require.NoError(t, err)
	assert.Equal(t, root, result.Node)
}

func TestResolvePath_FollowsSoftLink(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	targetPK := makePubKey(0x42)
	linkPK := makePubKey(0x30)

	target := makeFileNode(targetPK, rootPK, makeTxID(0x55))
	store.addNode(target)

	link := makeLinkNode(linkPK, targetPK, LinkTypeSoft)
	store.addNode(link)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "shortcut", Type: NodeTypeLink, PubKey: linkPK},
	}

	result, err := ResolvePath(store, root, []string{"shortcut"})
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, result.Node.Type)
	assert.Equal(t, targetPK, result.Node.PNode)
}

func TestResolvePath_ChildNotFound(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	_, err := ResolvePath(store, root, []string{"nonexistent"})
	assert.ErrorIs(t, err, ErrChildNotFound)
}

func TestResolvePath_NotDirectory(t *testing.T) {
	store := newMockStore()

	filePK := makePubKey(0x10)
	file := makeFileNode(filePK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(file)

	root := makeRootDir(makePubKey(0x01))
	root.Children = []ChildEntry{
		{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: filePK},
	}

	// Trying to traverse into a file
	_, err := ResolvePath(store, root, []string{"file.txt", "child"})
	assert.ErrorIs(t, err, ErrNotDirectory)
}

func TestResolvePath_NilStore(t *testing.T) {
	root := makeRootDir(makePubKey(0x01))
	_, err := ResolvePath(nil, root, []string{"test"})
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestResolvePath_NilRoot(t *testing.T) {
	store := newMockStore()
	_, err := ResolvePath(store, nil, []string{"test"})
	assert.ErrorIs(t, err, ErrNilParam)
}

func TestResolvePath_EmptyComponent(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	_, err := ResolvePath(store, root, []string{""})
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// --- SplitPath tests ---

func TestSplitPath(t *testing.T) {
	tests := []struct {
		path     string
		expected []string
		err      error
	}{
		{"/", []string{}, nil},
		{"/docs", []string{"docs"}, nil},
		{"/docs/report.pdf", []string{"docs", "report.pdf"}, nil},
		{"docs/report.pdf", []string{"docs", "report.pdf"}, nil},
		{"/a/b/c/d", []string{"a", "b", "c", "d"}, nil},
		{"/a//b/c", []string{"a", "b", "c"}, nil}, // consecutive slashes
		{"/trailing/", []string{"trailing"}, nil},
		{"", nil, ErrInvalidPath},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			parts, err := SplitPath(tt.path)
			if tt.err != nil {
				assert.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, parts)
			}
		})
	}
}

// --- validateChildName tests ---

func TestValidateChildName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"file.txt", false},
		{"My Document.pdf", false},
		{"a", false},
		{"file-name_v2.tar.gz", false},
		{"", true},
		{"/", true},
		{".", true},
		{"..", true},
		{"path/name", true},
		{string([]byte{0x00}), true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("name=%q", tt.name), func(t *testing.T) {
			err := validateChildName(tt.name)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- compareTxIDs tests ---

func TestCompareTxIDs(t *testing.T) {
	tests := []struct {
		a, b     []byte
		expected int
	}{
		{makeTxID(0x01), makeTxID(0x02), -1},
		{makeTxID(0x02), makeTxID(0x01), 1},
		{makeTxID(0x01), makeTxID(0x01), 0},
		{nil, nil, 0},
		{[]byte{0x01}, []byte{0x01, 0x02}, -1},
	}

	for _, tt := range tests {
		result := compareTxIDs(tt.a, tt.b)
		assert.Equal(t, tt.expected, result)
	}
}

// --- DeserializePayload edge cases ---

func TestDeserializePayload_Empty(t *testing.T) {
	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload([]byte{}, node)
	assert.NoError(t, err)
}

func TestDeserializePayload_UnknownTag(t *testing.T) {
	// Build a payload with unknown tag 0xFF (varint length)
	var buf []byte
	buf = append(buf, 0xFF, 0x02, 0x01, 0x02) // tag=0xFF, varint len=2, data=0x01,0x02
	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload(buf, node)
	assert.NoError(t, err, "unknown tags should be skipped")
}

func TestDeserializePayload_Truncated(t *testing.T) {
	// Tag present but value truncated
	buf := []byte{tagVersion, 0x04, 0x01} // says varint length 4 but only 1 byte of data
	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload(buf, node)
	assert.Error(t, err)
}

func TestDeserializePayload_RejectsHugeTLVLength(t *testing.T) {
	// Craft a TLV with tag=0x01 (version) and a uvarint-encoded length
	// that exceeds math.MaxInt when cast to int on 32-bit platforms.
	buf := []byte{0x01} // tag
	// Encode length = math.MaxUint64 as uvarint (10 bytes: 0xFF x9 + 0x01)
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01)
	// Append a few bytes of "value" (far fewer than claimed length).
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)

	node := &Node{}
	err := deserializePayload(buf, node)
	assert.Error(t, err, "should reject TLV length exceeding buffer")
	assert.Contains(t, err.Error(), "truncated")
}

// --- Integration-style test: full workflow ---

func TestFullWorkflow_CreateAndResolve(t *testing.T) {
	store := newMockStore()

	// Create root directory
	rootPK := makePubKey(0x01)
	root := makeRootDir(rootPK)
	root.TxID = makeTxID(0x01)
	store.addNode(root)

	// Add "docs" subdirectory
	docsPK := makePubKey(0x10)
	docsDir := makeDirNode(docsPK, rootPK, makeTxID(0x10))
	store.addNode(docsDir)
	_, err := AddChild(root, "docs", NodeTypeDir, docsPK, false)
	require.NoError(t, err)

	// Add "readme.txt" to docs
	readmePK := makePubKey(0x20)
	readme := makeFileNode(readmePK, docsPK, makeTxID(0x20))
	readme.MimeType = "text/plain"
	readme.FileSize = 512
	store.addNode(readme)
	_, err = AddChild(docsDir, "readme.txt", NodeTypeFile, readmePK, false)
	require.NoError(t, err)

	// Add "images" subdirectory to docs
	imagesPK := makePubKey(0x30)
	imagesDir := makeDirNode(imagesPK, docsPK, makeTxID(0x30))
	store.addNode(imagesDir)
	_, err = AddChild(docsDir, "images", NodeTypeDir, imagesPK, false)
	require.NoError(t, err)

	// Add "logo.png" to images
	logoPK := makePubKey(0x40)
	logo := makeFileNode(logoPK, imagesPK, makeTxID(0x40))
	logo.MimeType = "image/png"
	store.addNode(logo)
	_, err = AddChild(imagesDir, "logo.png", NodeTypeFile, logoPK, false)
	require.NoError(t, err)

	// Create a soft link in root -> docs/readme.txt target
	linkPK := makePubKey(0x50)
	link := makeLinkNode(linkPK, readmePK, LinkTypeSoft)
	store.addNode(link)
	_, err = AddChild(root, "quick-readme", NodeTypeLink, linkPK, false)
	require.NoError(t, err)

	// Test: resolve docs/readme.txt
	result, err := ResolvePath(store, root, []string{"docs", "readme.txt"})
	require.NoError(t, err)
	assert.Equal(t, "text/plain", result.Node.MimeType)

	// Test: resolve docs/images/logo.png
	result, err = ResolvePath(store, root, []string{"docs", "images", "logo.png"})
	require.NoError(t, err)
	assert.Equal(t, "image/png", result.Node.MimeType)

	// Test: resolve via link
	result, err = ResolvePath(store, root, []string{"quick-readme"})
	require.NoError(t, err)
	assert.Equal(t, NodeTypeFile, result.Node.Type)
	assert.Equal(t, "text/plain", result.Node.MimeType)

	// Test: navigate up with ..
	result, err = ResolvePath(store, root, []string{"docs", "images", "..", "readme.txt"})
	require.NoError(t, err)
	assert.Equal(t, "text/plain", result.Node.MimeType)

	// Test: list docs directory
	entries, err := ListDirectory(docsDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Test: remove a child
	err = RemoveChild(docsDir, "readme.txt")
	require.NoError(t, err)
	entries, err = ListDirectory(docsDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "images", entries[0].Name)

	// Test: NextChildIndex not reused
	assert.Equal(t, uint32(2), docsDir.NextChildIndex)
}

// ============================================================================
// Supplementary tests — filling critical quality gaps from AUDIT.md
// ============================================================================

// --- Priority 1: Circular link detection ---
// TestFollowLink_CircularLinks verifies that a cycle A->B->C->A is caught
// by the depth counter and returns ErrLinkDepthExceeded rather than looping forever.
func TestFollowLink_CircularLinks(t *testing.T) {
	store := newMockStore()

	pkA := makePubKey(0xA1)
	pkB := makePubKey(0xB2)
	pkC := makePubKey(0xC3)

	// A -> B -> C -> A (cycle)
	linkA := makeLinkNode(pkA, pkB, LinkTypeSoft)
	linkB := makeLinkNode(pkB, pkC, LinkTypeSoft)
	linkC := makeLinkNode(pkC, pkA, LinkTypeSoft)
	store.addNode(linkA)
	store.addNode(linkB)
	store.addNode(linkC)

	_, err := FollowLink(store, linkA, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrLinkDepthExceeded, "circular link chain must be caught by depth counter")
}

// --- Priority 2: Hard link to directory rejection ---
// TestAddChild_HardLinkToDirectory verifies that AddChild rejects creating
// a hard link (non-hardened child entry) targeting a directory node.
//
// EXPECTED TO FAIL: The spec (section 4.3) says "only FILE nodes can be
// hard-linked; directory hard links are forbidden," but AddChild currently
// does NOT validate this. This test documents the gap — AddChild should
// return ErrHardLinkToDirectory when the nodeType is NodeTypeDir and the
// entry would create a hard link (Hardened=false).
//
// TODO: Implement hard link validation in AddChild.
func TestAddChild_HardLinkToDirectory(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))

	// First add a directory child normally (hardened=true is fine)
	childPubKey := makePubKey(0x20)
	_, err := AddChild(dir, "subdir", NodeTypeDir, childPubKey, true)
	require.NoError(t, err, "hardened directory child should succeed")

	// Attempting to add another entry with the same PubKey as a DIR (hard link)
	// should be rejected because hard links to directories are forbidden.
	_, err = AddChild(dir, "subdir-link", NodeTypeDir, childPubKey, false)
	assert.ErrorIs(t, err, ErrHardLinkToDirectory,
		"hard links to directories should be rejected per spec section 4.3")
}

// --- Priority 3: InheritPricePerKB cycle guard ---
// TestInheritPricePerKB_CycleGuard verifies that if a node's Parent chain
// forms a cycle (node -> parent -> node), InheritPricePerKB does not loop
// infinitely. Currently, the implementation has NO cycle guard; it relies
// on the tree being well-formed. This test documents the risk.
func TestInheritPricePerKB_CycleGuard(t *testing.T) {
	store := newMockStore()

	pkA := makePubKey(0xA1)
	pkB := makePubKey(0xB2)

	// nodeA.Parent = pkB, nodeB.Parent = pkA => cycle
	nodeA := &Node{
		PNode:      pkA,
		Parent:     pkB,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}
	nodeB := &Node{
		PNode:      pkB,
		Parent:     pkA,
		PricePerKB: 0,
		Metadata:   make(map[string]string),
	}
	store.addNode(nodeA)
	store.addNode(nodeB)

	// This will loop forever if there's no cycle guard.
	// We run it in a goroutine with a timeout to avoid hanging the test suite.
	done := make(chan struct{})
	var price uint64
	var err error
	go func() {
		price, err = InheritPricePerKB(store, nodeA)
		close(done)
	}()

	select {
	case <-done:
		// With the cycle guard, InheritPricePerKB should return an error
		// after exceeding MaxLinkDepth iterations.
		assert.Error(t, err, "InheritPricePerKB should return an error on cyclic parent chain")
		assert.ErrorIs(t, err, ErrLinkDepthExceeded,
			"cyclic parent chain should trigger ErrLinkDepthExceeded")
		assert.Equal(t, uint64(0), price, "price should be 0 on error")
	case <-time.After(2 * time.Second):
		t.Fatal("InheritPricePerKB timed out — cycle guard not working")
	}
}

// --- Priority 4: FollowLink exactly at MaxDepth ---
// TestFollowLink_ExactlyAtMaxDepth verifies that a link chain of exactly 10
// links (MaxLinkDepth) ending with a non-link node succeeds. This is the
// boundary test for off-by-one errors.
func TestFollowLink_ExactlyAtMaxDepth(t *testing.T) {
	store := newMockStore()

	// Create a chain of 10 links, link[0] -> link[1] -> ... -> link[9] -> file
	// Total 10 hops = MaxLinkDepth, the file should be reached at the 10th iteration
	filePK := makePubKey(0xFF)
	file := makeFileNode(filePK, makePubKey(0x01), makeTxID(0xFE))
	store.addNode(file)

	// Build the chain backwards: link[9] -> file, link[8] -> link[9], etc.
	prevTarget := filePK
	var firstLink *Node
	for i := 9; i >= 0; i-- {
		pk := makePubKey(byte(0xE0 + i))
		link := makeLinkNode(pk, prevTarget, LinkTypeSoft)
		link.TxID = makeTxID(byte(0xD0 + i))
		store.addNode(link)
		prevTarget = pk
		if i == 0 {
			firstLink = link
		}
	}

	// Chain of 10 links -> file: should succeed because the loop runs MaxLinkDepth
	// iterations, and on the 10th iteration it reaches the file (non-link).
	resolved, err := FollowLink(store, firstLink, MaxLinkDepth)
	require.NoError(t, err, "chain of exactly MaxLinkDepth links to a file should succeed")
	assert.Equal(t, NodeTypeFile, resolved.Type)
	assert.Equal(t, filePK, resolved.PNode)
}

// --- Priority 5: ResolvePath — link to directory then traverse into it ---
// TestResolvePath_LinkToDirectoryThenTraverse verifies that resolving
// "link-to-dir/file.txt" works when link-to-dir points to a directory
// containing file.txt.
func TestResolvePath_LinkToDirectoryThenTraverse(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	dirPK := makePubKey(0x20)
	filePK := makePubKey(0x30)
	linkPK := makePubKey(0x40)

	// The target directory with a file child
	dir := makeDirNode(dirPK, rootPK, makeTxID(0x22))
	dir.Children = []ChildEntry{
		{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: filePK},
	}
	store.addNode(dir)

	// The file inside the directory
	file := makeFileNode(filePK, dirPK, makeTxID(0x33))
	file.MimeType = "text/plain"
	store.addNode(file)

	// Soft link targeting the directory
	link := makeLinkNode(linkPK, dirPK, LinkTypeSoft)
	store.addNode(link)

	// Root directory with the link as a child
	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "link-to-dir", Type: NodeTypeLink, PubKey: linkPK},
	}

	// Resolve "link-to-dir/file.txt": link resolves to dir, then traverse into dir for file.txt
	result, err := ResolvePath(store, root, []string{"link-to-dir", "file.txt"})
	require.NoError(t, err, "link-to-dir should resolve to a directory, then find file.txt inside it")
	assert.Equal(t, NodeTypeFile, result.Node.Type)
	assert.Equal(t, "text/plain", result.Node.MimeType)
	assert.Equal(t, []string{"link-to-dir", "file.txt"}, result.Path)
}

// --- Priority 6: ResolvePath — remote link error propagation ---
// TestResolvePath_RemoteLinkError verifies that when path traversal
// hits a remote link, ErrRemoteLinkNotSupported propagates up.
func TestResolvePath_RemoteLinkError(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	linkPK := makePubKey(0x40)

	// Remote soft link
	link := &Node{
		TxID:     makeTxID(0x44),
		PNode:    linkPK,
		Type:     NodeTypeLink,
		LinkType: LinkTypeSoftRemote,
		Domain:   "remote.example.com/path",
		Metadata: make(map[string]string),
	}
	store.addNode(link)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "remote-link", Type: NodeTypeLink, PubKey: linkPK},
	}

	_, err := ResolvePath(store, root, []string{"remote-link"})
	assert.ErrorIs(t, err, ErrRemoteLinkNotSupported,
		"remote link in path should propagate ErrRemoteLinkNotSupported")
}

// --- Priority 7: ResolvePath — depth exceeded through resolve ---
// TestResolvePath_DepthExceededError verifies that when path traversal
// encounters a link chain that exceeds max depth, ErrLinkDepthExceeded propagates.
func TestResolvePath_DepthExceededError(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)

	// Create a chain of 12 links (exceeds MaxLinkDepth)
	for i := 0; i < 12; i++ {
		pk := makePubKey(byte(0xA0 + i))
		var target []byte
		if i < 11 {
			target = makePubKey(byte(0xA0 + i + 1))
		} else {
			target = makePubKey(0xFF) // unreachable terminal
		}
		link := makeLinkNode(pk, target, LinkTypeSoft)
		link.TxID = makeTxID(byte(0xA0 + i))
		store.addNode(link)
	}

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "deep-link", Type: NodeTypeLink, PubKey: makePubKey(0xA0)},
	}

	_, err := ResolvePath(store, root, []string{"deep-link"})
	assert.ErrorIs(t, err, ErrLinkDepthExceeded,
		"link chain exceeding MaxLinkDepth should propagate ErrLinkDepthExceeded")
}

// --- Priority 8: ResolvePath — multiple ".." ---
// TestResolvePath_MultipleDotDot verifies that paths like "a/b/../../c"
// resolve correctly via multiple ".." back-navigation.
func TestResolvePath_MultipleDotDot(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	aPK := makePubKey(0x10)
	bPK := makePubKey(0x20)
	cPK := makePubKey(0x30)

	// root has children: a (dir), c (file)
	// a has child: b (dir)
	aDir := makeDirNode(aPK, rootPK, makeTxID(0x10))
	aDir.Children = []ChildEntry{
		{Index: 0, Name: "b", Type: NodeTypeDir, PubKey: bPK},
	}
	store.addNode(aDir)

	bDir := makeDirNode(bPK, aPK, makeTxID(0x20))
	store.addNode(bDir)

	cFile := makeFileNode(cPK, rootPK, makeTxID(0x30))
	cFile.MimeType = "text/csv"
	store.addNode(cFile)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "a", Type: NodeTypeDir, PubKey: aPK},
		{Index: 1, Name: "c", Type: NodeTypeFile, PubKey: cPK},
	}

	// a/b/../../c => root/c
	result, err := ResolvePath(store, root, []string{"a", "b", "..", "..", "c"})
	require.NoError(t, err, "a/b/../../c should resolve to root/c")
	assert.Equal(t, NodeTypeFile, result.Node.Type)
	assert.Equal(t, "text/csv", result.Node.MimeType)
}

// --- Priority 9: RenameChild — nil node ---
func TestRenameChild_NilDir(t *testing.T) {
	err := RenameChild(nil, "old", "new")
	assert.ErrorIs(t, err, ErrNilParam,
		"RenameChild on nil directory should return ErrNilParam")
}

// --- Priority 10: NextChildIndex — nil node ---
func TestNextChildIndex_NilDir(t *testing.T) {
	_, err := NextChildIndex(nil)
	assert.ErrorIs(t, err, ErrNilParam,
		"NextChildIndex on nil directory should return ErrNilParam")
}

// ============================================================================
// Additional gap tests from AUDIT.md (medium/high priority)
// ============================================================================

// TestFollowLink_SoftLinkToDirectory verifies that a soft link pointing
// to a directory node resolves correctly (not just files).
func TestFollowLink_SoftLinkToDirectory(t *testing.T) {
	store := newMockStore()

	dirPK := makePubKey(0x42)
	dir := makeDirNode(dirPK, makePubKey(0x01), makeTxID(0x55))
	dir.Children = []ChildEntry{
		{Index: 0, Name: "child.txt", Type: NodeTypeFile, PubKey: makePubKey(0x99)},
	}
	store.addNode(dir)

	link := makeLinkNode(makePubKey(0x30), dirPK, LinkTypeSoft)

	resolved, err := FollowLink(store, link, MaxLinkDepth)
	require.NoError(t, err, "soft link to directory should resolve successfully")
	assert.Equal(t, NodeTypeDir, resolved.Type)
	assert.Equal(t, dirPK, resolved.PNode)
	assert.Len(t, resolved.Children, 1)
}

// TestFollowLink_MaxDepthZero verifies that maxDepth=0 is treated as MaxLinkDepth.
func TestFollowLink_MaxDepthZero(t *testing.T) {
	store := newMockStore()

	filePK := makePubKey(0x42)
	file := makeFileNode(filePK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(file)

	link := makeLinkNode(makePubKey(0x30), filePK, LinkTypeSoft)

	// maxDepth=0 should be treated as MaxLinkDepth per the code: if maxDepth <= 0 { maxDepth = MaxLinkDepth }
	resolved, err := FollowLink(store, link, 0)
	require.NoError(t, err, "maxDepth=0 should default to MaxLinkDepth and resolve successfully")
	assert.Equal(t, NodeTypeFile, resolved.Type)
}

// TestFollowLink_MaxDepthOne verifies that maxDepth=1 resolves a single link
// but fails on a chained link.
func TestFollowLink_MaxDepthOne(t *testing.T) {
	store := newMockStore()

	filePK := makePubKey(0x42)
	file := makeFileNode(filePK, makePubKey(0x01), makeTxID(0x55))
	store.addNode(file)

	// Single link -> file: should succeed with maxDepth=1
	link1 := makeLinkNode(makePubKey(0x30), filePK, LinkTypeSoft)
	resolved, err := FollowLink(store, link1, 1)
	require.NoError(t, err, "single link with maxDepth=1 should succeed")
	assert.Equal(t, NodeTypeFile, resolved.Type)

	// Chained: link2 -> link1 -> file: should fail with maxDepth=1
	link1PK := makePubKey(0x30)
	store.addNode(link1)
	link2 := makeLinkNode(makePubKey(0x20), link1PK, LinkTypeSoft)

	_, err = FollowLink(store, link2, 1)
	assert.ErrorIs(t, err, ErrLinkDepthExceeded,
		"chained link with maxDepth=1 should exceed depth")
}

// TestLatestVersion_AllNils verifies that a slice of all nil entries returns nil
// without panic.
func TestLatestVersion_AllNils(t *testing.T) {
	result := LatestVersion([]*Node{nil, nil, nil})
	assert.Nil(t, result, "all-nil list should return nil")
}

// TestLatestVersion_UnconfirmedVsConfirmed verifies that a confirmed node
// (BlockHeight>0) wins over an unconfirmed node (BlockHeight=0).
func TestLatestVersion_UnconfirmedVsConfirmed(t *testing.T) {
	unconfirmed := &Node{BlockHeight: 0, Timestamp: 9999, TxID: makeTxID(0xFF)}
	confirmed := &Node{BlockHeight: 100, Timestamp: 1000, TxID: makeTxID(0x01)}

	result := LatestVersion([]*Node{unconfirmed, confirmed})
	assert.Equal(t, confirmed, result,
		"confirmed node (BlockHeight>0) should win over unconfirmed (BlockHeight=0)")
}

// TestRemoveChild_MiddlePreservesOrder verifies that removing a child from
// the middle of the children list preserves the order of remaining entries.
func TestRemoveChild_MiddlePreservesOrder(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "a.txt", NodeTypeFile, makePubKey(0x10), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "b.txt", NodeTypeFile, makePubKey(0x11), false)
	require.NoError(t, err)
	_, err = AddChild(dir, "c.txt", NodeTypeFile, makePubKey(0x12), false)
	require.NoError(t, err)

	err = RemoveChild(dir, "b.txt")
	require.NoError(t, err)

	assert.Len(t, dir.Children, 2)
	assert.Equal(t, "a.txt", dir.Children[0].Name, "first child preserved")
	assert.Equal(t, "c.txt", dir.Children[1].Name, "third child preserved after middle removal")
	assert.Equal(t, uint32(0), dir.Children[0].Index, "first child index preserved")
	assert.Equal(t, uint32(2), dir.Children[1].Index, "third child index preserved")
}

// TestRenameChild_PreservesFields verifies that renaming preserves all
// non-name fields (Index, Type, PubKey, Hardened).
func TestRenameChild_PreservesFields(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	pk := makePubKey(0x10)
	_, err := AddChild(dir, "original.txt", NodeTypeFile, pk, true)
	require.NoError(t, err)

	// Record original values
	origEntry, found := FindChild(dir, "original.txt")
	require.True(t, found)
	origIndex := origEntry.Index
	origType := origEntry.Type
	origPubKey := make([]byte, len(origEntry.PubKey))
	copy(origPubKey, origEntry.PubKey)
	origHardened := origEntry.Hardened

	err = RenameChild(dir, "original.txt", "renamed.txt")
	require.NoError(t, err)

	entry, found := FindChild(dir, "renamed.txt")
	require.True(t, found)
	assert.Equal(t, origIndex, entry.Index, "Index should be preserved")
	assert.Equal(t, origType, entry.Type, "Type should be preserved")
	assert.Equal(t, origPubKey, entry.PubKey, "PubKey should be preserved")
	assert.Equal(t, origHardened, entry.Hardened, "Hardened should be preserved")
}

// TestAddChild_NilPubKey verifies that AddChild with nil PubKey returns ErrInvalidPubKey.
func TestAddChild_NilPubKey(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, "file.txt", NodeTypeFile, nil, false)
	assert.ErrorIs(t, err, ErrInvalidPubKey,
		"nil PubKey (length 0) should return ErrInvalidPubKey")
}

// TestAddChild_PubKeyCopied verifies that mutating the original PubKey slice
// after AddChild does not affect the stored entry.
func TestAddChild_PubKeyCopied(t *testing.T) {
	dir := makeRootDir(makePubKey(0x01))
	pk := makePubKey(0x10)
	_, err := AddChild(dir, "file.txt", NodeTypeFile, pk, false)
	require.NoError(t, err)

	// Mutate the original PubKey
	pk[0] = 0xFF
	pk[1] = 0xFF

	// Stored entry should NOT be affected
	entry, found := FindChild(dir, "file.txt")
	require.True(t, found)
	assert.Equal(t, byte(0x02), entry.PubKey[0], "stored PubKey should not be affected by caller mutation")
	assert.Equal(t, byte(0x10), entry.PubKey[1], "stored PubKey should be an independent copy")
}

// TestListDirectory_LinkNode verifies that ListDirectory on a LINK node
// returns ErrNotDirectory.
func TestListDirectory_LinkNode(t *testing.T) {
	link := &Node{Type: NodeTypeLink, Metadata: make(map[string]string)}
	_, err := ListDirectory(link)
	assert.ErrorIs(t, err, ErrNotDirectory,
		"ListDirectory on LINK node should return ErrNotDirectory")
}

// TestFindChild_EmptyChildren verifies that FindChild on a dir with nil
// (empty) Children returns false without panic.
func TestFindChild_EmptyChildren(t *testing.T) {
	dir := &Node{Type: NodeTypeDir, Children: nil, Metadata: make(map[string]string)}
	_, found := FindChild(dir, "anything")
	assert.False(t, found, "FindChild on dir with nil Children should return false")
}

// TestSerializePayload_RemoteLinkWithDomain verifies that a remote link
// with Domain field round-trips correctly through serialize/deserialize.
func TestSerializePayload_RemoteLinkWithDomain(t *testing.T) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeLink,
		Op:         OpCreate,
		LinkTarget: makePubKey(0x42),
		LinkType:   LinkTypeSoftRemote,
		Domain:     "cdn.example.com/files",
		Metadata:   make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeLink, decoded.Type)
	assert.Equal(t, LinkTypeSoftRemote, decoded.LinkType)
	assert.Equal(t, node.LinkTarget, decoded.LinkTarget)
	assert.Equal(t, "cdn.example.com/files", decoded.Domain)
}

// TestResolvePath_DotAndDotDotMixed verifies that mixed "." and ".."
// components resolve correctly, e.g., "./a/.././b" resolves to "b".
func TestResolvePath_DotAndDotDotMixed(t *testing.T) {
	store := newMockStore()

	rootPK := makePubKey(0x01)
	aPK := makePubKey(0x10)
	bPK := makePubKey(0x20)

	aDir := makeDirNode(aPK, rootPK, makeTxID(0x10))
	store.addNode(aDir)

	bFile := makeFileNode(bPK, rootPK, makeTxID(0x20))
	bFile.MimeType = "text/plain"
	store.addNode(bFile)

	root := makeRootDir(rootPK)
	root.Children = []ChildEntry{
		{Index: 0, Name: "a", Type: NodeTypeDir, PubKey: aPK},
		{Index: 1, Name: "b", Type: NodeTypeFile, PubKey: bPK},
	}

	// ./a/.././b => "." no-op, "a" enter dir, ".." back to root, "." no-op, "b" resolve file
	result, err := ResolvePath(store, root, []string{".", "a", "..", ".", "b"})
	require.NoError(t, err, "./a/.././b should resolve to b")
	assert.Equal(t, NodeTypeFile, result.Node.Type)
	assert.Equal(t, "text/plain", result.Node.MimeType)
}

// TestResolvePath_RootResult verifies that resolving empty path returns
// nil Entry and nil Parent for the root node.
func TestResolvePath_RootResult(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	result, err := ResolvePath(store, root, []string{})
	require.NoError(t, err)
	assert.Equal(t, root, result.Node)
	assert.Nil(t, result.Entry, "root resolution should have nil Entry")
	assert.Nil(t, result.Parent, "root resolution should have nil Parent")
	assert.Empty(t, result.Path, "root resolution should have empty Path")
}

func TestResolvePath_RejectsExcessiveDepth(t *testing.T) {
	store := newMockStore()
	root := makeRootDir(makePubKey(0x01))

	// Build a path with 257 components -- exceeds MaxPathComponents.
	components := make([]string, 257)
	for i := range components {
		components[i] = "a"
	}

	_, err := ResolvePath(store, root, components)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too deep")
}

// TestValidateChildName_Unicode verifies that Unicode characters (Chinese, emoji)
// are accepted as valid child names.
func TestValidateChildName_Unicode(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"文档.pdf", false},
		{"数据目录", false},
		{"report-2026-日本語.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChildName(tt.name)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err, "Unicode name should be accepted")
			}
		})
	}
}

// TestValidateChildName_RejectsLongName verifies that names exceeding MaxChildNameLen are rejected.
func TestValidateChildName_RejectsLongName(t *testing.T) {
	longName := strings.Repeat("a", 256)
	dir := makeRootDir(makePubKey(0x01))
	_, err := AddChild(dir, longName, NodeTypeFile, makePubKey(0x10), false)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidName)
	assert.Contains(t, err.Error(), "too long")
}

// TestValidateChildName_Accepts255ByteName verifies that a 255-byte name is accepted.
func TestValidateChildName_Accepts255ByteName(t *testing.T) {
	name255 := strings.Repeat("b", 255)
	dir := makeRootDir(makePubKey(0x01))
	entry, err := AddChild(dir, name255, NodeTypeFile, makePubKey(0x10), false)
	assert.NoError(t, err)
	assert.Equal(t, name255, entry.Name)
}

// TestSplitPath_WhitespaceOnly verifies that SplitPath with whitespace-only
// input treats whitespace as a valid path component.
func TestSplitPath_WhitespaceOnly(t *testing.T) {
	parts, err := SplitPath(" ")
	require.NoError(t, err)
	assert.Equal(t, []string{" "}, parts,
		"whitespace is valid per current implementation")
}

// TestParseNodeFromPushesWithTxID_InvalidTxIDLength verifies that a TxID
// with length != 32 is silently ignored (documents current behavior).
func TestParseNodeFromPushesWithTxID_InvalidTxIDLength(t *testing.T) {
	pNode := makePubKey(0x01)
	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Metadata: make(map[string]string),
	}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	pushes := [][]byte{tx.MetaFlagBytes, pNode, nil, payload}

	// TxID with wrong length (16 bytes instead of 32)
	shortTxID := make([]byte, 16)
	for i := range shortTxID {
		shortTxID[i] = 0xAB
	}

	parsed, err := ParseNodeFromPushesWithTxID(pushes, shortTxID)
	require.NoError(t, err, "invalid TxID length should not cause an error")
	assert.Nil(t, parsed.TxID, "TxID with wrong length should be silently ignored")
}

// TestFollowLink_TwoNodeCycle verifies that a simple two-node cycle (A->B->A)
// is caught by the depth counter.
func TestFollowLink_TwoNodeCycle(t *testing.T) {
	store := newMockStore()

	pkA := makePubKey(0xA1)
	pkB := makePubKey(0xB2)

	linkA := makeLinkNode(pkA, pkB, LinkTypeSoft)
	linkA.TxID = makeTxID(0xA1)
	linkB := makeLinkNode(pkB, pkA, LinkTypeSoft)
	linkB.TxID = makeTxID(0xB2)
	store.addNode(linkA)
	store.addNode(linkB)

	_, err := FollowLink(store, linkA, MaxLinkDepth)
	assert.ErrorIs(t, err, ErrLinkDepthExceeded,
		"two-node cycle A->B->A should be caught by depth counter")
}

// --- validateChildName control character tests ---

func TestValidateChildName_RejectsControlChars(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"tab", "foo\tbar", true},
		{"newline", "foo\nbar", true},
		{"carriage return", "foo\rbar", true},
		{"escape", "foo\x1bbar", true},
		{"unicode RTL override", "foo\u202ebar", true},
		{"unicode LTR override", "foo\u202dbar", true},
		{"unicode zero-width joiner", "foo\u200dbar", true},
		{"valid ascii", "hello-world_123.txt", false},
		{"valid unicode", "日本語ファイル.txt", false},
		{"valid emoji", "📁data", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChildName(tt.input)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrInvalidName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkSerializePayload(b *testing.B) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeDir,
		Op:         OpCreate,
		MimeType:   "application/octet-stream",
		FileSize:   1048576,
		KeyHash:    bytes.Repeat([]byte{0xBB}, 32),
		Access:     AccessPaid,
		PricePerKB: 100,
		Timestamp:  1700000000,
		Parent:     makePubKey(0x01),
		Index:      5,
		Children: []ChildEntry{
			{Index: 0, Name: "readme.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10), Hardened: false},
			{Index: 1, Name: "docs", Type: NodeTypeDir, PubKey: makePubKey(0x20), Hardened: true},
		},
		NextChildIndex: 2,
		Domain:         "example.com",
		Description:    "Test directory",
		Encrypted:      true,
		Metadata:       make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SerializePayload(node)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeserializePayload(b *testing.B) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeDir,
		Op:         OpCreate,
		MimeType:   "application/octet-stream",
		FileSize:   1048576,
		KeyHash:    bytes.Repeat([]byte{0xBB}, 32),
		Access:     AccessPaid,
		PricePerKB: 100,
		Timestamp:  1700000000,
		Parent:     makePubKey(0x01),
		Index:      5,
		Children: []ChildEntry{
			{Index: 0, Name: "readme.txt", Type: NodeTypeFile, PubKey: makePubKey(0x10), Hardened: false},
			{Index: 1, Name: "docs", Type: NodeTypeDir, PubKey: makePubKey(0x20), Hardened: true},
		},
		NextChildIndex: 2,
		Domain:         "example.com",
		Description:    "Test directory",
		Encrypted:      true,
		Metadata:       make(map[string]string),
	}

	payload, err := SerializePayload(node)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoded := &Node{Metadata: make(map[string]string)}
		if err := deserializePayload(payload, decoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSerializeDeserializeRoundTrip(b *testing.B) {
	node := &Node{
		Version:    1,
		Type:       NodeTypeFile,
		Op:         OpCreate,
		MimeType:   "text/plain",
		FileSize:   4096,
		KeyHash:    bytes.Repeat([]byte{0xDD}, 32),
		Access:     AccessPaid,
		PricePerKB: 50,
		Timestamp:  1700000000,
		Parent:     makePubKey(0x01),
		Index:      3,
		Encrypted:  true,
		Metadata:   make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload, err := SerializePayload(node)
		if err != nil {
			b.Fatal(err)
		}
		decoded := &Node{Metadata: make(map[string]string)}
		if err := deserializePayload(payload, decoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseNode(b *testing.B) {
	pNode := makePubKey(0x01)
	parentTxID := makeTxID(0x02)

	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Op:       OpCreate,
		MimeType: "text/plain",
		FileSize: 256,
		KeyHash:  bytes.Repeat([]byte{0xDD}, 32),
		Metadata: make(map[string]string),
	}

	payload, err := SerializePayload(node)
	if err != nil {
		b.Fatal(err)
	}

	pushes := [][]byte{
		tx.MetaFlagBytes,
		pNode,
		parentTxID,
		payload,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseNode(pushes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddChild(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dir := makeRootDir(makePubKey(0x01))
		b.StartTimer()
		_, err := AddChild(dir, "file.txt", NodeTypeFile, makePubKey(0x10), false)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindChild(b *testing.B) {
	dir := makeRootDir(makePubKey(0x01))
	for i := 0; i < 100; i++ {
		pk := makePubKey(byte(i + 10))
		name := fmt.Sprintf("file-%03d.txt", i)
		_, _ = AddChild(dir, name, NodeTypeFile, pk, false)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindChild(dir, "file-050.txt")
	}
}
