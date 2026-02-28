package metanet

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bitfsorg/libbitfs-go/tx"
)

func TestNodeTypeAnchor_String(t *testing.T) {
	assert.Equal(t, "ANCHOR", NodeTypeAnchor.String())
}

func TestNodeTypeAnchor_Value(t *testing.T) {
	assert.Equal(t, NodeType(3), NodeTypeAnchor)
}

func TestSerializePayload_AnchorNode_RoundTrip(t *testing.T) {
	original := &Node{
		Version:       1,
		Type:          NodeTypeAnchor,
		Op:            OpCreate,
		Timestamp:     1700000000,
		TreeRootPNode: makePubKey(0x10),
		TreeRootTxID:  makeTxID(0x20),
		ParentAnchorTxID: [][]byte{
			makeTxID(0x30),
		},
		Author:        "Alice <alice@example.com>",
		CommitMessage: "Initial commit",
		GitCommitSHA:  bytes.Repeat([]byte{0xab}, 20),
		FileMode:      0o100644,
		Metadata:      make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	// Deserialize into a new node.
	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Version, parsed.Version)
	assert.Equal(t, original.Type, parsed.Type)
	assert.Equal(t, original.Op, parsed.Op)
	assert.Equal(t, original.Timestamp, parsed.Timestamp)
	assert.Equal(t, original.TreeRootPNode, parsed.TreeRootPNode)
	assert.Equal(t, original.TreeRootTxID, parsed.TreeRootTxID)
	require.Len(t, parsed.ParentAnchorTxID, 1)
	assert.Equal(t, original.ParentAnchorTxID[0], parsed.ParentAnchorTxID[0])
	assert.Equal(t, original.Author, parsed.Author)
	assert.Equal(t, original.CommitMessage, parsed.CommitMessage)
	assert.Equal(t, original.GitCommitSHA, parsed.GitCommitSHA)
	assert.Equal(t, original.FileMode, parsed.FileMode)
}

func TestSerializePayload_AnchorNode_MergeParents(t *testing.T) {
	// Merge commit: 3 parent anchors.
	original := &Node{
		Version: 1,
		Type:    NodeTypeAnchor,
		Op:      OpCreate,
		ParentAnchorTxID: [][]byte{
			makeTxID(0xaa),
			makeTxID(0xbb),
			makeTxID(0xcc),
		},
		Author:        "Bob <bob@example.com>",
		CommitMessage: "Merge branches",
		TreeRootPNode: makePubKey(0x50),
		TreeRootTxID:  makeTxID(0x60),
		GitCommitSHA:  bytes.Repeat([]byte{0xdd}, 20),
		Metadata:      make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	require.Len(t, parsed.ParentAnchorTxID, 3)
	assert.Equal(t, makeTxID(0xaa), parsed.ParentAnchorTxID[0])
	assert.Equal(t, makeTxID(0xbb), parsed.ParentAnchorTxID[1])
	assert.Equal(t, makeTxID(0xcc), parsed.ParentAnchorTxID[2])
}

func TestSerializePayload_AnchorNode_AllFields(t *testing.T) {
	original := &Node{
		Version:       2,
		Type:          NodeTypeAnchor,
		Op:            OpUpdate,
		MimeType:      "application/x-git-commit",
		Timestamp:     1700000000,
		Domain:        "example.com",
		Description:   "test anchor node",
		TreeRootPNode: makePubKey(0x11),
		TreeRootTxID:  makeTxID(0x22),
		ParentAnchorTxID: [][]byte{
			makeTxID(0x33),
			makeTxID(0x44),
		},
		Author:        "Charlie <charlie@example.com>",
		CommitMessage: "Update README.md\n\nAdded new section about setup.",
		GitCommitSHA:  bytes.Repeat([]byte{0xef}, 20),
		FileMode:      0o100755,
		Metadata:      make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	// Verify all fields survived the roundtrip.
	assert.Equal(t, original.Version, parsed.Version)
	assert.Equal(t, original.Type, parsed.Type)
	assert.Equal(t, original.Op, parsed.Op)
	assert.Equal(t, original.MimeType, parsed.MimeType)
	assert.Equal(t, original.Timestamp, parsed.Timestamp)
	assert.Equal(t, original.Domain, parsed.Domain)
	assert.Equal(t, original.Description, parsed.Description)
	assert.Equal(t, original.TreeRootPNode, parsed.TreeRootPNode)
	assert.Equal(t, original.TreeRootTxID, parsed.TreeRootTxID)
	require.Len(t, parsed.ParentAnchorTxID, 2)
	assert.Equal(t, original.ParentAnchorTxID[0], parsed.ParentAnchorTxID[0])
	assert.Equal(t, original.ParentAnchorTxID[1], parsed.ParentAnchorTxID[1])
	assert.Equal(t, original.Author, parsed.Author)
	assert.Equal(t, original.CommitMessage, parsed.CommitMessage)
	assert.Equal(t, original.GitCommitSHA, parsed.GitCommitSHA)
	assert.Equal(t, original.FileMode, parsed.FileMode)
}

func TestSerializePayload_AnchorNode_ParseNode(t *testing.T) {
	// Full roundtrip through ParseNode (via OP_RETURN pushes).
	original := &Node{
		Version:       1,
		Type:          NodeTypeAnchor,
		Op:            OpCreate,
		TreeRootPNode: makePubKey(0x10),
		TreeRootTxID:  makeTxID(0x20),
		Author:        "Alice",
		CommitMessage: "test commit",
		GitCommitSHA:  bytes.Repeat([]byte{0xab}, 20),
		FileMode:      0o100644,
		Metadata:      make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	// Build OP_RETURN pushes.
	pNode := makePubKey(0x01)
	parentTxID := makeTxID(0x02)
	pushes := [][]byte{
		tx.MetaFlagBytes,
		pNode,
		parentTxID,
		payload,
	}

	parsed, err := ParseNode(pushes)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeAnchor, parsed.Type)
	assert.Equal(t, original.TreeRootPNode, parsed.TreeRootPNode)
	assert.Equal(t, original.TreeRootTxID, parsed.TreeRootTxID)
	assert.Equal(t, original.Author, parsed.Author)
	assert.Equal(t, original.CommitMessage, parsed.CommitMessage)
	assert.Equal(t, original.GitCommitSHA, parsed.GitCommitSHA)
	assert.Equal(t, original.FileMode, parsed.FileMode)
}

func TestSerializePayload_AnchorNode_EmptyOptionalFields(t *testing.T) {
	// Anchor node with only required fields.
	original := &Node{
		Version:  1,
		Type:     NodeTypeAnchor,
		Op:       OpCreate,
		Metadata: make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeAnchor, parsed.Type)
	assert.Nil(t, parsed.TreeRootPNode)
	assert.Nil(t, parsed.TreeRootTxID)
	assert.Empty(t, parsed.ParentAnchorTxID)
	assert.Empty(t, parsed.Author)
	assert.Empty(t, parsed.CommitMessage)
	assert.Nil(t, parsed.GitCommitSHA)
	assert.Equal(t, uint32(0), parsed.FileMode)
}

// --- Regression tests: existing node types still work ---

func TestSerializePayload_FileNode_Regression(t *testing.T) {
	original := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Op:       OpCreate,
		MimeType: "text/plain",
		FileSize: 1024,
		KeyHash:  bytes.Repeat([]byte{0xab}, 32),
		Access:   AccessPrivate,
		Metadata: make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeFile, parsed.Type)
	assert.Equal(t, "text/plain", parsed.MimeType)
	assert.Equal(t, uint64(1024), parsed.FileSize)
	assert.Equal(t, original.KeyHash, parsed.KeyHash)
	// Anchor fields should be empty.
	assert.Nil(t, parsed.TreeRootPNode)
	assert.Nil(t, parsed.GitCommitSHA)
}

func TestSerializePayload_DirNode_Regression(t *testing.T) {
	original := &Node{
		Version: 1,
		Type:    NodeTypeDir,
		Op:      OpCreate,
		Children: []ChildEntry{
			{Index: 0, Name: "file.txt", Type: NodeTypeFile, PubKey: makePubKey(0x30)},
		},
		NextChildIndex: 1,
		Metadata:       make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeDir, parsed.Type)
	require.Len(t, parsed.Children, 1)
	assert.Equal(t, "file.txt", parsed.Children[0].Name)
	assert.Equal(t, uint32(1), parsed.NextChildIndex)
	// Anchor fields should be empty.
	assert.Nil(t, parsed.TreeRootPNode)
	assert.Empty(t, parsed.Author)
}

func TestSerializePayload_LinkNode_Regression(t *testing.T) {
	original := &Node{
		Version:    1,
		Type:       NodeTypeLink,
		Op:         OpCreate,
		LinkTarget: makePubKey(0x50),
		LinkType:   LinkTypeSoft,
		Metadata:   make(map[string]string),
	}

	payload, err := SerializePayload(original)
	require.NoError(t, err)

	parsed := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, parsed)
	require.NoError(t, err)

	assert.Equal(t, NodeTypeLink, parsed.Type)
	assert.Equal(t, original.LinkTarget, parsed.LinkTarget)
	assert.Equal(t, LinkTypeSoft, parsed.LinkType)
	// Anchor fields should be empty.
	assert.Nil(t, parsed.TreeRootPNode)
	assert.Empty(t, parsed.CommitMessage)
}

func TestNodeTypeConstants_NoOverlap(t *testing.T) {
	// Ensure all node type constants are distinct.
	types := []NodeType{NodeTypeFile, NodeTypeDir, NodeTypeLink, NodeTypeAnchor}
	seen := make(map[NodeType]bool)
	for _, nt := range types {
		assert.False(t, seen[nt], "duplicate NodeType value: %d", nt)
		seen[nt] = true
	}
}

func TestNodeTypeString_AllTypes(t *testing.T) {
	tests := []struct {
		nt       NodeType
		expected string
	}{
		{NodeTypeFile, "FILE"},
		{NodeTypeDir, "DIR"},
		{NodeTypeLink, "LINK"},
		{NodeTypeAnchor, "ANCHOR"},
		{NodeType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.nt.String())
		})
	}
}
