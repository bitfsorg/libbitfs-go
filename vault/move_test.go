package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMoveTestEngine sets up a test engine with root, /src, /dst directories,
// and a file at /src/file.txt. Returns the engine. Multiple fee UTXOs are
// pre-loaded to support cross-directory moves (atomic batch with 4 ops).
func setupMoveTestEngine(t *testing.T) *Engine {
	t.Helper()
	eng := initTestEngine(t)

	// Add many fee UTXOs — cross-directory moves need several.
	for i := 0; i < 10; i++ {
		addFeeUTXO(t, eng, 100000)
	}

	// Create root directory.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err != nil {
		t.Fatalf("Mkdir /: %v", err)
	}

	// Create /src directory.
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/src"})
	if err != nil {
		t.Fatalf("Mkdir /src: %v", err)
	}

	// Create /dst directory.
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/dst"})
	if err != nil {
		t.Fatalf("Mkdir /dst: %v", err)
	}

	// Create a local test file and upload it to /src/file.txt.
	testFile := filepath.Join(eng.DataDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/src/file.txt",
		Access:     "free",
	})
	if err != nil {
		t.Fatalf("PutFile /src/file.txt: %v", err)
	}

	return eng
}

func TestMove_SameDirectory(t *testing.T) {
	eng := setupMoveTestEngine(t)

	// Rename /src/file.txt to /src/renamed.txt (same directory).
	result, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/src/renamed.txt",
	})
	if err != nil {
		t.Fatalf("Move same-dir: %v", err)
	}

	if result.TxHex == "" {
		t.Error("expected non-empty TxHex")
	}
	if result.TxID == "" {
		t.Error("expected non-empty TxID")
	}
	if !strings.Contains(result.Message, "Moved") {
		t.Errorf("message should contain 'Moved', got: %s", result.Message)
	}

	// Verify old path is gone and new path exists.
	old := eng.State.FindNodeByPath("/src/file.txt")
	if old != nil {
		t.Error("old path /src/file.txt should no longer resolve")
	}
	newNode := eng.State.FindNodeByPath("/src/renamed.txt")
	if newNode == nil {
		t.Error("new path /src/renamed.txt should exist")
	}

	// Verify the parent's children list reflects the rename.
	srcDir := eng.State.FindNodeByPath("/src")
	if srcDir == nil {
		t.Fatal("/src directory not found")
	}
	found := false
	for _, c := range srcDir.Children {
		if c.Name == "renamed.txt" {
			found = true
		}
		if c.Name == "file.txt" {
			t.Error("old name 'file.txt' should not be in /src children")
		}
	}
	if !found {
		t.Error("'renamed.txt' should be in /src children")
	}
}

func TestMove_CrossDirectory(t *testing.T) {
	eng := setupMoveTestEngine(t)

	// Snapshot source node identity before the move.
	srcNode := eng.State.FindNodeByPath("/src/file.txt")
	require.NotNil(t, srcNode, "source node /src/file.txt not found")
	originalPubKey := srcNode.PubKeyHex
	originalTxID := srcNode.TxID

	// Cross-directory move: DELETE old + CreateChild at destination with new identity.
	result, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/dst/file.txt",
		Force:      true,
	})
	require.NoError(t, err, "Move cross-dir")

	assert.NotEmpty(t, result.TxHex, "expected non-empty TxHex")
	assert.NotEmpty(t, result.TxID, "expected non-empty TxID")
	assert.Contains(t, result.Message, "atomic", "message should mention '4 txs', got: %s", result.Message)

	// Verify the new node exists at destination with a NEW pubkey (not original).
	movedNode := eng.State.FindNodeByPath("/dst/file.txt")
	require.NotNil(t, movedNode, "moved node /dst/file.txt should exist")
	assert.NotEqual(t, originalPubKey, movedNode.PubKeyHex, "cross-dir move must assign new identity")

	// New node has a different TxID (it's a new CreateChild transaction).
	assert.NotEqual(t, originalTxID, movedNode.TxID, "moved node must have new TxID")
	// KeyHash is content-based (SHA256(SHA256(plaintext))), so it stays the same
	// for free-access files with identical content. The ciphertext is different
	// because it's encrypted with the new node's ECDH key.
	assert.NotEmpty(t, movedNode.KeyHash, "moved node must have a key hash")

	// The old path should no longer resolve.
	oldNode := eng.State.FindNodeByPath("/src/file.txt")
	assert.Nil(t, oldNode, "old path /src/file.txt should no longer resolve")

	// Verify /src no longer lists file.txt.
	srcDir := eng.State.FindNodeByPath("/src")
	require.NotNil(t, srcDir, "/src directory not found")
	for _, c := range srcDir.Children {
		assert.NotEqual(t, "file.txt", c.Name, "'file.txt' should have been removed from /src children")
	}

	// Verify /dst now lists file.txt with the NEW pubkey (not original).
	dstDir := eng.State.FindNodeByPath("/dst")
	require.NotNil(t, dstDir, "/dst directory not found")
	found := false
	for _, c := range dstDir.Children {
		if c.Name == "file.txt" {
			found = true
			assert.NotEqual(t, originalPubKey, c.PubKey, "child pubkey must be NEW (not original)")
			assert.Equal(t, movedNode.PubKeyHex, c.PubKey, "child pubkey must match moved node")
		}
	}
	assert.True(t, found, "'file.txt' should be in /dst children")
}

func TestMove_CrossDirectory_WithRename(t *testing.T) {
	eng := setupMoveTestEngine(t)

	// Snapshot original identity.
	srcNode := eng.State.FindNodeByPath("/src/file.txt")
	require.NotNil(t, srcNode)
	originalPubKey := srcNode.PubKeyHex

	// Move /src/file.txt to /dst/newname.txt (cross-directory + rename).
	result, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/dst/newname.txt",
		Force:      true,
	})
	require.NoError(t, err, "Move cross-dir with rename")

	assert.NotEmpty(t, result.TxID, "expected non-empty TxID")
	assert.Contains(t, result.Message, "atomic", "message should mention '4 txs'")

	// Verify the node exists at the new path with a NEW pubkey.
	movedNode := eng.State.FindNodeByPath("/dst/newname.txt")
	require.NotNil(t, movedNode, "moved node /dst/newname.txt should exist")
	assert.NotEqual(t, originalPubKey, movedNode.PubKeyHex, "cross-dir move must assign new identity")

	// Old path gone.
	assert.Nil(t, eng.State.FindNodeByPath("/src/file.txt"), "old path should no longer resolve")

	// Verify the child entry in /dst has the new name with new pubkey.
	dstDir := eng.State.FindNodeByPath("/dst")
	require.NotNil(t, dstDir, "/dst directory not found")
	found := false
	for _, c := range dstDir.Children {
		if c.Name == "newname.txt" {
			found = true
			assert.NotEqual(t, originalPubKey, c.PubKey, "child pubkey must be NEW")
			assert.Equal(t, movedNode.PubKeyHex, c.PubKey, "child pubkey must match moved node")
		}
	}
	assert.True(t, found, "'newname.txt' should be in /dst children")
}

func TestMove_CrossDirectory_SourceNodeNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/dir1/nonexistent",
		DstPath:    "/dir2/nonexistent",
	})
	if err == nil {
		t.Error("Move with missing source should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestMove_CrossDirectory_DstDirNotFound(t *testing.T) {
	eng := setupMoveTestEngine(t)

	_, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/nonexistent/file.txt",
	})
	if err == nil {
		t.Error("Move to nonexistent destination dir should fail")
	}
	if !strings.Contains(err.Error(), "destination directory") {
		t.Errorf("error should mention 'destination directory', got: %v", err)
	}
}

func TestMove_CrossDirectory_SrcDirNotFound(t *testing.T) {
	eng := initTestEngine(t)

	// Manually create a node at a path whose parent dir doesn't exist in state.
	eng.State.SetNode("fakepub", &NodeState{
		PubKeyHex:  "fakepub",
		Type:       "file",
		Path:       "/ghost/file.txt",
		VaultIndex: 0,
	})

	_, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/ghost/file.txt",
		DstPath:    "/dst/file.txt",
	})
	if err == nil {
		t.Error("Move from nonexistent source dir should fail")
	}
	if !strings.Contains(err.Error(), "source directory") {
		t.Errorf("error should mention 'source directory', got: %v", err)
	}
}

func TestMove_CrossDirectory_DuplicateDestName(t *testing.T) {
	eng := setupMoveTestEngine(t)

	// Create a file in /dst with the same name.
	testFile := filepath.Join(eng.DataDir, "conflict.txt")
	if err := os.WriteFile(testFile, []byte("conflict"), 0644); err != nil {
		t.Fatalf("write conflict file: %v", err)
	}
	_, err := eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/dst/file.txt",
		Access:     "free",
	})
	if err != nil {
		t.Fatalf("PutFile /dst/file.txt: %v", err)
	}

	// Try to move /src/file.txt to /dst/file.txt — should fail.
	_, err = eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/dst/file.txt",
	})
	if err == nil {
		t.Error("Move to existing destination should fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

// TestMove_CrossDirectory_TxBuildFailure_PreservesState verifies that when
// any of the 4 TX builds fails, all state (parents, node path, UTXOs) remains
// unchanged. We sabotage the destination parent's UTXO so the dstParent
// SelfUpdate (Tx2) fails after Tx1 was built successfully.
func TestMove_CrossDirectory_TxBuildFailure_PreservesState(t *testing.T) {
	eng := setupMoveTestEngine(t)

	// Snapshot state before the move.
	srcDir := eng.State.FindNodeByPath("/src")
	require.NotNil(t, srcDir)
	srcChildrenBefore := make([]string, len(srcDir.Children))
	for i, c := range srcDir.Children {
		srcChildrenBefore[i] = c.Name
	}

	dstDir := eng.State.FindNodeByPath("/dst")
	require.NotNil(t, dstDir)
	dstChildrenBefore := make([]string, len(dstDir.Children))
	for i, c := range dstDir.Children {
		dstChildrenBefore[i] = c.Name
	}

	srcNode := eng.State.FindNodeByPath("/src/file.txt")
	require.NotNil(t, srcNode)
	originalPath := srcNode.Path
	originalPubKey := srcNode.PubKeyHex

	// Mark destination parent's node UTXO as spent so
	// buildParentSelfUpdate (dstParent, Tx2) fails.
	for _, u := range eng.State.UTXOs {
		if u.PubKeyHex == dstDir.PubKeyHex && u.Type == "node" && !u.Spent {
			u.Spent = true
		}
	}

	// Move should fail because dst parent update can't build.
	_, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/src/file.txt",
		DstPath:    "/dst/file.txt",
		Force:      true,
	})
	require.Error(t, err, "move should fail when dst parent update fails")

	// Source parent's children must be unchanged.
	srcDirAfter := eng.State.FindNodeByPath("/src")
	srcChildrenAfter := make([]string, len(srcDirAfter.Children))
	for i, c := range srcDirAfter.Children {
		srcChildrenAfter[i] = c.Name
	}
	assert.Equal(t, srcChildrenBefore, srcChildrenAfter, "source parent children should be unchanged")

	// Destination parent's children must be unchanged.
	dstDirAfter := eng.State.FindNodeByPath("/dst")
	dstChildrenAfter := make([]string, len(dstDirAfter.Children))
	for i, c := range dstDirAfter.Children {
		dstChildrenAfter[i] = c.Name
	}
	assert.Equal(t, dstChildrenBefore, dstChildrenAfter, "destination parent children should be unchanged")

	// Node path and pubkey must be unchanged.
	assert.Equal(t, originalPath, srcNode.Path, "node path should be unchanged")
	assert.Equal(t, originalPubKey, srcNode.PubKeyHex, "node pubkey should be unchanged")
}

func TestMove_CrossDirectory_FromRoot(t *testing.T) {
	eng := initTestEngine(t)

	// Add many fee UTXOs — 4-tx cross-dir move needs several.
	for i := 0; i < 15; i++ {
		addFeeUTXO(t, eng, 100000)
	}

	// Create root.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err, "Mkdir /")

	// Create /subdir.
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/subdir"})
	require.NoError(t, err, "Mkdir /subdir")

	// Create a file at root level.
	testFile := filepath.Join(eng.DataDir, "root_file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("root content"), 0644))
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/root_file.txt",
		Access:     "free",
	})
	require.NoError(t, err, "PutFile /root_file.txt")

	// Snapshot original identity.
	srcNode := eng.State.FindNodeByPath("/root_file.txt")
	require.NotNil(t, srcNode)
	originalPubKey := srcNode.PubKeyHex
	originalTxID := srcNode.TxID

	// Move from root to subdir.
	result, err := eng.Move(&MoveOpts{
		VaultIndex: 0,
		SrcPath:    "/root_file.txt",
		DstPath:    "/subdir/moved_file.txt",
		Force:      true,
	})
	require.NoError(t, err, "Move from root to subdir")
	assert.NotEmpty(t, result.TxID, "expected non-empty TxID")
	assert.Contains(t, result.Message, "atomic", "message should mention '4 txs'")

	// Verify the new node at destination has a NEW identity.
	movedNode := eng.State.FindNodeByPath("/subdir/moved_file.txt")
	require.NotNil(t, movedNode, "node should be at /subdir/moved_file.txt")
	assert.NotEqual(t, originalPubKey, movedNode.PubKeyHex, "cross-dir move must assign new pubkey")
	assert.NotEqual(t, originalTxID, movedNode.TxID, "moved node must have new TxID")

	// Old path no longer resolves.
	oldNode := eng.State.FindNodeByPath("/root_file.txt")
	assert.Nil(t, oldNode, "old path should no longer resolve")

	// Verify root no longer has the file.
	rootPubHex, _ := eng.getRootPubHex(0)
	rootNode := eng.State.GetNode(rootPubHex)
	for _, c := range rootNode.Children {
		assert.NotEqual(t, "root_file.txt", c.Name, "'root_file.txt' should have been removed from root children")
	}

	// Verify /subdir has the file with NEW pubkey.
	subdir := eng.State.FindNodeByPath("/subdir")
	require.NotNil(t, subdir)
	found := false
	for _, c := range subdir.Children {
		if c.Name == "moved_file.txt" {
			found = true
			assert.NotEqual(t, originalPubKey, c.PubKey, "child entry pubkey must be NEW")
			assert.Equal(t, movedNode.PubKeyHex, c.PubKey, "child entry must match moved node")
		}
	}
	assert.True(t, found, "'moved_file.txt' should be in /subdir children")
}
