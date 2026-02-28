package vault

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tongxiaofeng/libbitfs-go/method42"
	"github.com/tongxiaofeng/libbitfs-go/wallet"
)

// addFeeUTXO derives a fee key and registers a fake fee UTXO for test operations.
func addFeeUTXO(t *testing.T, eng *Vault, amount uint64) {
	t.Helper()
	idx := eng.WState.NextReceiveIndex
	kp, err := eng.Wallet.DeriveFeeKey(wallet.ExternalChain, idx)
	if err != nil {
		t.Fatalf("DeriveFeeKey: %v", err)
	}
	eng.WState.NextReceiveIndex++

	pubHex := hex.EncodeToString(kp.PublicKey.Compressed())
	scriptPK := "76a914" + hex.EncodeToString(pubKeyHash(kp.PublicKey)) + "88ac"

	eng.State.AddUTXO(&UTXOState{
		TxID:         "aa" + strings.Repeat("00", 31), // 64 hex chars
		Vout:         0,
		Amount:       amount,
		ScriptPubKey: scriptPK,
		PubKeyHex:    pubHex,
		Type:         "fee",
	})
}

// setupCopyTestEngine sets up a test engine with a root directory and an
// uploaded test file at /test.txt. Returns the engine and the original plaintext.
func setupCopyTestEngine(t *testing.T) (*Vault, []byte) {
	t.Helper()
	eng := initTestEngine(t)

	// Create a local test file.
	testContent := []byte("hello world, this is a test file for copy")
	testFile := filepath.Join(eng.DataDir, "test.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Add fee UTXO for root creation.
	addFeeUTXO(t, eng, 100000)

	// Create root directory.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err != nil {
		t.Fatalf("Mkdir /: %v", err)
	}

	// Add fee UTXO for PutFile (change from Mkdir may not be enough).
	addFeeUTXO(t, eng, 100000)

	// Upload test file.
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/test.txt",
		Access:     "free",
	})
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	return eng, testContent
}

func TestCopy_CreatesIndependentNode(t *testing.T) {
	eng, _ := setupCopyTestEngine(t)

	// Add fee UTXO for copy operation.
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/test.txt",
		DstPath:    "/copy.txt",
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}

	if result.TxHex == "" {
		t.Error("expected non-empty TxHex")
	}
	if result.TxID == "" {
		t.Error("expected non-empty TxID")
	}
	if !strings.Contains(result.Message, "Copied") {
		t.Errorf("message should mention 'Copied', got: %s", result.Message)
	}

	// Both nodes should exist.
	srcNode := eng.State.FindNodeByPath("/test.txt")
	dstNode := eng.State.FindNodeByPath("/copy.txt")
	if srcNode == nil {
		t.Fatal("source node should still exist")
	}
	if dstNode == nil {
		t.Fatal("destination node should exist")
	}

	// They must have different pubkeys (independent identity).
	if srcNode.PubKeyHex == dstNode.PubKeyHex {
		t.Error("source and destination should have different pubkeys")
	}

	// Key hashes are content-based (SHA256(SHA256(plaintext))), so they will
	// be the same for files with identical content. The files are still
	// independent on the DAG (different pubkeys, different TxIDs).
	// The encrypted ciphertext in the store differs because it uses a
	// different AES key derived from the new node's ECDH.
	if dstNode.TxID == srcNode.TxID {
		t.Error("source and destination should have different TxIDs")
	}

	// Both should be files.
	if dstNode.Type != "file" {
		t.Errorf("destination type = %q, want 'file'", dstNode.Type)
	}

	// Destination should have its own TxID.
	if dstNode.TxID == "" {
		t.Error("destination should have a TxID")
	}
}

func TestCopy_PreservesContent(t *testing.T) {
	eng, originalContent := setupCopyTestEngine(t)

	// Add fee UTXO for copy.
	addFeeUTXO(t, eng, 100000)

	_, err := eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/test.txt",
		DstPath:    "/copy.txt",
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}

	// Decrypt the copy's content and verify it matches original.
	dstNode := eng.State.FindNodeByPath("/copy.txt")
	if dstNode == nil {
		t.Fatal("destination node not found")
	}

	dstKeyHash, err := hex.DecodeString(dstNode.KeyHash)
	if err != nil {
		t.Fatalf("decode key hash: %v", err)
	}

	ciphertext, err := eng.Store.Get(dstKeyHash)
	if err != nil {
		t.Fatalf("Store.Get: %v", err)
	}

	dstKP, err := eng.Wallet.DeriveNodeKey(dstNode.VaultIndex, dstNode.ChildIndices, nil)
	if err != nil {
		t.Fatalf("DeriveNodeKey: %v", err)
	}

	decResult, err := method42.Decrypt(ciphertext, dstKP.PrivateKey, dstKP.PublicKey, dstKeyHash, method42.AccessFree)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decResult.Plaintext) != string(originalContent) {
		t.Errorf("decrypted content = %q, want %q", decResult.Plaintext, originalContent)
	}
}

func TestCopy_SourceNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/nonexistent.txt",
		DstPath:    "/copy.txt",
	})
	if err == nil {
		t.Fatal("Copy from nonexistent source should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestCopy_CannotCopyDirectory(t *testing.T) {
	eng := initTestEngine(t)

	// Add fee UTXO for root creation.
	addFeeUTXO(t, eng, 100000)

	// Create root.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err != nil {
		t.Fatalf("Mkdir /: %v", err)
	}

	// Add fee UTXO for subdir creation.
	addFeeUTXO(t, eng, 100000)

	// Create a subdirectory.
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/mydir"})
	if err != nil {
		t.Fatalf("Mkdir /mydir: %v", err)
	}

	_, err = eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/mydir",
		DstPath:    "/mydir-copy",
	})
	if err == nil {
		t.Fatal("Copy of directory should fail")
	}
	if !strings.Contains(err.Error(), "can only copy files") {
		t.Errorf("error should mention 'can only copy files', got: %v", err)
	}
}

func TestCopy_DuplicateDestination(t *testing.T) {
	eng, _ := setupCopyTestEngine(t)

	// Create a second file at the destination path.
	testFile2 := filepath.Join(eng.DataDir, "test2.txt")
	if err := os.WriteFile(testFile2, []byte("other content"), 0644); err != nil {
		t.Fatalf("write test2 file: %v", err)
	}

	addFeeUTXO(t, eng, 100000)
	_, err := eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile2,
		RemotePath: "/existing.txt",
		Access:     "free",
	})
	if err != nil {
		t.Fatalf("PutFile existing.txt: %v", err)
	}

	// Now try to copy test.txt to existing.txt — should fail.
	addFeeUTXO(t, eng, 100000)
	_, err = eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/test.txt",
		DstPath:    "/existing.txt",
	})
	if err == nil {
		t.Fatal("Copy to existing destination should fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

func TestCopy_PreservesAccessMode(t *testing.T) {
	eng := initTestEngine(t)

	// Create a local test file.
	testContent := []byte("private content for copy test")
	testFile := filepath.Join(eng.DataDir, "secret.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Add fee UTXO for root creation.
	addFeeUTXO(t, eng, 100000)

	// Create root.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err != nil {
		t.Fatalf("Mkdir /: %v", err)
	}

	// Upload a private file.
	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/secret.txt",
		Access:     "private",
	})
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	// Copy the private file.
	addFeeUTXO(t, eng, 100000)
	_, err = eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/secret.txt",
		DstPath:    "/secret-copy.txt",
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}

	// Verify the copy preserves the private access mode.
	dstNode := eng.State.FindNodeByPath("/secret-copy.txt")
	if dstNode == nil {
		t.Fatal("destination node not found")
	}
	if dstNode.Access != "private" {
		t.Errorf("destination access = %q, want 'private'", dstNode.Access)
	}

	// Verify file metadata is preserved.
	srcNode := eng.State.FindNodeByPath("/secret.txt")
	if srcNode == nil {
		t.Fatal("source node not found")
	}
	if dstNode.FileSize != srcNode.FileSize {
		t.Errorf("file size mismatch: dst=%d, src=%d", dstNode.FileSize, srcNode.FileSize)
	}
	if dstNode.MimeType != srcNode.MimeType {
		t.Errorf("mime type mismatch: dst=%q, src=%q", dstNode.MimeType, srcNode.MimeType)
	}
}

func TestCopy_PreservesExtendedMetadata(t *testing.T) {
	eng, _ := setupCopyTestEngine(t)

	// Manually set extended metadata on the source node.
	srcNode := eng.State.FindNodeByPath("/test.txt")
	require.NotNil(t, srcNode)
	srcNode.Keywords = "test,example"
	srcNode.Description = "A test file"
	srcNode.Domain = "example.com"
	srcNode.OnChain = true
	srcNode.Compression = 1
	require.NoError(t, eng.State.Save()) // persist in-memory changes before locked op

	addFeeUTXO(t, eng, 100000)

	_, err := eng.Copy(&CopyOpts{
		VaultIndex: 0,
		SrcPath:    "/test.txt",
		DstPath:    "/copy.txt",
	})
	require.NoError(t, err)

	dstNode := eng.State.FindNodeByPath("/copy.txt")
	require.NotNil(t, dstNode)
	assert.Equal(t, "test,example", dstNode.Keywords)
	assert.Equal(t, "A test file", dstNode.Description)
	assert.Equal(t, "example.com", dstNode.Domain)
	assert.True(t, dstNode.OnChain)
	assert.Equal(t, int32(1), dstNode.Compression)
}
