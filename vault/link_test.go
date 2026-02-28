package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupLinkTestEngine sets up a test engine with a root directory and an
// uploaded test file at /test.txt. Returns the engine ready for link tests.
func setupLinkTestEngine(t *testing.T) *Vault {
	t.Helper()
	eng := initTestEngine(t)

	// Create a local test file.
	testFile := filepath.Join(eng.DataDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world, this is a test file for link"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Add fee UTXO for root creation.
	addFeeUTXO(t, eng, 100000)

	// Create root directory.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err != nil {
		t.Fatalf("Mkdir /: %v", err)
	}

	// Add fee UTXO for PutFile.
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

	return eng
}

// --- Soft link tests ---

func TestSoftLink_CreatesLinkNode(t *testing.T) {
	eng := setupLinkTestEngine(t)

	// Soft link needs two fee UTXOs (create child + parent update in batch).
	addFeeUTXO(t, eng, 100000)
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/test.txt",
		LinkPath:   "/link.txt",
		Soft:       true,
	})
	if err != nil {
		t.Fatalf("Link (soft): %v", err)
	}

	if result.TxHex == "" {
		t.Error("expected non-empty TxHex")
	}
	if result.TxID == "" {
		t.Error("expected non-empty TxID")
	}
	if !strings.Contains(result.Message, "soft link") {
		t.Errorf("message should mention 'soft link', got: %s", result.Message)
	}

	// Verify state has new node at /link.txt with Type="link".
	linkNode := eng.State.FindNodeByPath("/link.txt")
	if linkNode == nil {
		t.Fatal("link node should exist at /link.txt")
	}
	if linkNode.Type != "link" {
		t.Errorf("link node type = %q, want 'link'", linkNode.Type)
	}

	// Verify LinkTarget points to the target node's pubkey.
	targetNode := eng.State.FindNodeByPath("/test.txt")
	if targetNode == nil {
		t.Fatal("target node should still exist")
	}
	if linkNode.LinkTarget != targetNode.PubKeyHex {
		t.Errorf("link target = %q, want %q", linkNode.LinkTarget, targetNode.PubKeyHex)
	}
}

func TestSoftLink_TargetNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/nonexistent",
		LinkPath:   "/link.txt",
		Soft:       true,
	})
	if err == nil {
		t.Fatal("soft link to nonexistent target should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestSoftLink_DuplicateName(t *testing.T) {
	eng := setupLinkTestEngine(t)

	// Try to create soft link at /test.txt which already exists.
	addFeeUTXO(t, eng, 100000)
	addFeeUTXO(t, eng, 100000)

	_, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/test.txt",
		LinkPath:   "/test.txt",
		Soft:       true,
	})
	if err == nil {
		t.Fatal("soft link with duplicate name should fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

// --- Hard link tests ---

func TestHardLink_CreatesEntry(t *testing.T) {
	eng := setupLinkTestEngine(t)

	// Hard link needs one fee UTXO (parent self-update only).
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/test.txt",
		LinkPath:   "/hardlink.txt",
		Soft:       false,
	})
	if err != nil {
		t.Fatalf("Link (hard): %v", err)
	}

	if result.TxHex == "" {
		t.Error("expected non-empty TxHex")
	}
	if result.TxID == "" {
		t.Error("expected non-empty TxID")
	}
	if !strings.Contains(result.Message, "hard link") {
		t.Errorf("message should mention 'hard link', got: %s", result.Message)
	}

	// Verify parent (root) now has child "hardlink.txt" pointing to the
	// same pubkey as test.txt.
	targetNode := eng.State.FindNodeByPath("/test.txt")
	if targetNode == nil {
		t.Fatal("target node should still exist")
	}

	rootPubHex, err := eng.getRootPubHex(0)
	if err != nil {
		t.Fatalf("getRootPubHex: %v", err)
	}
	root := eng.State.GetNode(rootPubHex)
	if root == nil {
		t.Fatal("root node should exist")
	}

	var found bool
	for _, c := range root.Children {
		if c.Name == "hardlink.txt" {
			found = true
			if c.PubKey != targetNode.PubKeyHex {
				t.Errorf("hard link pubkey = %q, want %q (same as target)", c.PubKey, targetNode.PubKeyHex)
			}
		}
	}
	if !found {
		t.Error("root children should contain 'hardlink.txt'")
	}
}

func TestHardLink_TargetNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/nonexistent",
		LinkPath:   "/hardlink.txt",
		Soft:       false,
	})
	if err == nil {
		t.Fatal("hard link to nonexistent target should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestHardLink_DuplicateName(t *testing.T) {
	eng := setupLinkTestEngine(t)

	// Try to create hard link at /test.txt which already exists.
	addFeeUTXO(t, eng, 100000)

	_, err := eng.Link(&LinkOpts{
		VaultIndex: 0,
		TargetPath: "/test.txt",
		LinkPath:   "/test.txt",
		Soft:       false,
	})
	if err == nil {
		t.Fatal("hard link with duplicate name should fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}
