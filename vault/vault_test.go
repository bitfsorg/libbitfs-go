package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bitfsorg/libbitfs-go/tx"
	"github.com/bitfsorg/libbitfs-go/wallet"
)

const testPassword = "testpass"

// initTestEngine creates a temporary data directory with an initialized wallet
// and returns a ready-to-use Vault. The wallet has a "default" vault at index 0.
func initTestEngine(t *testing.T) *Vault {
	t.Helper()
	dataDir := t.TempDir()

	// Generate mnemonic and seed.
	mnemonic, err := wallet.GenerateMnemonic(wallet.Mnemonic12Words)
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	seed, err := wallet.SeedFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatalf("SeedFromMnemonic: %v", err)
	}

	// Encrypt and save wallet.
	encrypted, err := wallet.EncryptSeed(seed, testPassword)
	if err != nil {
		t.Fatalf("EncryptSeed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "wallet.enc"), encrypted, 0600); err != nil {
		t.Fatalf("write wallet.enc: %v", err)
	}

	// Create wallet state with default vault.
	w, err := wallet.NewWallet(seed, &wallet.MainNet)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	wState := wallet.NewWalletState()
	_, err = w.CreateVault(wState, "default")
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	stateData, err := json.MarshalIndent(wState, "", "  ")
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.json"), stateData, 0600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}

	eng, err := New(dataDir, testPassword)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	return eng
}

// --- Vault construction tests ---

func TestNew_Success(t *testing.T) {
	eng := initTestEngine(t)
	if eng.Wallet == nil {
		t.Error("Wallet should not be nil")
	}
	if eng.Store == nil {
		t.Error("Store should not be nil")
	}
	if eng.State == nil {
		t.Error("State should not be nil")
	}
}

func TestNew_ResolverInitialized(t *testing.T) {
	eng := initTestEngine(t)
	assert.NotNil(t, eng.Resolver, "Resolver should be initialized")
	assert.Equal(t, eng.Store, eng.Resolver.Store, "Resolver should use engine's store")
}

func TestNew_MissingWallet(t *testing.T) {
	_, err := New(t.TempDir(), "pass")
	if err == nil {
		t.Error("New with missing wallet should fail")
	}
}

func TestNew_WrongPassword(t *testing.T) {
	eng := initTestEngine(t)
	dataDir := eng.DataDir

	_, err := New(dataDir, "wrongpass")
	if err == nil {
		t.Error("New with wrong password should fail")
	}
}

func TestNew_EmptyPasswordError(t *testing.T) {
	dataDir := t.TempDir()

	mnemonic, _ := wallet.GenerateMnemonic(wallet.Mnemonic12Words)
	seed, _ := wallet.SeedFromMnemonic(mnemonic, "")
	encrypted, _ := wallet.EncryptSeed(seed, "testpass")
	os.WriteFile(filepath.Join(dataDir, "wallet.enc"), encrypted, 0600)

	w, _ := wallet.NewWallet(seed, &wallet.MainNet)
	wState := wallet.NewWalletState()
	w.CreateVault(wState, "default")
	stateData, _ := json.MarshalIndent(wState, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "state.json"), stateData, 0600)

	// Empty password should return an error.
	_, err := New(dataDir, "")
	if err == nil {
		t.Fatal("expected error for empty password, got nil")
	}
}

func TestClose_SavesState(t *testing.T) {
	eng := initTestEngine(t)
	eng.State.SetNode("testpub", &NodeState{PubKeyHex: "testpub", Path: "/test"})

	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify state was persisted.
	loaded, err := LoadLocalState(filepath.Join(eng.DataDir, "nodes.json"))
	if err != nil {
		t.Fatalf("LoadLocalState: %v", err)
	}
	if loaded.GetNode("testpub") == nil {
		t.Error("state not persisted after Close")
	}
}

// --- ResolveVaultIndex tests ---

func TestResolveVaultIndex_EmptyUsesFirst(t *testing.T) {
	eng := initTestEngine(t)

	idx, err := eng.ResolveVaultIndex("")
	if err != nil {
		t.Fatalf("ResolveVaultIndex: %v", err)
	}
	if idx != 0 {
		t.Errorf("vault index = %d, want 0", idx)
	}
}

func TestResolveVaultIndex_ByName(t *testing.T) {
	eng := initTestEngine(t)

	idx, err := eng.ResolveVaultIndex("default")
	if err != nil {
		t.Fatalf("ResolveVaultIndex(default): %v", err)
	}
	if idx != 0 {
		t.Errorf("vault index = %d, want 0", idx)
	}
}

func TestResolveVaultIndex_NotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.ResolveVaultIndex("nonexistent")
	if err == nil {
		t.Error("ResolveVaultIndex(nonexistent) should fail")
	}
}

func TestResolveVaultIndex_NoVaults(t *testing.T) {
	eng := initTestEngine(t)
	// Remove all vaults.
	eng.WState.Vaults = nil

	_, err := eng.ResolveVaultIndex("")
	if err == nil {
		t.Error("ResolveVaultIndex with no vaults should fail")
	}
}

// --- DeriveChangeAddr tests ---

func TestDeriveChangeAddr(t *testing.T) {
	eng := initTestEngine(t)
	startIdx := eng.WState.NextChangeIndex

	hash, priv, err := eng.DeriveChangeAddr()
	if err != nil {
		t.Fatalf("DeriveChangeAddr: %v", err)
	}
	if len(hash) != 20 {
		t.Errorf("change addr hash length = %d, want 20", len(hash))
	}
	if priv == nil {
		t.Error("private key should not be nil")
	}
	if eng.WState.NextChangeIndex != startIdx+1 {
		t.Error("NextChangeIndex should be incremented")
	}
}

// --- Operation error path tests ---

func TestMkdir_NoFeeUTXO(t *testing.T) {
	eng := initTestEngine(t)

	// No fee UTXOs funded — should fail.
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	if err == nil {
		t.Error("Mkdir without fee UTXO should fail")
	}
	if !strings.Contains(err.Error(), "UTXO") && !strings.Contains(err.Error(), "fund") {
		t.Errorf("error should mention UTXO/fund, got: %v", err)
	}
}

func TestRemove_NodeNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Remove(&RemoveOpts{VaultIndex: 0, Path: "/nonexistent"})
	if err == nil {
		t.Error("Remove nonexistent should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestMove_NodeNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Move(&MoveOpts{VaultIndex: 0, SrcPath: "/a", DstPath: "/b"})
	if err == nil {
		t.Error("Move nonexistent should fail")
	}
}

func TestMove_CrossDirectory_SourceNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Move(&MoveOpts{VaultIndex: 0, SrcPath: "/dir1/file", DstPath: "/dir2/file"})
	if err == nil {
		t.Error("Cross-directory move with missing source should fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestLink_TargetNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Link(&LinkOpts{VaultIndex: 0, TargetPath: "/nonexistent", LinkPath: "/link", Soft: false})
	if err == nil {
		t.Error("Link to nonexistent target should fail")
	}
}

func TestLink_SoftTargetNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Link(&LinkOpts{VaultIndex: 0, TargetPath: "/nonexistent", LinkPath: "/link", Soft: true})
	if err == nil {
		t.Error("Soft link to nonexistent target should fail")
	}
}

func TestEncryptNode_NotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.EncryptNode(&EncryptOpts{VaultIndex: 0, Path: "/nonexistent"})
	if err == nil {
		t.Error("EncryptNode nonexistent should fail")
	}
}

func TestEncryptNode_NotFile(t *testing.T) {
	eng := initTestEngine(t)
	eng.State.SetNode("dirpub", &NodeState{
		PubKeyHex: "dirpub",
		Type:      "dir",
		Path:      "/mydir",
	})

	_, err := eng.EncryptNode(&EncryptOpts{VaultIndex: 0, Path: "/mydir"})
	if err == nil {
		t.Error("EncryptNode on directory should fail")
	}
	if !strings.Contains(err.Error(), "not a file") {
		t.Errorf("error should mention 'not a file', got: %v", err)
	}
}

func TestEncryptNode_AlreadyPrivate(t *testing.T) {
	eng := initTestEngine(t)
	eng.State.SetNode("filepub", &NodeState{
		PubKeyHex: "filepub",
		Type:      "file",
		Access:    "private",
		Path:      "/secret.txt",
	})

	_, err := eng.EncryptNode(&EncryptOpts{VaultIndex: 0, Path: "/secret.txt"})
	if err == nil {
		t.Error("EncryptNode on already-private file should fail")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error should mention 'already', got: %v", err)
	}
}

func TestSell_NodeNotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Sell(&SellOpts{VaultIndex: 0, Path: "/nonexistent", PricePerKB: 100})
	if err == nil {
		t.Error("Sell nonexistent should fail")
	}
}

func TestSell_Success(t *testing.T) {
	eng, _ := setupCopyTestEngine(t) // root + /test.txt

	// Add fee UTXOs for sell tx.
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Sell(&SellOpts{VaultIndex: 0, Path: "/test.txt", PricePerKB: 50})
	require.NoError(t, err)
	assert.NotEmpty(t, result.TxHex)
	assert.NotEmpty(t, result.TxID)
	assert.Contains(t, result.Message, "50 sats/KB")

	// Verify node state is updated.
	node := eng.State.FindNodeByPath("/test.txt")
	require.NotNil(t, node)
	assert.Equal(t, "paid", node.Access)
	assert.Equal(t, uint64(50), node.PricePerKB)
}

func TestSell_NoFeeUTXO(t *testing.T) {
	eng, _ := setupCopyTestEngine(t) // root + /test.txt

	// Mark all fee UTXOs as spent so Sell can't find one.
	for _, u := range eng.State.UTXOs {
		if u.Type == "fee" {
			u.Spent = true
		}
	}
	require.NoError(t, eng.State.Save())

	_, err := eng.Sell(&SellOpts{VaultIndex: 0, Path: "/test.txt", PricePerKB: 50})
	require.Error(t, err)
}

func TestSell_PreservesMetadata(t *testing.T) {
	eng := initTestEngine(t)

	testFile := filepath.Join(eng.DataDir, "meta.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("metadata file"), 0644))

	// Create root + file with metadata.
	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex:  0,
		LocalFile:   testFile,
		RemotePath:  "/meta.txt",
		Access:      "free",
		Keywords:    "test,data",
		Description: "A test file",
		Domain:      "example.com",
	})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	result, err := eng.Sell(&SellOpts{VaultIndex: 0, Path: "/meta.txt", PricePerKB: 100})
	require.NoError(t, err)
	assert.NotEmpty(t, result.TxID)

	// Verify metadata is preserved after sell.
	updatedNode := eng.State.FindNodeByPath("/meta.txt")
	require.NotNil(t, updatedNode)
	assert.Equal(t, "test,data", updatedNode.Keywords)
	assert.Equal(t, "A test file", updatedNode.Description)
	assert.Equal(t, "example.com", updatedNode.Domain)
}

func TestPutFile_FileNotExist(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  "/nonexistent/file.txt",
		RemotePath: "/file.txt",
	})
	if err == nil {
		t.Error("PutFile with missing local file should fail")
	}
}

// --- ResolveParentNode tests ---

func TestPutFile_PreservesExtendedMetadata(t *testing.T) {
	eng := initTestEngine(t)

	testFile := filepath.Join(eng.DataDir, "meta.txt")
	if err := os.WriteFile(testFile, []byte("metadata test"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex:  0,
		LocalFile:   testFile,
		RemotePath:  "/meta.txt",
		Access:      "free",
		Keywords:    "test,metadata",
		Description: "A test file with metadata",
		Domain:      "example.com",
		OnChain:     true,
		Compression: 2,
	})
	require.NoError(t, err)

	node := eng.State.FindNodeByPath("/meta.txt")
	require.NotNil(t, node)
	assert.Equal(t, "test,metadata", node.Keywords)
	assert.Equal(t, "A test file with metadata", node.Description)
	assert.Equal(t, "example.com", node.Domain)
	assert.True(t, node.OnChain)
	assert.Equal(t, int32(2), node.Compression)
}

func TestResolveParentNode_RootNotInitialized(t *testing.T) {
	eng := initTestEngine(t)

	_, _, err := eng.ResolveParentNode("/file.txt", 0)
	if err == nil {
		t.Error("ResolveParentNode with uninitialized root should fail")
	}
	if !strings.Contains(err.Error(), "root node not initialized") {
		t.Errorf("error should mention root not initialized, got: %v", err)
	}
}

func TestResolveParentNode_ParentNotDir(t *testing.T) {
	eng := initTestEngine(t)
	eng.State.SetNode("filepub", &NodeState{
		PubKeyHex: "filepub",
		Type:      "file",
		Path:      "/notadir",
	})

	_, _, err := eng.ResolveParentNode("/notadir/child.txt", 0)
	if err == nil {
		t.Error("ResolveParentNode with file as parent should fail")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should mention 'not a directory', got: %v", err)
	}
}

// --- AllocateFeeUTXO tests ---

func TestAllocateFeeUTXO_NoneAvailable(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.AllocateFeeUTXO(1000)
	if err == nil {
		t.Error("AllocateFeeUTXO with no UTXOs should fail")
	}
	if !strings.Contains(err.Error(), "fund") {
		t.Errorf("error should mention 'fund', got: %v", err)
	}
}

// --- TrackNewUTXOs tests ---

func TestTrackNewUTXOs_NilOutputs(t *testing.T) {
	eng := initTestEngine(t)

	// Should not panic with nil outputs.
	eng.TrackNewUTXOs(&tx.MetanetTx{}, "", "")
	if len(eng.State.UTXOs) != 0 {
		t.Error("no UTXOs should be added for nil outputs")
	}
}

// --- Remove + parent update tests ---

// TestRemove_ParentUpdateFailure_PreservesState verifies that when the parent
// update TX build fails, the parent's Children list is NOT mutated (P1 fix).
func TestRemove_NonEmptyDirectory_Fails(t *testing.T) {
	eng, _ := setupCopyTestEngine(t) // root has /test.txt as child

	rootPubHex, err := eng.getRootPubHex(0)
	require.NoError(t, err)
	root := eng.State.GetNode(rootPubHex)
	require.NotNil(t, root)
	require.Greater(t, len(root.Children), 0, "root should have children")

	addFeeUTXO(t, eng, 100000)

	_, err = eng.Remove(&RemoveOpts{VaultIndex: 0, Path: "/"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not empty")
}

func TestRemove_EmptyDirectory_Succeeds(t *testing.T) {
	eng := initTestEngine(t)

	// Create root + empty subdirectory.
	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/emptydir"})
	require.NoError(t, err)

	emptyDir := eng.State.FindNodeByPath("/emptydir")
	require.NotNil(t, emptyDir)
	require.Empty(t, emptyDir.Children, "/emptydir should have no children")

	// Add fee UTXOs for removal (node delete + parent update).
	addFeeUTXO(t, eng, 100000)
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Remove(&RemoveOpts{VaultIndex: 0, Path: "/emptydir"})
	require.NoError(t, err)
	assert.Contains(t, result.Message, "Removed")

	// Verify /emptydir is removed from root's children.
	rootPubHex, _ := eng.getRootPubHex(0)
	root := eng.State.GetNode(rootPubHex)
	for _, c := range root.Children {
		assert.NotEqual(t, "emptydir", c.Name)
	}
}

func TestRemove_ParentUpdateFailure_PreservesState(t *testing.T) {
	eng, _ := setupCopyTestEngine(t) // gives us root + /test.txt

	rootPubHex, err := eng.getRootPubHex(0)
	require.NoError(t, err)
	root := eng.State.GetNode(rootPubHex)
	require.NotNil(t, root)

	// Snapshot parent's children before remove.
	childrenBefore := make([]string, len(root.Children))
	for i, c := range root.Children {
		childrenBefore[i] = c.Name
	}
	require.Contains(t, childrenBefore, "test.txt")

	// Add fee UTXO only for the node deletion TX.
	addFeeUTXO(t, eng, 100000)

	// Mark root's node UTXO as spent so buildParentSelfUpdate fails.
	for _, u := range eng.State.UTXOs {
		if u.PubKeyHex == rootPubHex && u.Type == "node" && !u.Spent {
			u.Spent = true
		}
	}
	require.NoError(t, eng.State.Save()) // persist sabotaged state before locked op

	// Remove should still succeed (best-effort), but with a warning.
	result, err := eng.Remove(&RemoveOpts{VaultIndex: 0, Path: "/test.txt"})
	require.NoError(t, err)
	assert.Contains(t, result.Message, "warning")

	// Parent's children list must still contain test.txt (not mutated).
	rootAfter := eng.State.GetNode(rootPubHex)
	childrenAfter := make([]string, len(rootAfter.Children))
	for i, c := range rootAfter.Children {
		childrenAfter[i] = c.Name
	}
	assert.Equal(t, childrenBefore, childrenAfter, "parent children should be unchanged after failed parent update")
}

func TestRemove_UpdatesParentChildList(t *testing.T) {
	eng, _ := setupCopyTestEngine(t) // gives us root + /test.txt

	// Verify the file exists in parent's children.
	root := eng.State.FindNodeByPath("/")
	if root == nil {
		// root might be stored by pubkey only
		rootPubHex, _ := eng.getRootPubHex(0)
		root = eng.State.GetNode(rootPubHex)
	}
	require.NotNil(t, root)

	found := false
	for _, c := range root.Children {
		if c.Name == "test.txt" {
			found = true
		}
	}
	require.True(t, found, "test.txt should be in root children before remove")

	// Add fee UTXOs for both txs (node delete + parent update).
	addFeeUTXO(t, eng, 100000)
	addFeeUTXO(t, eng, 100000)

	result, err := eng.Remove(&RemoveOpts{VaultIndex: 0, Path: "/test.txt"})
	require.NoError(t, err)
	assert.NotEmpty(t, result.TxHex)
	assert.Contains(t, result.Message, "Removed")

	// Result should contain 2 txs (newline-separated).
	txParts := strings.Split(result.TxHex, "\n")
	assert.Len(t, txParts, 2, "Remove should produce 2 txs: node delete + parent update")

	// Parent's children list should no longer contain test.txt.
	rootPubHex, _ := eng.getRootPubHex(0)
	rootAfter := eng.State.GetNode(rootPubHex)
	for _, c := range rootAfter.Children {
		assert.NotEqual(t, "test.txt", c.Name, "test.txt should be removed from parent children")
	}
}
