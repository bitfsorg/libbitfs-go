package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupDecryptTestEngine creates a test engine with a root and a FREE file
// at /test-decrypt.txt, then encrypts it to PRIVATE. Returns the engine.
func setupDecryptTestEngine(t *testing.T) *Vault {
	t.Helper()
	eng := initTestEngine(t)

	// Create local test file.
	testFile := filepath.Join(eng.DataDir, "decrypt.txt")
	if err := os.WriteFile(testFile, []byte("hello decrypt"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Create root.
	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	// Upload file as FREE.
	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/test-decrypt.txt",
		Access:     "free",
	})
	require.NoError(t, err)

	// Encrypt it (FREE -> PRIVATE).
	addFeeUTXO(t, eng, 100000)
	_, err = eng.EncryptNode(&EncryptOpts{VaultIndex: 0, Path: "/test-decrypt.txt"})
	require.NoError(t, err)

	// Verify it's now private.
	ns := eng.State.FindNodeByPath("/test-decrypt.txt")
	require.NotNil(t, ns)
	require.Equal(t, "private", ns.Access)

	return eng
}

func TestDecryptNode(t *testing.T) {
	eng := setupDecryptTestEngine(t)

	// Decrypt it (PRIVATE -> FREE).
	addFeeUTXO(t, eng, 100000)
	result, err := eng.DecryptNode(&DecryptOpts{Path: "/test-decrypt.txt"})
	require.NoError(t, err)
	assert.Contains(t, result.Message, "Decrypted")
	assert.NotEmpty(t, result.TxHex)
	assert.NotEmpty(t, result.TxID)

	// Verify it's now free.
	ns := eng.State.FindNodeByPath("/test-decrypt.txt")
	require.NotNil(t, ns)
	assert.Equal(t, "free", ns.Access)
}

func TestDecryptNode_AlreadyFree(t *testing.T) {
	eng := initTestEngine(t)

	testFile := filepath.Join(eng.DataDir, "free.txt")
	if err := os.WriteFile(testFile, []byte("already free"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/free-file.txt",
		Access:     "free",
	})
	require.NoError(t, err)

	_, err = eng.DecryptNode(&DecryptOpts{Path: "/free-file.txt"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already free")
}

func TestDecryptNode_NotFound(t *testing.T) {
	eng := initTestEngine(t)
	_, err := eng.DecryptNode(&DecryptOpts{Path: "/nonexistent"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDecryptNode_Directory(t *testing.T) {
	eng := initTestEngine(t)

	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/somedir"})
	require.NoError(t, err)

	_, err = eng.DecryptNode(&DecryptOpts{Path: "/somedir"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a file")
}
