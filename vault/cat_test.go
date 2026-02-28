package vault

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCat_Success(t *testing.T) {
	eng, originalPlaintext := setupCopyTestEngine(t)

	reader, info, err := eng.Cat(&CatOpts{
		Path: "/test.txt",
	})
	require.NoError(t, err)
	require.NotNil(t, reader)
	require.NotNil(t, info)

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, originalPlaintext, data)
	assert.Equal(t, "text/plain", info.MimeType)
	assert.Equal(t, uint64(len(originalPlaintext)), info.FileSize)
	assert.Equal(t, "free", info.Access)
}

func TestCat_NotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, _, err := eng.Cat(&CatOpts{Path: "/nonexistent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCat_IsDirectory(t *testing.T) {
	eng := initTestEngine(t)

	// Create root directory.
	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	_, _, err = eng.Cat(&CatOpts{Path: "/"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a file")
}

func TestCat_PrivateFile(t *testing.T) {
	eng := setupPrivateFileEngine(t)

	reader, info, err := eng.Cat(&CatOpts{
		Path: "/secret.txt",
	})
	require.NoError(t, err)

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "secret content", string(data))
	assert.Equal(t, "private", info.Access)
}

// setupPrivateFileEngine creates an engine with a private file at /secret.txt.
func setupPrivateFileEngine(t *testing.T) *Vault {
	t.Helper()
	eng := initTestEngine(t)

	testFile := writeTestFile(t, eng.DataDir, "secret.txt", "secret content")

	addFeeUTXO(t, eng, 100000)
	_, err := eng.Mkdir(&MkdirOpts{VaultIndex: 0, Path: "/"})
	require.NoError(t, err)

	addFeeUTXO(t, eng, 100000)
	_, err = eng.PutFile(&PutOpts{
		VaultIndex: 0,
		LocalFile:  testFile,
		RemotePath: "/secret.txt",
		Access:     "private",
	})
	require.NoError(t, err)

	return eng
}
