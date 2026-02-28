package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGet_Success(t *testing.T) {
	eng, originalPlaintext := setupCopyTestEngine(t)
	outDir := t.TempDir()

	result, err := eng.Get(&GetOpts{
		VaultIndex: 0,
		RemotePath: "/test.txt",
		LocalDir:   outDir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Message, "Downloaded")
	assert.Contains(t, result.Message, "test.txt")

	// Verify downloaded content.
	data, err := os.ReadFile(filepath.Join(outDir, "test.txt"))
	require.NoError(t, err)
	assert.Equal(t, originalPlaintext, data)
}

func TestGet_ExplicitLocalPath(t *testing.T) {
	eng, originalPlaintext := setupCopyTestEngine(t)
	outDir := t.TempDir()
	localPath := filepath.Join(outDir, "custom_name.txt")

	result, err := eng.Get(&GetOpts{
		VaultIndex: 0,
		RemotePath: "/test.txt",
		LocalPath:  localPath,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Message, "custom_name.txt")

	data, err := os.ReadFile(localPath)
	require.NoError(t, err)
	assert.Equal(t, originalPlaintext, data)
}

func TestGet_NotFound(t *testing.T) {
	eng := initTestEngine(t)

	_, err := eng.Get(&GetOpts{VaultIndex: 0, RemotePath: "/nope", LocalDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// writeTestFile creates a test file and returns its path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}
