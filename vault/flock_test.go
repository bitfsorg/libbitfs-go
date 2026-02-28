package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileLock_ExclusiveAccess(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "vault.lock")

	fl, err := acquireLock(lockPath)
	require.NoError(t, err)
	defer releaseLock(fl)

	// Lock file should exist.
	_, err = os.Stat(lockPath)
	assert.NoError(t, err)
}

func TestFileLock_BlocksSecondAcquire(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "vault.lock")

	fl1, err := acquireLock(lockPath)
	require.NoError(t, err)
	defer releaseLock(fl1)

	// Second acquire with tryLock should fail.
	fl2, err := tryLock(lockPath)
	assert.Error(t, err)
	assert.Nil(t, fl2)
}

func TestFileLock_ReleaseThenReacquire(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "vault.lock")

	fl1, err := acquireLock(lockPath)
	require.NoError(t, err)
	releaseLock(fl1)

	fl2, err := acquireLock(lockPath)
	require.NoError(t, err)
	releaseLock(fl2)
}
