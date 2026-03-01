//go:build windows

package vault

import (
	"fmt"
	"os"
)

// Windows stub: file locking not supported via syscall.Flock.
// Vault operations are process-safe via Go mutexes but not cross-process safe on Windows.

// acquireLock opens the lock file but does not acquire a cross-process lock on Windows.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	return f, nil
}

// tryLock opens the lock file but does not acquire a cross-process lock on Windows.
func tryLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	return f, nil
}

// releaseLock closes the lock file.
func releaseLock(f *os.File) {
	if f == nil {
		return
	}
	_ = f.Close()
}
