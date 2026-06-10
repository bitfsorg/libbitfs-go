//go:build unix

package engine

import (
	"os"
	"syscall"
)

// lockFile acquires a shared (read) or exclusive (write) advisory lock on f.
// Blocks until the lock is granted.
func lockFile(f *os.File, exclusive bool) error {
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	return syscall.Flock(int(f.Fd()), mode)
}

// unlockFile releases the advisory lock held on f.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
