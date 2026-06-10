//go:build windows

package engine

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = modkernel32.NewProc("LockFileEx")
	procUnlockFile = modkernel32.NewProc("UnlockFile")
)

const (
	// LOCKFILE_EXCLUSIVE_LOCK requests an exclusive lock; without it,
	// LockFileEx grants a shared lock.
	lockfileExclusiveLock = 0x00000002
)

// lockFile acquires a shared (read) or exclusive (write) lock on f using
// LockFileEx. Blocks until the lock is granted. Locks a single byte at
// offset 0, matching the vault package's Windows lock implementation.
func lockFile(f *os.File, exclusive bool) error {
	var flags uint32
	if exclusive {
		flags = lockfileExclusiveLock
	}
	var overlapped syscall.Overlapped
	r1, _, err := procLockFileEx.Call(
		f.Fd(),
		uintptr(flags),
		0,                                    // reserved
		1,                                    // nNumberOfBytesToLockLow
		0,                                    // nNumberOfBytesToLockHigh
		uintptr(unsafe.Pointer(&overlapped)), //nolint:gosec // required by Windows API
	)
	if r1 == 0 {
		return err
	}
	return nil
}

// unlockFile releases the lock held on f via UnlockFile.
func unlockFile(f *os.File) error {
	r1, _, err := procUnlockFile.Call(
		f.Fd(),
		0, // dwFileOffsetLow
		0, // dwFileOffsetHigh
		1, // nNumberOfBytesToUnlockLow
		0, // nNumberOfBytesToUnlockHigh
	)
	if r1 == 0 {
		return err
	}
	return nil
}
