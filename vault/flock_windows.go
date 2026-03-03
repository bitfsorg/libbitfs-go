//go:build windows

package vault

import (
	"fmt"
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
	// LOCKFILE_EXCLUSIVE_LOCK requests an exclusive lock.
	lockfileExclusiveLock = 0x00000002
	// LOCKFILE_FAIL_IMMEDIATELY makes the call non-blocking.
	lockfileFailImmediately = 0x00000001
)

// acquireLock acquires an exclusive file lock (blocking) using LockFileEx.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := lockFileEx(f, lockfileExclusiveLock); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire lock: %w", err)
	}
	return f, nil
}

// tryLock attempts a non-blocking exclusive lock. Returns error if already held.
func tryLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := lockFileEx(f, lockfileExclusiveLock|lockfileFailImmediately); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock held by another process: %w", err)
	}
	return f, nil
}

// releaseLock releases the file lock and closes the file.
func releaseLock(f *os.File) {
	if f == nil {
		return
	}
	_ = unlockFile(f)
	_ = f.Close()
}

// lockFileEx calls the Windows LockFileEx API to lock the entire file.
func lockFileEx(f *os.File, flags uint32) error {
	// Lock the entire file by setting length to max uint32 values.
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

// unlockFile calls the Windows UnlockFile API.
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
