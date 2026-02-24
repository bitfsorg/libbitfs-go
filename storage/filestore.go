package storage

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore implements Store using the local filesystem.
// Files are stored at: {baseDir}/{hex(keyHash[:1])}/{hex(keyHash)}
// The first byte (2 hex chars) is used as a subdirectory for sharding.
type FileStore struct {
	baseDir string
	mu      sync.RWMutex
}

// NewFileStore creates a new file-based content store.
// baseDir is typically "~/.bitfs/store". The directory is created if it does not exist.
func NewFileStore(baseDir string) (*FileStore, error) {
	if baseDir == "" {
		return nil, ErrInvalidBaseDir
	}

	// Create base directory if it does not exist
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return &FileStore{
		baseDir: baseDir,
	}, nil
}

// KeyHashToPath converts a key_hash to its filesystem path.
// Uses first byte as subdirectory for sharding: {base}/{ab}/{abcdef...}
func KeyHashToPath(baseDir string, keyHash []byte) string {
	hexHash := hex.EncodeToString(keyHash)
	// First 2 hex chars (1 byte) as shard directory
	shard := hexHash[:2]
	return filepath.Join(baseDir, shard, hexHash)
}

// validateKeyHash checks that the key hash is exactly 32 bytes.
func validateKeyHash(keyHash []byte) error {
	if len(keyHash) != KeyHashSize {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKeyHash, len(keyHash))
	}
	return nil
}

// shardDir returns the shard directory path for a key hash.
func (fs *FileStore) shardDir(keyHash []byte) string {
	hexHash := hex.EncodeToString(keyHash)
	return filepath.Join(fs.baseDir, hexHash[:2])
}

// filePath returns the full file path for a key hash.
func (fs *FileStore) filePath(keyHash []byte) string {
	return KeyHashToPath(fs.baseDir, keyHash)
}

// Put stores encrypted content indexed by key_hash.
func (fs *FileStore) Put(keyHash []byte, ciphertext []byte) error {
	if err := validateKeyHash(keyHash); err != nil {
		return err
	}
	if len(ciphertext) == 0 {
		return ErrEmptyContent
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Ensure shard directory exists
	shard := fs.shardDir(keyHash)
	if err := os.MkdirAll(shard, 0700); err != nil {
		return fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	path := fs.filePath(keyHash)
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		return fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return nil
}

// Get retrieves encrypted content by key_hash.
func (fs *FileStore) Get(keyHash []byte) ([]byte, error) {
	if err := validateKeyHash(keyHash); err != nil {
		return nil, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.filePath(keyHash)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return data, nil
}

// Has checks if content exists for the given key_hash.
func (fs *FileStore) Has(keyHash []byte) (bool, error) {
	if err := validateKeyHash(keyHash); err != nil {
		return false, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.filePath(keyHash)
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return true, nil
}

// Delete removes content by key_hash.
func (fs *FileStore) Delete(keyHash []byte) error {
	if err := validateKeyHash(keyHash); err != nil {
		return err
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	path := fs.filePath(keyHash)
	err := os.Remove(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return nil
}

// Size returns the size in bytes of stored content for key_hash.
func (fs *FileStore) Size(keyHash []byte) (int64, error) {
	if err := validateKeyHash(keyHash); err != nil {
		return 0, err
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	path := fs.filePath(keyHash)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	return info.Size(), nil
}

// List returns all stored key hashes by scanning the shard directories.
func (fs *FileStore) List() ([][]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var result [][]byte

	// Read shard directories
	entries, err := os.ReadDir(fs.baseDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIOFailure, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		shardName := entry.Name()
		// Shard directories are 2-character hex strings
		if len(shardName) != 2 {
			continue
		}

		shardPath := filepath.Join(fs.baseDir, shardName)
		files, err := os.ReadDir(shardPath)
		if err != nil {
			continue
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}

			name := f.Name()
			keyHash, err := hex.DecodeString(name)
			if err != nil {
				continue // skip non-hex filenames
			}
			if len(keyHash) != KeyHashSize {
				continue // skip invalid-length hashes
			}
			result = append(result, keyHash)
		}
	}

	return result, nil
}
