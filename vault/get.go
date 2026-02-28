package vault

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
)

// GetOpts holds options for the Get (download file) operation.
type GetOpts struct {
	VaultIndex uint32
	RemotePath string
	LocalDir   string // base directory for default file placement
	LocalPath  string // explicit local path (overrides LocalDir + filename)
}

// Get downloads a file from the vault to the local filesystem.
func (e *Engine) Get(opts *GetOpts) (*Result, error) {
	reader, info, err := e.Cat(&CatOpts{
		Path: opts.RemotePath,
	})
	if err != nil {
		return nil, err
	}

	// Determine local path.
	localPath := opts.LocalPath
	if localPath == "" {
		filename := path.Base(opts.RemotePath)
		localPath = filepath.Join(opts.LocalDir, filename)
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return nil, fmt.Errorf("engine: create local directory: %w", err)
	}

	f, err := os.Create(localPath)
	if err != nil {
		return nil, fmt.Errorf("engine: create local file: %w", err)
	}

	var retErr error
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(localPath)
		}
	}()

	n, err := io.Copy(f, reader)
	if err != nil {
		retErr = fmt.Errorf("engine: write local file: %w", err)
		return nil, retErr
	}

	return &Result{
		Message: fmt.Sprintf("Downloaded %s -> %s (%d bytes, %s)", opts.RemotePath, localPath, n, info.MimeType),
	}, nil
}
