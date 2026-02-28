package vault

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/tongxiaofeng/libbitfs-go/method42"
)

// CatOpts holds options for the Cat (view file) operation.
type CatOpts struct {
	Path string
}

// FileInfo describes a file's metadata returned by Cat/Get.
type FileInfo struct {
	MimeType string
	FileSize uint64
	Access   string
}

// Cat reads a file from the vault and returns its decrypted content.
// The caller is responsible for reading from the returned io.Reader.
func (e *Engine) Cat(opts *CatOpts) (io.Reader, *FileInfo, error) {
	// 1. Find the node by path.
	node := e.State.FindNodeByPath(opts.Path)
	if node == nil {
		return nil, nil, fmt.Errorf("engine: %q not found", opts.Path)
	}
	if node.Type != "file" {
		return nil, nil, fmt.Errorf("engine: %q is a %s, not a file", opts.Path, node.Type)
	}
	if node.KeyHash == "" {
		return nil, nil, fmt.Errorf("engine: %q has no content (key_hash is empty)", opts.Path)
	}

	// 2. Decode key_hash.
	keyHash, err := hex.DecodeString(node.KeyHash)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: invalid key_hash for %q: %w", opts.Path, err)
	}

	// 3. Fetch ciphertext via ContentResolver.
	ciphertext, err := e.Resolver.Fetch(keyHash)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: fetch content for %q: %w", opts.Path, err)
	}

	// 4. Derive the node's key pair for decryption.
	kp, err := e.Wallet.DeriveNodeKey(node.VaultIndex, node.ChildIndices, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: derive key for %q: %w", opts.Path, err)
	}

	// 5. Determine access mode.
	var accessMode method42.Access
	switch node.Access {
	case "private":
		accessMode = method42.AccessPrivate
	case "paid":
		return nil, nil, fmt.Errorf("engine: %q has paid access; use daemon buyer workflow to purchase content", opts.Path)
	default:
		accessMode = method42.AccessFree
	}

	// 6. Decrypt.
	decResult, err := method42.Decrypt(ciphertext, kp.PrivateKey, kp.PublicKey, keyHash, accessMode)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: decrypt %q: %w", opts.Path, err)
	}

	info := &FileInfo{
		MimeType: node.MimeType,
		FileSize: node.FileSize,
		Access:   node.Access,
	}

	return bytes.NewReader(decResult.Plaintext), info, nil
}
