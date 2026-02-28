package vault

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/method42"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// DecryptOpts holds options for the Decrypt operation.
type DecryptOpts struct {
	Path string // remote path
}

// DecryptNode re-encrypts content from PRIVATE to FREE access.
func (e *Engine) DecryptNode(opts *DecryptOpts) (*Result, error) {
	nodeState := e.State.FindNodeByPath(opts.Path)
	if nodeState == nil {
		return nil, fmt.Errorf("engine: node %q not found", opts.Path)
	}

	if nodeState.Type != "file" {
		return nil, fmt.Errorf("engine: %q is not a file", opts.Path)
	}
	if nodeState.Access != "private" {
		return nil, fmt.Errorf("engine: %q is already %s", opts.Path, nodeState.Access)
	}

	kp, err := e.Wallet.DeriveNodeKey(nodeState.VaultIndex, nodeState.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("engine: derive key: %w", err)
	}

	// Read current ciphertext from store.
	keyHash := mustDecodeHex(nodeState.KeyHash)
	ciphertext, err := e.Store.Get(keyHash)
	if err != nil {
		return nil, fmt.Errorf("engine: read content: %w", err)
	}

	// Re-encrypt PRIVATE -> FREE.
	reEncResult, err := method42.ReEncrypt(ciphertext, kp.PrivateKey, kp.PublicKey, keyHash, method42.AccessPrivate, method42.AccessFree)
	if err != nil {
		return nil, fmt.Errorf("engine: re-encrypt: %w", err)
	}

	// Store new ciphertext (key_hash changes because derivation differs).
	if err := e.Store.Put(reEncResult.KeyHash, reEncResult.Ciphertext); err != nil {
		return nil, fmt.Errorf("engine: store re-encrypted: %w", err)
	}

	// Delete old ciphertext only if key_hash changed (it won't when
	// key_hash = SHA256(SHA256(plaintext)) which is access-mode-independent).
	if !bytes.Equal(keyHash, reEncResult.KeyHash) {
		_ = e.Store.Delete(keyHash)
	}

	// Build SelfUpdate payload.
	node := &metanet.Node{
		Version:   1,
		Type:      metanet.NodeTypeFile,
		Op:        metanet.OpUpdate,
		Access:    metanet.AccessFree,
		KeyHash:   reEncResult.KeyHash,
		Timestamp: uint64(time.Now().Unix()),
	}
	if nodeState.MimeType != "" {
		node.MimeType = nodeState.MimeType
	}
	if nodeState.FileSize > 0 {
		node.FileSize = nodeState.FileSize
	}

	// Preserve extended metadata in on-chain payload.
	node.Keywords = nodeState.Keywords
	node.Description = nodeState.Description
	node.Domain = nodeState.Domain
	node.OnChain = nodeState.OnChain
	node.Compression = nodeState.Compression

	payload, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("engine: serialize payload: %w", err)
	}

	var parentTxID []byte
	if nodeState.ParentTxID != "" {
		parentTxID, err = TxIDBytes(nodeState.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

	nodeUTXO, nodeUS, err := e.getNodeUTXOWithState(nodeState.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("engine: node UTXO: %w", err)
	}

	changeAddr, changePriv, err := e.DeriveChangeAddr()
	if err != nil {
		nodeUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := e.AllocateFeeUTXOWithState(2000)
	if err != nil {
		nodeUS.Spent = false
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			nodeUS.Spent = false
			feeUS.Spent = false
		}
	}()

	// Build atomic batch: OpUpdate(node).
	batch := tx.NewMutationBatch()
	batch.AddSelfUpdate(kp.PublicKey, parentTxID, payload, nodeUTXO, kp.PrivateKey)
	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("engine: batch decrypt tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// Update local state.
	nodeState.TxID = txIDHex
	nodeState.Access = "free"
	nodeState.KeyHash = hex.EncodeToString(reEncResult.KeyHash)
	e.TrackBatchUTXOs(result, []string{nodeState.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Decrypted %s (PRIVATE -> FREE)", opts.Path),
		NodePub: nodeState.PubKeyHex,
	}, nil
}
