package vault

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/method42"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// PutOpts holds options for the Put (upload file) operation.
type PutOpts struct {
	VaultIndex  uint32
	LocalFile   string // local file path
	RemotePath  string // remote path, e.g. "/docs/readme.txt"
	Access      string // "free" or "private"
	Keywords    string // optional comma-separated keywords
	Description string // optional file description
	Domain      string // optional associated domain
	OnChain     bool   // store content on-chain
	Compression int32  // compression type (0=none)
}

// PutFile uploads a local file to the BitFS filesystem.
func (e *Engine) PutFile(opts *PutOpts) (*Result, error) {
	// Read local file.
	plaintext, err := os.ReadFile(opts.LocalFile)
	if err != nil {
		return nil, fmt.Errorf("engine: read file: %w", err)
	}

	// Ensure root exists.
	_, _, err = e.EnsureRootExists(opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("engine: ensure root: %w", err)
	}

	// Resolve parent directory.
	parent, childName, err := e.ResolveParentNode(opts.RemotePath, opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	// Check for duplicate.
	for _, c := range parent.Children {
		if c.Name == childName {
			return nil, fmt.Errorf("engine: %q already exists in %q", childName, parent.Path)
		}
	}

	// Derive child key.
	childIdx := parent.NextChildIdx
	childIndices := append(append([]uint32{}, parent.ChildIndices...), childIdx)
	childKP, err := e.Wallet.DeriveNodeKey(opts.VaultIndex, childIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("engine: derive child key: %w", err)
	}
	childPubHex := hex.EncodeToString(childKP.PublicKey.Compressed())

	// Determine access mode.
	var accessMode method42.Access
	var accessLevel metanet.AccessLevel
	switch opts.Access {
	case "private":
		accessMode = method42.AccessPrivate
		accessLevel = metanet.AccessPrivate
	default:
		accessMode = method42.AccessFree
		accessLevel = metanet.AccessFree
	}

	// Encrypt content.
	encResult, err := method42.Encrypt(plaintext, childKP.PrivateKey, childKP.PublicKey, accessMode)
	if err != nil {
		return nil, fmt.Errorf("engine: encrypt: %w", err)
	}

	// Store encrypted content.
	if err := e.Store.Put(encResult.KeyHash, encResult.Ciphertext); err != nil {
		return nil, fmt.Errorf("engine: store content: %w", err)
	}

	// Build payload.
	mimeType := DetectMimeType(opts.LocalFile)
	node := &metanet.Node{
		Version:     1,
		Type:        metanet.NodeTypeFile,
		Op:          metanet.OpCreate,
		MimeType:    mimeType,
		FileSize:    uint64(len(plaintext)),
		KeyHash:     encResult.KeyHash,
		Access:      accessLevel,
		Timestamp:   uint64(time.Now().Unix()),
		Parent:      mustDecodeHex(parent.PubKeyHex),
		Index:       childIdx,
		Keywords:    opts.Keywords,
		Description: opts.Description,
		Domain:      opts.Domain,
		OnChain:     opts.OnChain,
		Compression: opts.Compression,
	}

	payload, err := serializePayloadForChain(node, childKP.PrivateKey, childKP.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("engine: serialize payload: %w", err)
	}

	// Get parent TxID and UTXO.
	parentTxID, err := TxIDBytes(parent.TxID)
	if err != nil {
		return nil, err
	}

	parentUTXO, parentUS, err := e.getNodeUTXOWithState(parent.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("engine: parent UTXO: %w", err)
	}

	changeAddr, changePriv, err := e.DeriveChangeAddr()
	if err != nil {
		parentUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := e.AllocateFeeUTXOWithState(3000)
	if err != nil {
		parentUS.Spent = false
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			parentUS.Spent = false
			feeUS.Spent = false
		}
	}()

	// Build atomic batch: OpCreate(child) + OpUpdate(parent).
	batch := tx.NewMutationBatch()
	batch.AddCreateChild(childKP.PublicKey, parentTxID, payload, parentUTXO, parentUTXO.PrivateKey)

	// Build parent update payload with new child added.
	parentPayload, err := e.buildParentUpdatePayload(parent, &ChildState{
		Name:     childName,
		Type:     "file",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: parent payload: %w", err)
	}

	parentKP, err := e.Wallet.DeriveNodeKey(parent.VaultIndex, parent.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("engine: derive parent key: %w", err)
	}
	var parentParentTxID []byte
	if parent.ParentTxID != "" {
		parentParentTxID, err = TxIDBytes(parent.ParentTxID)
		if err != nil {
			return nil, err
		}
	}
	batch.AddSelfUpdate(parentKP.PublicKey, parentParentTxID, parentPayload, parentUTXO, parentKP.PrivateKey)

	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("engine: batch put tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// Update local state.
	childState := &NodeState{
		PubKeyHex:    childPubHex,
		TxID:         txIDHex,
		ParentTxID:   parent.TxID,
		Type:         "file",
		Access:       opts.Access,
		Path:         opts.RemotePath,
		VaultIndex:   opts.VaultIndex,
		ChildIndices: childIndices,
		KeyHash:      hex.EncodeToString(encResult.KeyHash),
		FileSize:     uint64(len(plaintext)),
		MimeType:     mimeType,
		Keywords:     opts.Keywords,
		Description:  opts.Description,
		Domain:       opts.Domain,
		OnChain:      opts.OnChain,
		Compression:  opts.Compression,
	}
	e.State.SetNode(childPubHex, childState)

	// Update parent.
	parent.Children = append(parent.Children, &ChildState{
		Name:     childName,
		Type:     "file",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	parent.NextChildIdx = childIdx + 1
	parent.TxID = txIDHex

	// Track batch UTXOs: [0]=child, [1]=parent.
	e.TrackBatchUTXOs(result, []string{childPubHex, parent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Uploaded %s to %s (%d bytes, %s)", path.Base(opts.LocalFile), opts.RemotePath, len(plaintext), opts.Access),
		NodePub: childPubHex,
	}, nil
}
