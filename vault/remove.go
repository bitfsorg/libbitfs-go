package vault

import (
	"encoding/hex"
	"fmt"
	"path"
	"time"

	"github.com/bitfsorg/libbitfs-go/metanet"
	"github.com/bitfsorg/libbitfs-go/tx"
)

// RemoveOpts holds options for the Remove operation.
type RemoveOpts struct {
	VaultIndex uint32
	Path       string // remote path to remove
}

// Remove marks a node as deleted via a single atomic batch transaction
// containing both the node deletion and parent directory update.
func (v *Vault) Remove(opts *RemoveOpts) (*Result, error) {
	var result *Result
	err := v.withWriteLock(func() error {
		var err error
		result, err = v.removeInner(opts)
		return err
	})
	return result, err
}

func (v *Vault) removeInner(opts *RemoveOpts) (*Result, error) {
	// Find the node.
	nodeState := v.State.FindNodeByPath(opts.Path)
	if nodeState == nil {
		return nil, fmt.Errorf("vault: node %q not found", opts.Path)
	}

	// Reject non-empty directory removal.
	if nodeState.Type == "dir" && len(nodeState.Children) > 0 {
		return nil, fmt.Errorf("vault: directory %q is not empty (%d children)", opts.Path, len(nodeState.Children))
	}

	// Derive key pair for the node being deleted.
	kp, err := v.Wallet.DeriveNodeKey(nodeState.VaultIndex, nodeState.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive key: %w", err)
	}

	// Build delete payload.
	node := &metanet.Node{
		Version:   1,
		Type:      metanet.NodeType(nodeTypeInt(nodeState.Type)),
		Op:        metanet.OpDelete,
		Timestamp: uint64(time.Now().Unix()),
	}

	payload, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	// Get parent TxID for the node.
	var parentTxID []byte
	if nodeState.ParentTxID != "" {
		parentTxID, err = TxIDBytes(nodeState.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

	// Get node UTXO (for the delete op).
	nodeUTXO, nodeUS, err := v.getNodeUTXOWithState(nodeState.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("vault: node UTXO: %w", err)
	}

	// Resolve parent directory for the update op.
	parentDir := path.Dir(opts.Path)
	parent, parentErr := v.resolveParentDir(parentDir, opts.VaultIndex)
	if parentErr != nil {
		nodeUS.Spent = false
		return nil, fmt.Errorf("vault: parent directory %q: %w", parentDir, parentErr)
	}

	// Build new children slice without the removed entry.
	childName := path.Base(opts.Path)
	childrenAfter := make([]*ChildState, 0, len(parent.Children))
	for _, c := range parent.Children {
		if c.Name != childName {
			childrenAfter = append(childrenAfter, c)
		}
	}

	// Build parent update payload with child removed.
	origChildren := parent.Children
	parent.Children = childrenAfter
	parentPayload, buildErr := v.buildParentUpdatePayload(parent, nil)
	parent.Children = origChildren // restore
	if buildErr != nil {
		nodeUS.Spent = false
		return nil, fmt.Errorf("vault: parent payload: %w", buildErr)
	}

	// Derive parent key pair.
	parentKP, err := v.Wallet.DeriveNodeKey(parent.VaultIndex, parent.ChildIndices, nil)
	if err != nil {
		nodeUS.Spent = false
		return nil, fmt.Errorf("vault: derive parent key: %w", err)
	}
	var parentParentTxID []byte
	if parent.ParentTxID != "" {
		parentParentTxID, err = TxIDBytes(parent.ParentTxID)
		if err != nil {
			nodeUS.Spent = false
			return nil, err
		}
	}

	// Get parent UTXO (for the self-update op).
	parentUTXO, parentUS, err := v.getNodeUTXOWithState(parent.PubKeyHex)
	if err != nil {
		nodeUS.Spent = false
		return nil, fmt.Errorf("vault: parent UTXO: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		nodeUS.Spent = false
		parentUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(3000)
	if err != nil {
		nodeUS.Spent = false
		parentUS.Spent = false
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			nodeUS.Spent = false
			parentUS.Spent = false
			feeUS.Spent = false
		}
	}()

	// Build single atomic batch: OpDelete(node) + OpUpdate(parent).
	batch := tx.NewMutationBatch()
	batch.AddDelete(kp.PublicKey, parentTxID, payload, nodeUTXO, kp.PrivateKey)
	batch.AddSelfUpdate(parentKP.PublicKey, parentParentTxID, parentPayload, parentUTXO, parentKP.PrivateKey)
	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("vault: batch remove tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// Apply state changes atomically.
	nodeState.TxID = txIDHex
	parent.Children = childrenAfter
	parent.TxID = txIDHex

	// Track batch UTXOs: [0]=delete(nil UTXO), [1]=parent.
	v.TrackBatchUTXOs(result, []string{"", parent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Removed %s (atomic: delete+parentUpdate)", opts.Path),
		NodePub: nodeState.PubKeyHex,
	}, nil
}

// nodeTypeInt converts a string node type to int for metanet.NodeType.
func nodeTypeInt(s string) int32 {
	switch s {
	case "dir":
		return int32(metanet.NodeTypeDir)
	case "link":
		return int32(metanet.NodeTypeLink)
	default:
		return int32(metanet.NodeTypeFile)
	}
}
