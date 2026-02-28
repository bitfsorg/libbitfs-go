package vault

import (
	"encoding/hex"
	"fmt"
	"path"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// RemoveOpts holds options for the Remove operation.
type RemoveOpts struct {
	VaultIndex uint32
	Path       string // remote path to remove
}

// Remove marks a node as deleted via SelfUpdate transaction.
func (v *Vault) Remove(opts *RemoveOpts) (*Result, error) {
	// Find the node.
	nodeState := v.State.FindNodeByPath(opts.Path)
	if nodeState == nil {
		return nil, fmt.Errorf("vault: node %q not found", opts.Path)
	}

	// Reject non-empty directory removal.
	if nodeState.Type == "dir" && len(nodeState.Children) > 0 {
		return nil, fmt.Errorf("vault: directory %q is not empty (%d children)", opts.Path, len(nodeState.Children))
	}

	// Derive key pair.
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

	// Get parent TxID.
	var parentTxID []byte
	if nodeState.ParentTxID != "" {
		parentTxID, err = TxIDBytes(nodeState.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

	// Get node UTXO.
	nodeUTXO, nodeUS, err := v.getNodeUTXOWithState(nodeState.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("vault: node UTXO: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		nodeUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(2000)
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

	batch := tx.NewMutationBatch()
	batch.AddSelfUpdate(kp.PublicKey, parentTxID, payload, nodeUTXO, kp.PrivateKey)
	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("vault: batch remove tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// Update local state.
	nodeState.TxID = txIDHex
	v.TrackBatchUTXOs(result, []string{nodeState.PubKeyHex}, changePubHex)

	// --- Update parent directory to remove child entry ---
	parentDir := path.Dir(opts.Path)
	parent, parentErr := v.resolveParentDir(parentDir, opts.VaultIndex)
	if parentErr != nil {
		// Best effort: return node-only result with a warning.
		return &Result{
			TxHex:   txHex,
			TxID:    txIDHex,
			Message: fmt.Sprintf("Removed %s (warning: parent update failed: %v)", opts.Path, parentErr),
			NodePub: nodeState.PubKeyHex,
		}, nil
	}

	// Build new children slice without the removed entry (don't mutate yet).
	childName := path.Base(opts.Path)
	childrenAfter := make([]*ChildState, 0, len(parent.Children))
	for _, c := range parent.Children {
		if c.Name != childName {
			childrenAfter = append(childrenAfter, c)
		}
	}

	// Temporarily swap children for the build, then restore.
	origChildren := parent.Children
	parent.Children = childrenAfter
	parentTxHex, parentTxIDHex, parentBuildErr := v.buildParentSelfUpdate(parent)
	parent.Children = origChildren // restore
	if parentBuildErr != nil {
		// Best effort: return node-only result with a warning.
		return &Result{
			TxHex:   txHex,
			TxID:    txIDHex,
			Message: fmt.Sprintf("Removed %s (warning: parent update failed: %v)", opts.Path, parentBuildErr),
			NodePub: nodeState.PubKeyHex,
		}, nil
	}

	// Both TXs succeeded — now apply state changes.
	parent.Children = childrenAfter
	parent.TxID = parentTxIDHex

	return &Result{
		TxHex:   txHex + "\n" + parentTxHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Removed %s (2 txs: node=%s, parent=%s)", opts.Path, txIDHex[:8], parentTxIDHex[:8]),
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
