package vault

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// LinkOpts holds options for the Link operation.
type LinkOpts struct {
	VaultIndex uint32
	TargetPath string // what the link points to
	LinkPath   string // where the link lives
	Soft       bool   // true = soft link, false = hard link
}

// Link creates a hard or soft link.
func (v *Vault) Link(opts *LinkOpts) (*Result, error) {
	var result *Result
	err := v.withWriteLock(func() error {
		var err error
		result, err = v.linkInner(opts)
		return err
	})
	return result, err
}

func (v *Vault) linkInner(opts *LinkOpts) (*Result, error) {
	// Find target node.
	targetNode := v.State.FindNodeByPath(opts.TargetPath)
	if targetNode == nil {
		return nil, fmt.Errorf("vault: target %q not found", opts.TargetPath)
	}

	if opts.Soft {
		return v.createSoftLink(opts, targetNode)
	}
	return v.createHardLink(opts, targetNode)
}

// createSoftLink creates a new link node (CreateChild tx).
func (v *Vault) createSoftLink(opts *LinkOpts, targetNode *NodeState) (*Result, error) {
	_, _, err := v.EnsureRootExists(opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	parent, childName, err := v.ResolveParentNode(opts.LinkPath, opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	for _, c := range parent.Children {
		if c.Name == childName {
			return nil, fmt.Errorf("vault: %q already exists in %q", childName, parent.Path)
		}
	}

	childIdx := parent.NextChildIdx
	childIndices := append(append([]uint32{}, parent.ChildIndices...), childIdx)
	childKP, err := v.Wallet.DeriveNodeKey(opts.VaultIndex, childIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive child key: %w", err)
	}
	childPubHex := hex.EncodeToString(childKP.PublicKey.Compressed())

	node := &metanet.Node{
		Version:    1,
		Type:       metanet.NodeTypeLink,
		Op:         metanet.OpCreate,
		LinkTarget: mustDecodeHex(targetNode.PubKeyHex),
		LinkType:   metanet.LinkTypeSoft,
		Access:     metanet.AccessFree,
		Timestamp:  uint64(time.Now().Unix()),
		Parent:     mustDecodeHex(parent.PubKeyHex),
		Index:      childIdx,
	}

	payload, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	parentTxID, err := TxIDBytes(parent.TxID)
	if err != nil {
		return nil, err
	}

	parentUTXO, parentUS, err := v.getNodeUTXOWithState(parent.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("vault: parent UTXO: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		parentUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(3000)
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

	// Build atomic batch: OpCreate(link) + OpUpdate(parent).
	batch := tx.NewMutationBatch()
	batch.AddCreateChild(childKP.PublicKey, parentTxID, payload, parentUTXO, parentUTXO.PrivateKey)

	parentPayload, err := v.buildParentUpdatePayload(parent, &ChildState{
		Name:     childName,
		Type:     "link",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: parent payload: %w", err)
	}

	parentKP, err := v.Wallet.DeriveNodeKey(parent.VaultIndex, parent.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive parent key: %w", err)
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
		return nil, fmt.Errorf("vault: batch link tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	childState := &NodeState{
		PubKeyHex:    childPubHex,
		TxID:         txIDHex,
		ParentTxID:   parent.TxID,
		Type:         "link",
		Access:       "free",
		Path:         opts.LinkPath,
		VaultIndex:   opts.VaultIndex,
		ChildIndices: childIndices,
		LinkTarget:   targetNode.PubKeyHex,
	}
	v.State.SetNode(childPubHex, childState)

	parent.Children = append(parent.Children, &ChildState{
		Name:     childName,
		Type:     "link",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	parent.NextChildIdx = childIdx + 1
	parent.TxID = txIDHex

	// Track batch UTXOs: [0]=link, [1]=parent.
	v.TrackBatchUTXOs(result, []string{childPubHex, parent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Created soft link %s -> %s", opts.LinkPath, opts.TargetPath),
		NodePub: childPubHex,
	}, nil
}

// createHardLink adds a ChildEntry in the parent pointing to the same PubKey.
// This is a SelfUpdate on the parent directory. Uses build-then-apply pattern
// to keep state consistent if the TX build fails.
func (v *Vault) createHardLink(opts *LinkOpts, targetNode *NodeState) (*Result, error) {
	parent, childName, err := v.ResolveParentNode(opts.LinkPath, opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	for _, c := range parent.Children {
		if c.Name == childName {
			return nil, fmt.Errorf("vault: %q already exists in %q", childName, parent.Path)
		}
	}

	// Prepare new children list with the hard link entry (don't mutate yet).
	newChild := &ChildState{
		Name:     childName,
		Type:     targetNode.Type,
		PubKey:   targetNode.PubKeyHex,
		Index:    parent.NextChildIdx, // doesn't actually derive a new key
		Hardened: false,
	}
	childrenAfter := make([]*ChildState, len(parent.Children)+1)
	copy(childrenAfter, parent.Children)
	childrenAfter[len(parent.Children)] = newChild
	nextIdxAfter := parent.NextChildIdx + 1

	// Temporarily swap children for the build, then restore.
	origChildren := parent.Children
	origNextIdx := parent.NextChildIdx
	parent.Children = childrenAfter
	parent.NextChildIdx = nextIdxAfter
	txHex, txIDHex, err := v.buildParentSelfUpdate(parent)
	parent.Children = origChildren    // restore
	parent.NextChildIdx = origNextIdx // restore
	if err != nil {
		return nil, fmt.Errorf("vault: build self-update tx: %w", err)
	}

	// TX build succeeded — apply state changes.
	parent.Children = childrenAfter
	parent.NextChildIdx = nextIdxAfter
	parent.TxID = txIDHex

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Created hard link %s -> %s", opts.LinkPath, opts.TargetPath),
		NodePub: parent.PubKeyHex,
	}, nil
}
