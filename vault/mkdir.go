package vault

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// MkdirOpts holds options for the Mkdir operation.
type MkdirOpts struct {
	VaultIndex uint32
	Path       string // remote path, v.g. "/docs"
}

// Mkdir creates a directory node at the given path.
func (v *Vault) Mkdir(opts *MkdirOpts) (*Result, error) {
	// Ensure root exists.
	rootNode, rootResult, err := v.EnsureRootExists(opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("vault: ensure root: %w", err)
	}

	// If creating root ("/"), return the root creation result.
	if opts.Path == "/" {
		if rootResult != nil {
			rootResult.Message = "Created root directory /"
			return rootResult, nil
		}
		return &Result{
			TxID:    rootNode.TxID,
			Message: "Root directory already exists",
			NodePub: rootNode.PubKeyHex,
		}, nil
	}

	// Resolve parent directory.
	parent, childName, err := v.ResolveParentNode(opts.Path, opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	// Check for duplicate child name.
	for _, c := range parent.Children {
		if c.Name == childName {
			return nil, fmt.Errorf("vault: %q already exists in %q", childName, parent.Path)
		}
	}

	// Derive child key.
	childIdx := parent.NextChildIdx
	childIndices := append(append([]uint32{}, parent.ChildIndices...), childIdx)
	childKP, err := v.Wallet.DeriveNodeKey(opts.VaultIndex, childIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive child key: %w", err)
	}
	childPubHex := hex.EncodeToString(childKP.PublicKey.Compressed())

	// Build payload.
	node := &metanet.Node{
		Version:   1,
		Type:      metanet.NodeTypeDir,
		Op:        metanet.OpCreate,
		Access:    metanet.AccessFree,
		Timestamp: uint64(time.Now().Unix()),
		Parent:    mustDecodeHex(parent.PubKeyHex),
		Index:     childIdx,
	}

	payload, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	// Get parent TxID and UTXO.
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

	// Build atomic batch: OpCreate(child) + OpUpdate(parent).
	batch := tx.NewMutationBatch()
	batch.AddCreateChild(childKP.PublicKey, parentTxID, payload, parentUTXO, parentUTXO.PrivateKey)

	// Build parent update payload with new child added.
	parentPayload, err := v.buildParentUpdatePayload(parent, &ChildState{
		Name:     childName,
		Type:     "dir",
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
		return nil, fmt.Errorf("vault: batch mkdir tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// Update local state.
	childPath := opts.Path
	childState := &NodeState{
		PubKeyHex:    childPubHex,
		TxID:         txIDHex,
		ParentTxID:   parent.TxID,
		Type:         "dir",
		Access:       "free",
		Path:         childPath,
		VaultIndex:   opts.VaultIndex,
		ChildIndices: childIndices,
		Children:     make([]*ChildState, 0),
	}
	v.State.SetNode(childPubHex, childState)

	// Update parent.
	parent.Children = append(parent.Children, &ChildState{
		Name:     childName,
		Type:     "dir",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	parent.NextChildIdx = childIdx + 1
	parent.TxID = txIDHex

	// Track batch UTXOs: [0]=child, [1]=parent.
	v.TrackBatchUTXOs(result, []string{childPubHex, parent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Created directory %s", opts.Path),
		NodePub: childPubHex,
	}, nil
}

// getNodeUTXOWithState retrieves a node's UTXO from local state and returns both
// the tx UTXO (with private key) and the underlying UTXOState for rollback.
// If the transaction build/sign fails, the caller should set utxoState.Spent = false
// to release the UTXO back to the pool.
//
// NOTE: This function is not safe for concurrent use. The Vault assumes a
// single-writer model — concurrent callers must be serialized externally
// (v.g., the daemon HTTP server serializes write operations through a mutex).
func (v *Vault) getNodeUTXOWithState(pubKeyHex string) (*txUTXO, *UTXOState, error) {
	utxoState := v.State.GetNodeUTXO(pubKeyHex)
	if utxoState == nil {
		return nil, nil, fmt.Errorf("no UTXO for node %s", pubKeyHex[:16])
	}
	utxoState.Spent = true // mark for exclusion during this operation
	txU, err := v.utxoStateToTx(utxoState)
	if err != nil {
		utxoState.Spent = false // rollback on conversion error
		return nil, nil, err
	}
	return txU, utxoState, nil
}

// mustDecodeHex decodes a hex string, returning nil on error.
func mustDecodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// txUTXO is an alias for the tx package's UTXO type.
type txUTXO = tx.UTXO
