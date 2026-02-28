package vault

import (
	"encoding/hex"
	"fmt"
	"path"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/method42"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// MoveOpts holds options for the Move (rename) operation.
type MoveOpts struct {
	VaultIndex uint32
	SrcPath    string
	DstPath    string
	Force      bool // skip interactive warnings (for non-interactive/agent use)
}

// Move renames or moves a node. Same-directory renames update a single parent;
// cross-directory moves update both the source and destination parents.
func (v *Vault) Move(opts *MoveOpts) (*Result, error) {
	srcDir := path.Dir(opts.SrcPath)
	dstDir := path.Dir(opts.DstPath)

	// Find the source node.
	nodeState := v.State.FindNodeByPath(opts.SrcPath)
	if nodeState == nil {
		return nil, fmt.Errorf("vault: source %q not found", opts.SrcPath)
	}

	if srcDir != dstDir {
		return v.crossDirectoryMove(opts, nodeState)
	}

	// Find the parent directory.
	parent, err := v.resolveParentDir(srcDir, opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("vault: parent directory %q not found", srcDir)
	}

	// Check destination name doesn't exist.
	dstName := path.Base(opts.DstPath)
	srcName := path.Base(opts.SrcPath)
	for _, c := range parent.Children {
		if c.Name == dstName {
			return nil, fmt.Errorf("vault: %q already exists in %q", dstName, srcDir)
		}
	}

	// Temporarily rename in parent's children list for the build.
	renamedIdx := -1
	for i, c := range parent.Children {
		if c.Name == srcName {
			renamedIdx = i
			break
		}
	}
	if renamedIdx == -1 {
		return nil, fmt.Errorf("vault: %q not found in parent children", srcName)
	}

	parent.Children[renamedIdx].Name = dstName
	txHex, txIDHex, err := v.buildParentSelfUpdate(parent)
	if err != nil {
		parent.Children[renamedIdx].Name = srcName // restore on failure
		return nil, fmt.Errorf("vault: update parent: %w", err)
	}

	// TX build succeeded — apply remaining state changes.
	parent.TxID = txIDHex
	nodeState.Path = opts.DstPath

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Moved %s -> %s", opts.SrcPath, opts.DstPath),
		NodePub: parent.PubKeyHex,
	}, nil
}

// crossDirectoryMove moves a node between two different directories using a
// single atomic batch transaction containing four operations:
//
//	Op1: OpCreate — create new child at destination (new key, re-encrypted content)
//	Op2: OpDelete — delete source node (UTXO dies, LinkTarget=new P_node as moved_to)
//	Op3: OpUpdate — update source parent (remove child entry)
//	Op4: OpUpdate — update destination parent (add child entry)
//
// All four operations are packed into one transaction: single fee UTXO, single
// signing pass, fully atomic. If any part fails, nothing is broadcast.
func (v *Vault) crossDirectoryMove(opts *MoveOpts, srcNodeState *NodeState) (*Result, error) {
	// Cross-directory move only supports files.
	// Directory moves would require recursive re-keying of all descendants.
	if srcNodeState.Type == "dir" {
		return nil, fmt.Errorf("vault: cross-directory move of directories is not supported")
	}

	srcDir := path.Dir(opts.SrcPath)
	dstDir := path.Dir(opts.DstPath)
	srcName := path.Base(opts.SrcPath)
	dstName := path.Base(opts.DstPath)

	// 1. Find source parent directory.
	srcParent, err := v.resolveParentDir(srcDir, opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("vault: source directory %q: %w", srcDir, err)
	}

	// 2. Find destination parent directory.
	dstParent, err := v.resolveParentDir(dstDir, opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("vault: destination directory %q: %w", dstDir, err)
	}

	// 3. Check destination doesn't already have this name.
	for _, c := range dstParent.Children {
		if c.Name == dstName {
			return nil, fmt.Errorf("vault: %q already exists in %q", dstName, dstDir)
		}
	}

	// 4. Find the child entry in source parent.
	var srcChildIdx = -1
	for i, c := range srcParent.Children {
		if c.Name == srcName {
			srcChildIdx = i
			break
		}
	}
	if srcChildIdx == -1 {
		return nil, fmt.Errorf("vault: %q not found in source directory", srcName)
	}

	// 5. Read encrypted content from store via source KeyHash.
	srcKeyHash, err := hex.DecodeString(srcNodeState.KeyHash)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid source key hash: %w", err)
	}
	ciphertext, err := v.Store.Get(srcKeyHash)
	if err != nil {
		return nil, fmt.Errorf("vault: read source content: %w", err)
	}

	// 6. Decrypt with source node's Method 42 key.
	srcKP, err := v.Wallet.DeriveNodeKey(srcNodeState.VaultIndex, srcNodeState.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive source key: %w", err)
	}

	var srcAccess method42.Access
	switch srcNodeState.Access {
	case "private":
		srcAccess = method42.AccessPrivate
	case "paid":
		return nil, fmt.Errorf("vault: %q has paid access; use daemon buyer workflow to purchase content", opts.SrcPath)
	default:
		srcAccess = method42.AccessFree
	}

	decResult, err := method42.Decrypt(ciphertext, srcKP.PrivateKey, srcKP.PublicKey, srcKeyHash, srcAccess)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt source: %w", err)
	}

	// 7. Derive new child key at destination (new HD index).
	childIdx := dstParent.NextChildIdx
	childIndices := append(append([]uint32{}, dstParent.ChildIndices...), childIdx)
	childKP, err := v.Wallet.DeriveNodeKey(opts.VaultIndex, childIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive child key: %w", err)
	}
	childPubHex := hex.EncodeToString(childKP.PublicKey.Compressed())

	// 8. Re-encrypt with new key.
	encResult, err := method42.Encrypt(decResult.Plaintext, childKP.PrivateKey, childKP.PublicKey, srcAccess)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt copy: %w", err)
	}

	// --- Build single atomic batch with 4 ops ---

	// Build Op1 payload: CreateChild at destination.
	var accessLevel metanet.AccessLevel
	switch srcNodeState.Access {
	case "private":
		accessLevel = metanet.AccessPrivate
	case "paid":
		accessLevel = metanet.AccessPaid
	default:
		accessLevel = metanet.AccessFree
	}

	createNode := &metanet.Node{
		Version:     1,
		Type:        metanet.NodeType(nodeTypeInt(srcNodeState.Type)),
		Op:          metanet.OpCreate,
		MimeType:    srcNodeState.MimeType,
		FileSize:    srcNodeState.FileSize,
		KeyHash:     encResult.KeyHash,
		Access:      accessLevel,
		Timestamp:   uint64(time.Now().Unix()),
		Parent:      mustDecodeHex(dstParent.PubKeyHex),
		Index:       childIdx,
		Keywords:    srcNodeState.Keywords,
		Description: srcNodeState.Description,
		Domain:      srcNodeState.Domain,
		OnChain:     srcNodeState.OnChain,
		Compression: srcNodeState.Compression,
	}
	createPayload, err := serializePayloadForChain(createNode, childKP.PrivateKey, childKP.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize create payload: %w", err)
	}

	// Build Op2 payload: Delete source node.
	deleteNode := &metanet.Node{
		Version:    1,
		Type:       metanet.NodeType(nodeTypeInt(srcNodeState.Type)),
		Op:         metanet.OpDelete,
		Timestamp:  uint64(time.Now().Unix()),
		LinkTarget: childKP.PublicKey.Compressed(), // "moved_to" pointer
	}
	deletePayload, err := metanet.SerializePayload(deleteNode)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize delete payload: %w", err)
	}

	// Build Op3 payload: Update source parent (remove child entry).
	srcChildrenAfter := make([]*ChildState, 0, len(srcParent.Children)-1)
	srcChildrenAfter = append(srcChildrenAfter, srcParent.Children[:srcChildIdx]...)
	srcChildrenAfter = append(srcChildrenAfter, srcParent.Children[srcChildIdx+1:]...)

	origSrcChildren := srcParent.Children
	srcParent.Children = srcChildrenAfter
	srcParentPayload, err := v.buildParentUpdatePayload(srcParent, nil)
	srcParent.Children = origSrcChildren // restore
	if err != nil {
		return nil, fmt.Errorf("vault: serialize src parent payload: %w", err)
	}

	// Build Op4 payload: Update destination parent (add child entry).
	dstParentPayload, err := v.buildParentUpdatePayload(dstParent, &ChildState{
		Name:     dstName,
		Type:     srcNodeState.Type,
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: serialize dst parent payload: %w", err)
	}

	// Allocate UTXOs: dst parent, src node, src parent, fee.
	dstParentTxID, err := TxIDBytes(dstParent.TxID)
	if err != nil {
		return nil, fmt.Errorf("vault: dst parent txid: %w", err)
	}
	dstParentUTXO, dstParentUS, err := v.getNodeUTXOWithState(dstParent.PubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("vault: dst parent UTXO: %w", err)
	}

	srcNodeUTXO, srcNodeUS, err := v.getNodeUTXOWithState(srcNodeState.PubKeyHex)
	if err != nil {
		dstParentUS.Spent = false
		return nil, fmt.Errorf("vault: src node UTXO: %w", err)
	}

	srcParentUTXO, srcParentUS, err := v.getNodeUTXOWithState(srcParent.PubKeyHex)
	if err != nil {
		dstParentUS.Spent = false
		srcNodeUS.Spent = false
		return nil, fmt.Errorf("vault: src parent UTXO: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		dstParentUS.Spent = false
		srcNodeUS.Spent = false
		srcParentUS.Spent = false
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(5000)
	if err != nil {
		dstParentUS.Spent = false
		srcNodeUS.Spent = false
		srcParentUS.Spent = false
		return nil, err
	}

	allSuccess := false
	defer func() {
		if !allSuccess {
			dstParentUS.Spent = false
			srcNodeUS.Spent = false
			srcParentUS.Spent = false
			feeUS.Spent = false
		}
	}()

	// Derive keys for all participants.
	dstParentKP, err := v.Wallet.DeriveNodeKey(dstParent.VaultIndex, dstParent.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive dst parent key: %w", err)
	}
	var dstParentParentTxID []byte
	if dstParent.ParentTxID != "" {
		dstParentParentTxID, err = TxIDBytes(dstParent.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

	var srcParentTxIDBytes []byte
	if srcNodeState.ParentTxID != "" {
		srcParentTxIDBytes, err = TxIDBytes(srcNodeState.ParentTxID)
		if err != nil {
			return nil, fmt.Errorf("vault: src parent txid: %w", err)
		}
	}

	srcParentKP, err := v.Wallet.DeriveNodeKey(srcParent.VaultIndex, srcParent.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive src parent key: %w", err)
	}
	var srcParentParentTxID []byte
	if srcParent.ParentTxID != "" {
		srcParentParentTxID, err = TxIDBytes(srcParent.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

	// Assemble batch: 4 ops in one atomic transaction.
	batch := tx.NewMutationBatch()

	// Op1: Create child at destination (spends dstParentUTXO as Metanet edge).
	batch.AddCreateChild(childKP.PublicKey, dstParentTxID, createPayload, dstParentUTXO, dstParentUTXO.PrivateKey)

	// Op2: Delete source node (spends srcNodeUTXO, no P2PKH refresh — UTXO dies).
	batch.AddDelete(srcKP.PublicKey, srcParentTxIDBytes, deletePayload, srcNodeUTXO, srcKP.PrivateKey)

	// Op3: Update source parent (remove child from children list).
	batch.AddSelfUpdate(srcParentKP.PublicKey, srcParentParentTxID, srcParentPayload, srcParentUTXO, srcParentKP.PrivateKey)

	// Op4: Update destination parent (add child to children list).
	// dstParentUTXO is same as Op1's — gets deduped to one input.
	batch.AddSelfUpdate(dstParentKP.PublicKey, dstParentParentTxID, dstParentPayload, dstParentUTXO, dstParentKP.PrivateKey)

	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("vault: batch cross-move tx: %w", err)
	}

	// Store new encrypted content.
	if err := v.Store.Put(encResult.KeyHash, encResult.Ciphertext); err != nil {
		return nil, fmt.Errorf("vault: store copy: %w", err)
	}

	allSuccess = true
	txIDHex := hex.EncodeToString(result.TxID)

	// --- Apply state changes ---

	// Register new child node.
	childState := &NodeState{
		PubKeyHex:    childPubHex,
		TxID:         txIDHex,
		ParentTxID:   dstParent.TxID,
		Type:         srcNodeState.Type,
		Access:       srcNodeState.Access,
		Path:         opts.DstPath,
		VaultIndex:   opts.VaultIndex,
		ChildIndices: childIndices,
		KeyHash:      hex.EncodeToString(encResult.KeyHash),
		FileSize:     srcNodeState.FileSize,
		MimeType:     srcNodeState.MimeType,
		Keywords:     srcNodeState.Keywords,
		Description:  srcNodeState.Description,
		Domain:       srcNodeState.Domain,
		OnChain:      srcNodeState.OnChain,
		Compression:  srcNodeState.Compression,
	}
	if srcNodeState.PricePerKB > 0 {
		childState.PricePerKB = srcNodeState.PricePerKB
	}
	v.State.SetNode(childPubHex, childState)

	// Update destination parent.
	dstParent.Children = append(dstParent.Children, &ChildState{
		Name:     dstName,
		Type:     srcNodeState.Type,
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	dstParent.NextChildIdx = childIdx + 1
	dstParent.TxID = txIDHex

	// Mark source node as deleted.
	srcNodeState.TxID = txIDHex
	srcNodeState.Path = "" // no longer resolvable

	// Update source parent.
	srcParent.Children = srcChildrenAfter
	srcParent.TxID = txIDHex

	// Clean up old encrypted content (best-effort).
	_ = v.Store.Delete(srcKeyHash)

	// Track batch UTXOs: [0]=child(create), [1]=delete(nil), [2]=srcParent, [3]=dstParent.
	v.TrackBatchUTXOs(result, []string{childPubHex, "", srcParent.PubKeyHex, dstParent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Moved %s -> %s (atomic: create+delete+srcUpdate+dstUpdate)", opts.SrcPath, opts.DstPath),
		NodePub: childPubHex,
	}, nil
}
