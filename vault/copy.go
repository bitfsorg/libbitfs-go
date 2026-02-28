package vault

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/method42"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// CopyOpts holds options for the Copy (file copy) operation.
type CopyOpts struct {
	VaultIndex uint32
	SrcPath    string
	DstPath    string
}

// Copy creates an independent node at DstPath with a new key pair and
// re-encrypted content. Unlike a hard link, the copy has its own identity
// on the Metanet DAG.
func (v *Vault) Copy(opts *CopyOpts) (*Result, error) {
	// 1. Find source node by path.
	srcNode := v.State.FindNodeByPath(opts.SrcPath)
	if srcNode == nil {
		return nil, fmt.Errorf("vault: source %q not found", opts.SrcPath)
	}
	if srcNode.Type != "file" {
		return nil, fmt.Errorf("vault: can only copy files, %q is a %s", opts.SrcPath, srcNode.Type)
	}

	// 2. Read encrypted content from store using src's KeyHash.
	srcKeyHash, err := hex.DecodeString(srcNode.KeyHash)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid source key hash: %w", err)
	}
	ciphertext, err := v.Store.Get(srcKeyHash)
	if err != nil {
		return nil, fmt.Errorf("vault: read source content: %w", err)
	}

	// 3. Decrypt content using source node's key.
	srcKP, err := v.Wallet.DeriveNodeKey(srcNode.VaultIndex, srcNode.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive source key: %w", err)
	}

	var srcAccess method42.Access
	switch srcNode.Access {
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

	// 4. Ensure root exists for destination vault.
	_, _, err = v.EnsureRootExists(opts.VaultIndex)
	if err != nil {
		return nil, fmt.Errorf("vault: ensure root: %w", err)
	}

	// 5. Resolve destination parent.
	dstParent, dstName, err := v.ResolveParentNode(opts.DstPath, opts.VaultIndex)
	if err != nil {
		return nil, err
	}

	// 6. Check for duplicate at destination.
	for _, c := range dstParent.Children {
		if c.Name == dstName {
			return nil, fmt.Errorf("vault: %q already exists in %q", dstName, dstParent.Path)
		}
	}

	// 7. Derive new child key for destination (independent from source).
	childIdx := dstParent.NextChildIdx
	childIndices := append(append([]uint32{}, dstParent.ChildIndices...), childIdx)
	childKP, err := v.Wallet.DeriveNodeKey(opts.VaultIndex, childIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive child key: %w", err)
	}
	childPubHex := hex.EncodeToString(childKP.PublicKey.Compressed())

	// 8. Re-encrypt with new key (preserve same access mode as source).
	encResult, err := method42.Encrypt(decResult.Plaintext, childKP.PrivateKey, childKP.PublicKey, srcAccess)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt copy: %w", err)
	}

	// 9. Store new encrypted content.
	if err := v.Store.Put(encResult.KeyHash, encResult.Ciphertext); err != nil {
		return nil, fmt.Errorf("vault: store copy: %w", err)
	}

	// 10. Build metanet payload (CreateChild, same type/metadata as source).
	var accessLevel metanet.AccessLevel
	switch srcNode.Access {
	case "private":
		accessLevel = metanet.AccessPrivate
	case "paid":
		accessLevel = metanet.AccessPaid
	default:
		accessLevel = metanet.AccessFree
	}

	node := &metanet.Node{
		Version:     1,
		Type:        metanet.NodeTypeFile,
		Op:          metanet.OpCreate,
		MimeType:    srcNode.MimeType,
		FileSize:    srcNode.FileSize,
		KeyHash:     encResult.KeyHash,
		Access:      accessLevel,
		Timestamp:   uint64(time.Now().Unix()),
		Parent:      mustDecodeHex(dstParent.PubKeyHex),
		Index:       childIdx,
		Keywords:    srcNode.Keywords,
		Description: srcNode.Description,
		Domain:      srcNode.Domain,
		OnChain:     srcNode.OnChain,
		Compression: srcNode.Compression,
	}

	payload, err := serializePayloadForChain(node, childKP.PrivateKey, childKP.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	// 11. Get parent TxID and UTXO.
	parentTxID, err := TxIDBytes(dstParent.TxID)
	if err != nil {
		return nil, err
	}
	parentUTXO, parentUS, err := v.getNodeUTXOWithState(dstParent.PubKeyHex)
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

	parentPayload, err := v.buildParentUpdatePayload(dstParent, &ChildState{
		Name:     dstName,
		Type:     "file",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	if err != nil {
		return nil, fmt.Errorf("vault: parent payload: %w", err)
	}

	parentKP, err := v.Wallet.DeriveNodeKey(dstParent.VaultIndex, dstParent.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive parent key: %w", err)
	}
	var parentParentTxID []byte
	if dstParent.ParentTxID != "" {
		parentParentTxID, err = TxIDBytes(dstParent.ParentTxID)
		if err != nil {
			return nil, err
		}
	}
	batch.AddSelfUpdate(parentKP.PublicKey, parentParentTxID, parentPayload, parentUTXO, parentKP.PrivateKey)

	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("vault: batch copy tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	// 12. Update local state.
	childState := &NodeState{
		PubKeyHex:    childPubHex,
		TxID:         txIDHex,
		ParentTxID:   dstParent.TxID,
		Type:         "file",
		Access:       srcNode.Access,
		Path:         opts.DstPath,
		VaultIndex:   opts.VaultIndex,
		ChildIndices: childIndices,
		KeyHash:      hex.EncodeToString(encResult.KeyHash),
		FileSize:     srcNode.FileSize,
		MimeType:     srcNode.MimeType,
		Keywords:     srcNode.Keywords,
		Description:  srcNode.Description,
		Domain:       srcNode.Domain,
		OnChain:      srcNode.OnChain,
		Compression:  srcNode.Compression,
	}
	if srcNode.PricePerKB > 0 {
		childState.PricePerKB = srcNode.PricePerKB
	}
	v.State.SetNode(childPubHex, childState)

	// Update destination parent.
	dstParent.Children = append(dstParent.Children, &ChildState{
		Name:     dstName,
		Type:     "file",
		PubKey:   childPubHex,
		Index:    childIdx,
		Hardened: true,
	})
	dstParent.NextChildIdx = childIdx + 1
	dstParent.TxID = txIDHex

	// Track batch UTXOs: [0]=child, [1]=parent.
	v.TrackBatchUTXOs(result, []string{childPubHex, dstParent.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Copied %s to %s (%d bytes)", opts.SrcPath, opts.DstPath, srcNode.FileSize),
		NodePub: childPubHex,
	}, nil
}
