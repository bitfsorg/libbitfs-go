package vault

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bitfsorg/libbitfs-go/metanet"
	"github.com/bitfsorg/libbitfs-go/tx"
)

// resolveParentDir finds the parent directory node for a given directory path.
// Handles the root directory case (path "/" or ".").
func (v *Vault) resolveParentDir(dirPath string, vaultIdx uint32) (*NodeState, error) {
	parent := v.State.FindNodeByPath(dirPath)
	if parent != nil {
		return parent, nil
	}

	if dirPath == "/" || dirPath == "." {
		rootPubHex, err := v.getRootPubHex(vaultIdx)
		if err != nil {
			return nil, err
		}
		parent = v.State.GetNode(rootPubHex)
		if parent != nil {
			return parent, nil
		}
	}

	return nil, fmt.Errorf("directory %q not found", dirPath)
}

// buildParentUpdatePayload builds a serialized payload for a parent directory update.
// If newChild is non-nil, it is appended to the parent's children list for the payload
// (but the caller is responsible for updating parent.Children in local state).
func (v *Vault) buildParentUpdatePayload(parent *NodeState, newChild *ChildState) ([]byte, error) {
	var children []metanet.ChildEntry
	for _, c := range parent.Children {
		children = append(children, metanet.ChildEntry{
			Index:    c.Index,
			Name:     c.Name,
			Type:     metanet.NodeType(nodeTypeInt(c.Type)),
			PubKey:   mustDecodeHex(c.PubKey),
			Hardened: c.Hardened,
		})
	}

	nextChildIdx := parent.NextChildIdx
	if newChild != nil {
		children = append(children, metanet.ChildEntry{
			Index:    newChild.Index,
			Name:     newChild.Name,
			Type:     metanet.NodeType(nodeTypeInt(newChild.Type)),
			PubKey:   mustDecodeHex(newChild.PubKey),
			Hardened: newChild.Hardened,
		})
		if newChild.Index >= nextChildIdx {
			nextChildIdx = newChild.Index + 1
		}
	}

	parentNode := &metanet.Node{
		Version:        1,
		Type:           metanet.NodeTypeDir,
		Op:             metanet.OpUpdate,
		Access:         metanet.AccessFree,
		Timestamp:      uint64(time.Now().Unix()),
		Children:       children,
		NextChildIndex: nextChildIdx,
	}

	parentNode.Keywords = parent.Keywords
	parentNode.Description = parent.Description
	parentNode.Domain = parent.Domain
	parentNode.OnChain = parent.OnChain
	parentNode.Compression = parent.Compression

	return metanet.SerializePayload(parentNode)
}

// buildParentSelfUpdate builds and signs a SelfUpdate transaction for a parent
// directory node, reflecting its current children list using MutationBatch.
// Returns the signed tx hex and tx ID hex.
func (v *Vault) buildParentSelfUpdate(parent *NodeState) (txHex string, txIDHex string, err error) {
	parentKP, err := v.Wallet.DeriveNodeKey(parent.VaultIndex, parent.ChildIndices, nil)
	if err != nil {
		return "", "", fmt.Errorf("derive parent key: %w", err)
	}

	payload, err := v.buildParentUpdatePayload(parent, nil)
	if err != nil {
		return "", "", fmt.Errorf("serialize payload: %w", err)
	}

	var parentTxIDBytes []byte
	if parent.ParentTxID != "" {
		parentTxIDBytes, err = TxIDBytes(parent.ParentTxID)
		if err != nil {
			return "", "", err
		}
	}

	parentUTXO, parentUS, err := v.getNodeUTXOWithState(parent.PubKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("parent UTXO: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		parentUS.Spent = false
		return "", "", err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(2000)
	if err != nil {
		parentUS.Spent = false
		return "", "", err
	}

	success := false
	defer func() {
		if !success {
			parentUS.Spent = false
			feeUS.Spent = false
		}
	}()

	batch := tx.NewMutationBatch()
	batch.AddSelfUpdate(parentKP.PublicKey, parentTxIDBytes, payload, parentUTXO, parentKP.PrivateKey)
	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	signedHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return "", "", fmt.Errorf("batch self-update tx: %w", err)
	}

	success = true
	txIDHex = hex.EncodeToString(result.TxID)

	v.TrackBatchUTXOs(result, []string{parent.PubKeyHex}, changePubHex)

	return signedHex, txIDHex, nil
}
