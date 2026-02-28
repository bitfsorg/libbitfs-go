package vault

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tongxiaofeng/libbitfs-go/metanet"
	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// SellOpts holds options for the Sell operation.
type SellOpts struct {
	VaultIndex uint32
	Path       string // remote path
	PricePerKB uint64 // price in sats/KB
}

// Sell sets a price on content via SelfUpdate transaction (access → paid).
func (v *Vault) Sell(opts *SellOpts) (*Result, error) {
	nodeState := v.State.FindNodeByPath(opts.Path)
	if nodeState == nil {
		return nil, fmt.Errorf("vault: node %q not found", opts.Path)
	}

	kp, err := v.Wallet.DeriveNodeKey(nodeState.VaultIndex, nodeState.ChildIndices, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: derive key: %w", err)
	}

	node := &metanet.Node{
		Version:    1,
		Type:       metanet.NodeType(nodeTypeInt(nodeState.Type)),
		Op:         metanet.OpUpdate,
		Access:     metanet.AccessPaid,
		PricePerKB: opts.PricePerKB,
		Timestamp:  uint64(time.Now().Unix()),
	}

	if nodeState.KeyHash != "" {
		node.KeyHash = mustDecodeHex(nodeState.KeyHash)
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
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	var parentTxID []byte
	if nodeState.ParentTxID != "" {
		parentTxID, err = TxIDBytes(nodeState.ParentTxID)
		if err != nil {
			return nil, err
		}
	}

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
		return nil, fmt.Errorf("vault: batch sell tx: %w", err)
	}

	success = true
	txIDHex := hex.EncodeToString(result.TxID)

	nodeState.TxID = txIDHex
	nodeState.Access = "paid"
	nodeState.PricePerKB = opts.PricePerKB
	v.TrackBatchUTXOs(result, []string{nodeState.PubKeyHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    txIDHex,
		Message: fmt.Sprintf("Set price for %s to %d sats/KB", opts.Path, opts.PricePerKB),
		NodePub: nodeState.PubKeyHex,
	}, nil
}
