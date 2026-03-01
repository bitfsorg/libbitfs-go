package vault

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvhash "github.com/bsv-blockchain/go-sdk/primitives/hash"

	"github.com/bitfsorg/libbitfs-go/metanet"
	"github.com/bitfsorg/libbitfs-go/method42"
	"github.com/bitfsorg/libbitfs-go/tx"
	"github.com/bitfsorg/libbitfs-go/wallet"
)

// readFile reads a file from disk.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// loadWalletState loads wallet state from a JSON file.
func loadWalletState(path string) (*wallet.WalletState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read wallet state: %w", err)
	}
	var state wallet.WalletState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse wallet state: %w", err)
	}
	return &state, nil
}

// saveWalletState persists wallet state (indices, vaults) to disk.
func (v *Vault) saveWalletState() error {
	statePath := filepath.Join(v.DataDir, "state.json")
	data, err := json.MarshalIndent(v.WState, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal wallet state: %w", err)
	}
	return os.WriteFile(statePath, data, 0600)
}

// pubKeyHash computes HASH160(pubkey) = RIPEMD160(SHA256(pubkey)).
// Returns the 20-byte hash used in P2PKH addresses.
func pubKeyHash(pub *ec.PublicKey) []byte {
	return bsvhash.Hash160(pub.Compressed())
}

// mustDecompressPubKey parses a hex-encoded compressed public key.
// Panics on invalid input — only call with validated data from HD derivation.
func mustDecompressPubKey(hexStr string) *ec.PublicKey {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("mustDecompressPubKey: invalid hex: " + err.Error())
	}
	pub, err := ec.PublicKeyFromBytes(b)
	if err != nil {
		panic("mustDecompressPubKey: invalid public key: " + err.Error())
	}
	return pub
}

// ResolveParentNode finds the parent directory node for a given path.
// Returns the parent's NodeState and the child name.
func (v *Vault) ResolveParentNode(remotePath string, vaultIdx uint32) (*NodeState, string, error) {
	dir := path.Dir(remotePath)
	name := path.Base(remotePath)

	if dir == "/" || dir == "." {
		// Parent is root.
		rootPubHex, err := v.getRootPubHex(vaultIdx)
		if err != nil {
			return nil, "", err
		}
		rootNode := v.State.GetNode(rootPubHex)
		if rootNode == nil {
			return nil, "", fmt.Errorf("vault: root node not initialized; run 'bitfs mkdir /' first")
		}
		return rootNode, name, nil
	}

	parent := v.State.FindNodeByPath(dir)
	if parent == nil {
		return nil, "", fmt.Errorf("vault: parent directory %q not found", dir)
	}
	if parent.Type != "dir" {
		return nil, "", fmt.Errorf("vault: %q is not a directory", dir)
	}
	return parent, name, nil
}

// EnsureRootExists creates the vault root node if it doesn't exist.
func (v *Vault) EnsureRootExists(vaultIdx uint32) (*NodeState, *Result, error) {
	rootPubHex, err := v.getRootPubHex(vaultIdx)
	if err != nil {
		return nil, nil, err
	}

	existing := v.State.GetNode(rootPubHex)
	if existing != nil {
		return existing, nil, nil
	}

	// Create root node.
	return v.createRootNode(vaultIdx, rootPubHex)
}

// getRootPubHex returns the hex pubkey for a vault's root node.
func (v *Vault) getRootPubHex(vaultIdx uint32) (string, error) {
	kp, err := v.Wallet.DeriveVaultRootKey(vaultIdx)
	if err != nil {
		return "", fmt.Errorf("vault: derive vault root key: %w", err)
	}
	return hex.EncodeToString(kp.PublicKey.Compressed()), nil
}

// createRootNode creates and tracks a new root node transaction.
func (v *Vault) createRootNode(vaultIdx uint32, rootPubHex string) (*NodeState, *Result, error) {
	kp, err := v.Wallet.DeriveVaultRootKey(vaultIdx)
	if err != nil {
		return nil, nil, err
	}

	node := &metanet.Node{
		Version:   1,
		Type:      metanet.NodeTypeDir,
		Op:        metanet.OpCreate,
		Access:    metanet.AccessFree,
		Timestamp: uint64(time.Now().Unix()),
	}

	result, err := v.buildAndSignRootTx(kp, node, rootPubHex)
	if err != nil {
		return nil, nil, err
	}

	rootState := &NodeState{
		PubKeyHex:    rootPubHex,
		TxID:         result.TxID,
		Type:         "dir",
		Access:       "free",
		Path:         "/",
		VaultIndex:   vaultIdx,
		ChildIndices: nil,
		Children:     make([]*ChildState, 0),
	}

	v.State.SetNode(rootPubHex, rootState)
	v.State.mu.Lock()
	v.State.RootTxID[vaultIdx] = result.TxID
	v.State.mu.Unlock()

	return rootState, result, nil
}

// buildAndSignRootTx builds and signs a CreateRoot transaction using MutationBatch.
func (v *Vault) buildAndSignRootTx(kp *wallet.KeyPair, node *metanet.Node, nodePubHex string) (*Result, error) {
	payload, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize payload: %w", err)
	}

	changeAddr, changePriv, err := v.DeriveChangeAddr()
	if err != nil {
		return nil, err
	}
	changePubHex := hex.EncodeToString(changePriv.PubKey().Compressed())

	feeUTXO, feeUS, err := v.AllocateFeeUTXOWithState(2000)
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			feeUS.Spent = false
		}
	}()

	batch := tx.NewMutationBatch()
	batch.AddCreateRoot(kp.PublicKey, payload)
	batch.AddFeeInput(feeUTXO)
	batch.SetChange(changeAddr)

	txHex, result, err := buildAndSignBatch(batch)
	if err != nil {
		return nil, fmt.Errorf("vault: batch root tx: %w", err)
	}

	success = true
	v.TrackBatchUTXOs(result, []string{nodePubHex}, changePubHex)

	return &Result{
		TxHex:   txHex,
		TxID:    hex.EncodeToString(result.TxID),
		Message: "Root node created",
		NodePub: nodePubHex,
	}, nil
}

// serializePayloadForChain serializes a node's TLV payload for on-chain storage.
// For PRIVATE nodes, the full TLV is encrypted via Method 42 and wrapped in a
// minimal cleartext envelope (version, type, op, access, EncPayload).
// For non-PRIVATE nodes, this is a plain SerializePayload call.
func serializePayloadForChain(node *metanet.Node, privKey *ec.PrivateKey, pubKey *ec.PublicKey) ([]byte, error) {
	if node.Access != metanet.AccessPrivate {
		return metanet.SerializePayload(node)
	}

	// Serialize the full TLV (all metadata fields).
	fullTLV, err := metanet.SerializePayload(node)
	if err != nil {
		return nil, fmt.Errorf("vault: serialize full TLV: %w", err)
	}

	// Encrypt the full TLV as metadata.
	encPayload, err := method42.EncryptMetadata(fullTLV, privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("vault: encrypt metadata: %w", err)
	}

	// Build minimal cleartext envelope with only structural fields.
	envelope := &metanet.Node{
		Version:    node.Version,
		Type:       node.Type,
		Op:         node.Op,
		Access:     metanet.AccessPrivate,
		EncPayload: encPayload,
	}
	return metanet.SerializePayload(envelope)
}

// DetectMimeType guesses MIME type from filename extension.
func DetectMimeType(filename string) string {
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".mp4":
		return "video/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".zip":
		return "application/zip"
	case ".gz":
		return "application/gzip"
	case ".tar":
		return "application/x-tar"
	case ".csv":
		return "text/csv"
	case ".md":
		return "text/markdown"
	default:
		return http.DetectContentType([]byte{})
	}
}

// NodeTypeString converts a metanet.NodeType to a string.
func NodeTypeString(nt metanet.NodeType) string {
	switch nt {
	case metanet.NodeTypeFile:
		return "file"
	case metanet.NodeTypeDir:
		return "dir"
	case metanet.NodeTypeLink:
		return "link"
	default:
		return "unknown"
	}
}

// AccessString converts a metanet.AccessLevel to a string.
func AccessString(al metanet.AccessLevel) string {
	switch al {
	case metanet.AccessPrivate:
		return "private"
	case metanet.AccessFree:
		return "free"
	case metanet.AccessPaid:
		return "paid"
	default:
		return "unknown"
	}
}

// nodeTypeFromString converts a string to a metanet.NodeType.
func nodeTypeFromString(s string) metanet.NodeType {
	switch s {
	case "dir":
		return metanet.NodeTypeDir
	case "link":
		return metanet.NodeTypeLink
	default:
		return metanet.NodeTypeFile
	}
}
