package vault

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LocalState tracks Metanet nodes and UTXOs created locally.
// Persisted as JSON at {dataDir}/nodes.json.
type LocalState struct {
	Nodes           map[string]*NodeState `json:"nodes"`            // key: pubkey hex (compressed)
	UTXOs           []*UTXOState          `json:"utxos"`            // tracked unspent outputs
	RootTxID        map[uint32]string     `json:"root_txid"`        // vault index → root TxID hex
	PublishBindings []*PublishBinding     `json:"publish_bindings"` // domain → vault bindings

	mu   sync.Mutex `json:"-"`
	path string     `json:"-"` // file path for persistence
}

// NodeState tracks a single Metanet node in local state.
type NodeState struct {
	PubKeyHex    string            `json:"pubkey"`      // compressed pubkey hex
	TxID         string            `json:"txid"`        // latest TxID hex
	ParentTxID   string            `json:"parent_txid"` // parent's TxID hex (empty for root)
	Type         string            `json:"type"`        // "file", "dir", "link"
	Access       string            `json:"access"`      // "free", "private", "paid"
	Path         string            `json:"path"`        // filesystem path
	VaultIndex   uint32            `json:"vault_index"`
	ChildIndices []uint32          `json:"child_indices"` // BIP32 child indices from root
	Children     []*ChildState     `json:"children"`      // directory children
	NextChildIdx uint32            `json:"next_child_idx"`
	KeyHash      string            `json:"key_hash,omitempty"` // hex, for files
	FileSize     uint64            `json:"file_size,omitempty"`
	MimeType     string            `json:"mime_type,omitempty"`
	PricePerKB   uint64            `json:"price_per_kb,omitempty"`
	LinkTarget   string            `json:"link_target,omitempty"` // target pubkey hex
	Metadata     map[string]string `json:"metadata,omitempty"`
	Keywords     string            `json:"keywords,omitempty"`
	Description  string            `json:"description,omitempty"`
	Domain       string            `json:"domain,omitempty"`
	OnChain      bool              `json:"on_chain,omitempty"`
	Compression  int32             `json:"compression,omitempty"`
}

// ChildState tracks a child entry within a directory.
type ChildState struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "file", "dir", "link"
	PubKey   string `json:"pubkey"`
	Index    uint32 `json:"index"`
	Hardened bool   `json:"hardened"`
}

// UTXOState tracks an unspent output.
type UTXOState struct {
	TxID         string `json:"txid"` // hex
	Vout         uint32 `json:"vout"`
	Amount       uint64 `json:"amount"`        // satoshis
	ScriptPubKey string `json:"script_pubkey"` // hex
	PubKeyHex    string `json:"pubkey"`        // owner pubkey hex (for key lookup)
	Type         string `json:"type"`          // "fee", "node"
	Spent        bool   `json:"spent"`
	FeeChain     uint32 `json:"fee_chain,omitempty"`     // 0=external, 1=internal (fee UTXOs only)
	FeeDerivIdx  uint32 `json:"fee_deriv_idx,omitempty"` // derivation index within chain (fee UTXOs only)
}

// PublishBinding tracks a domain-to-vault DNSLink binding.
type PublishBinding struct {
	Domain     string `json:"domain"`
	VaultIndex uint32 `json:"vault_index"`
	PubKeyHex  string `json:"pubkey"`
	Verified   bool   `json:"verified"`
}

// NewLocalState creates a new empty local state.
func NewLocalState(path string) *LocalState {
	return &LocalState{
		Nodes:           make(map[string]*NodeState),
		UTXOs:           make([]*UTXOState, 0),
		RootTxID:        make(map[uint32]string),
		PublishBindings: make([]*PublishBinding, 0),
		path:            path,
	}
}

// LoadLocalState loads local state from disk. Returns a new empty state if
// the file does not exist.
func LoadLocalState(path string) (*LocalState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewLocalState(path), nil
		}
		return nil, fmt.Errorf("vault: read local state: %w", err)
	}

	var state LocalState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("vault: parse local state: %w", err)
	}
	if state.Nodes == nil {
		state.Nodes = make(map[string]*NodeState)
	}
	if state.UTXOs == nil {
		state.UTXOs = make([]*UTXOState, 0)
	}
	if state.RootTxID == nil {
		state.RootTxID = make(map[uint32]string)
	}
	if state.PublishBindings == nil {
		state.PublishBindings = make([]*PublishBinding, 0)
	}
	state.path = path
	return &state, nil
}

// Reload re-reads the state file from disk (used after acquiring write lock).
// No-op if the state file has not been persisted yet.
func (s *LocalState) Reload() error {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return nil // not yet persisted, keep current in-memory state
	}
	fresh, err := LoadLocalState(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Nodes = fresh.Nodes
	s.UTXOs = fresh.UTXOs
	s.RootTxID = fresh.RootTxID
	s.PublishBindings = fresh.PublishBindings
	return nil
}

// Save persists the local state to disk.
// Spent UTXOs are pruned before writing to prevent unbounded growth.
func (s *LocalState) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prune spent UTXOs to prevent unbounded growth.
	live := make([]*UTXOState, 0, len(s.UTXOs))
	for _, u := range s.UTXOs {
		if !u.Spent {
			live = append(live, u)
		}
	}
	s.UTXOs = live

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: marshal local state: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("vault: create state directory: %w", err)
	}
	return os.WriteFile(s.path, data, 0600)
}

// AllocateFeeUTXO finds an unspent fee UTXO with at least minAmount satoshis.
// Returns nil if none found.
func (s *LocalState) AllocateFeeUTXO(minAmount uint64) *UTXOState {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.UTXOs {
		if u.Type == "fee" && !u.Spent && u.Amount >= minAmount {
			u.Spent = true
			return u
		}
	}
	return nil
}

// GetNodeUTXO finds the unspent node UTXO for a given pubkey.
func (s *LocalState) GetNodeUTXO(pubKeyHex string) *UTXOState {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.UTXOs {
		if u.Type == "node" && !u.Spent && u.PubKeyHex == pubKeyHex {
			return u
		}
	}
	return nil
}

// ReleaseUTXO marks a previously allocated UTXO as unspent, enabling rollback
// when a transaction build or sign fails after UTXO allocation.
func (s *LocalState) ReleaseUTXO(txid string, vout uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.UTXOs {
		if u.TxID == txid && u.Vout == vout {
			u.Spent = false
			return
		}
	}
}

// AddUTXO adds a new UTXO to tracking.
func (s *LocalState) AddUTXO(u *UTXOState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.UTXOs = append(s.UTXOs, u)
}

// FindUTXOByPubKey returns the first unspent UTXO matching the given pubkey and type.
func (s *LocalState) FindUTXOByPubKey(pubKeyHex, utxoType string) *UTXOState {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.UTXOs {
		if u.PubKeyHex == pubKeyHex && u.Type == utxoType && !u.Spent {
			return u
		}
	}
	return nil
}

// GetNode returns the node state for a given pubkey hex.
// Note: the returned pointer escapes the mutex. Callers that mutate the
// returned node must do so within withWriteLock to ensure consistency.
func (s *LocalState) GetNode(pubKeyHex string) *NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Nodes[pubKeyHex]
}

// SetNode stores a node state.
func (s *LocalState) SetNode(pubKeyHex string, node *NodeState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Nodes[pubKeyHex] = node
}

// FindNodeByPath returns the node at the given filesystem path.
// Note: the returned pointer escapes the mutex. Callers that mutate the
// returned node must do so within withWriteLock to ensure consistency.
func (s *LocalState) FindNodeByPath(path string) *NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, node := range s.Nodes {
		if node.Path == path {
			return node
		}
	}
	return nil
}

// GetPublishBinding returns the publish binding for a domain, or nil if not found.
func (s *LocalState) GetPublishBinding(domain string) *PublishBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.PublishBindings {
		if b.Domain == domain {
			return b
		}
	}
	return nil
}

// SetPublishBinding adds or updates a publish binding for a domain.
func (s *LocalState) SetPublishBinding(binding *PublishBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, b := range s.PublishBindings {
		if b.Domain == binding.Domain {
			s.PublishBindings[i] = binding
			return
		}
	}
	s.PublishBindings = append(s.PublishBindings, binding)
}

// ListPublishBindings returns a deep copy of all publish bindings.
func (s *LocalState) ListPublishBindings() []*PublishBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*PublishBinding, len(s.PublishBindings))
	for i, b := range s.PublishBindings {
		cp := *b
		out[i] = &cp
	}
	return out
}

// RemovePublishBinding removes the publish binding for a domain.
func (s *LocalState) RemovePublishBinding(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, b := range s.PublishBindings {
		if b.Domain == domain {
			s.PublishBindings = append(s.PublishBindings[:i], s.PublishBindings[i+1:]...)
			return true
		}
	}
	return false
}

// TxIDBytes converts a hex TxID string to 32 bytes.
func TxIDBytes(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("vault: invalid txid hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("vault: txid must be 32 bytes, got %d", len(b))
	}
	return b, nil
}
