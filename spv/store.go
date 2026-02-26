package spv

import (
	"bytes"
	"fmt"
	"sync"
)

// HeaderStore persists block headers for chain verification.
type HeaderStore interface {
	// PutHeader stores a block header.
	PutHeader(header *BlockHeader) error

	// GetHeader retrieves a header by block hash.
	GetHeader(blockHash []byte) (*BlockHeader, error)

	// GetHeaderByHeight retrieves a header by block height.
	GetHeaderByHeight(height uint32) (*BlockHeader, error)

	// GetTip returns the header with the greatest height.
	GetTip() (*BlockHeader, error)

	// GetHeaderCount returns the total number of stored headers.
	GetHeaderCount() (uint64, error)
}

// TxStore persists transactions with Merkle proofs.
type TxStore interface {
	// PutTx stores a transaction with optional Merkle proof.
	PutTx(tx *StoredTx) error

	// GetTx retrieves a transaction by TxID.
	GetTx(txID []byte) (*StoredTx, error)

	// GetTxsByPubKey returns all transactions related to a P_node public key.
	GetTxsByPubKey(pNode []byte) ([]*StoredTx, error)

	// DeleteTx removes a transaction from the store.
	DeleteTx(txID []byte) error

	// ListTxs returns all stored transactions (for backup/export).
	ListTxs() ([]*StoredTx, error)
}

// MemHeaderStore is an in-memory implementation of HeaderStore for testing.
type MemHeaderStore struct {
	mu        sync.RWMutex
	byHash    map[string]*BlockHeader
	byHeight  map[uint32]*BlockHeader
	tipHeight uint32
	hasTip    bool
}

// NewMemHeaderStore creates a new in-memory header store.
func NewMemHeaderStore() *MemHeaderStore {
	return &MemHeaderStore{
		byHash:   make(map[string]*BlockHeader),
		byHeight: make(map[uint32]*BlockHeader),
	}
}

func hashKey(h []byte) string {
	return string(h)
}

// PutHeader stores a block header.
func (s *MemHeaderStore) PutHeader(header *BlockHeader) error {
	if header == nil {
		return fmt.Errorf("%w: header", ErrNilParam)
	}

	// Compute hash if not set
	if len(header.Hash) == 0 {
		header.Hash = ComputeHeaderHash(header)
	}

	if len(header.Hash) != HashSize {
		return fmt.Errorf("%w: header hash must be %d bytes", ErrInvalidHeader, HashSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashKey(header.Hash)
	if _, exists := s.byHash[key]; exists {
		return ErrDuplicateHeader
	}

	s.byHash[key] = header
	s.byHeight[header.Height] = header

	if !s.hasTip || header.Height > s.tipHeight {
		s.tipHeight = header.Height
		s.hasTip = true
	}

	return nil
}

// GetHeader retrieves a header by block hash.
func (s *MemHeaderStore) GetHeader(blockHash []byte) (*BlockHeader, error) {
	if len(blockHash) != HashSize {
		return nil, fmt.Errorf("%w: block hash must be %d bytes", ErrInvalidHeader, HashSize)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	h, ok := s.byHash[hashKey(blockHash)]
	if !ok {
		return nil, ErrHeaderNotFound
	}
	return h, nil
}

// GetHeaderByHeight retrieves a header by block height.
func (s *MemHeaderStore) GetHeaderByHeight(height uint32) (*BlockHeader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h, ok := s.byHeight[height]
	if !ok {
		return nil, ErrHeaderNotFound
	}
	return h, nil
}

// GetTip returns the header with the greatest height.
func (s *MemHeaderStore) GetTip() (*BlockHeader, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.hasTip {
		return nil, ErrHeaderNotFound
	}
	return s.byHeight[s.tipHeight], nil
}

// GetHeaderCount returns the total number of stored headers.
func (s *MemHeaderStore) GetHeaderCount() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint64(len(s.byHash)), nil
}

// MemTxStore is an in-memory implementation of TxStore for testing.
type MemTxStore struct {
	mu       sync.RWMutex
	byTxID   map[string]*StoredTx
	byPubKey map[string][]*StoredTx
}

// NewMemTxStore creates a new in-memory transaction store.
func NewMemTxStore() *MemTxStore {
	return &MemTxStore{
		byTxID:   make(map[string]*StoredTx),
		byPubKey: make(map[string][]*StoredTx),
	}
}

// PutTx stores a transaction with optional Merkle proof.
func (s *MemTxStore) PutTx(tx *StoredTx) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashKey(tx.TxID)
	if _, exists := s.byTxID[key]; exists {
		return ErrDuplicateTx
	}

	s.byTxID[key] = tx
	return nil
}

// PutTxWithPubKey stores a transaction and indexes it by a P_node public key.
func (s *MemTxStore) PutTxWithPubKey(tx *StoredTx, pNode []byte) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashKey(tx.TxID)
	if _, exists := s.byTxID[key]; exists {
		return ErrDuplicateTx
	}

	s.byTxID[key] = tx

	if len(pNode) > 0 {
		pkKey := hashKey(pNode)
		s.byPubKey[pkKey] = append(s.byPubKey[pkKey], tx)
	}

	return nil
}

// GetTx retrieves a transaction by TxID.
func (s *MemTxStore) GetTx(txID []byte) (*StoredTx, error) {
	if len(txID) != HashSize {
		return nil, fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	tx, ok := s.byTxID[hashKey(txID)]
	if !ok {
		return nil, ErrTxNotFound
	}
	return tx, nil
}

// GetTxsByPubKey returns all transactions related to a P_node public key.
func (s *MemTxStore) GetTxsByPubKey(pNode []byte) ([]*StoredTx, error) {
	if len(pNode) == 0 {
		return nil, fmt.Errorf("%w: pNode", ErrNilParam)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	txs := s.byPubKey[hashKey(pNode)]
	if len(txs) == 0 {
		return nil, nil
	}

	// Return a copy to avoid mutation
	result := make([]*StoredTx, len(txs))
	copy(result, txs)
	return result, nil
}

// DeleteTx removes a transaction from the store.
func (s *MemTxStore) DeleteTx(txID []byte) error {
	if len(txID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := hashKey(txID)
	if _, ok := s.byTxID[key]; !ok {
		return ErrTxNotFound
	}

	delete(s.byTxID, key)

	// Also remove from pubkey index
	for pk, txs := range s.byPubKey {
		for i, tx := range txs {
			if bytes.Equal(tx.TxID, txID) {
				s.byPubKey[pk] = append(txs[:i], txs[i+1:]...)
				break
			}
		}
	}

	return nil
}

// ListTxs returns all stored transactions.
func (s *MemTxStore) ListTxs() ([]*StoredTx, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*StoredTx, 0, len(s.byTxID))
	for _, tx := range s.byTxID {
		result = append(result, tx)
	}
	return result, nil
}
