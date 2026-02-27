package spv

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

var (
	bucketHeaders       = []byte("headers")
	bucketHeadersHeight = []byte("headers_height")
	bucketTxs           = []byte("txs")
	bucketTxPubkeys     = []byte("tx_pubkeys")
)

// BoltStore wraps a bbolt database for SPV header and transaction storage.
type BoltStore struct {
	db *bbolt.DB
}

// OpenBoltStore opens or creates the bbolt database at dbPath.
// The parent directory is created if it does not exist.
func OpenBoltStore(dbPath string) (*BoltStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("spv: create directory: %w", err)
	}
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("spv: open bolt db: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		for _, name := range [][]byte{bucketHeaders, bucketHeadersHeight, bucketTxs, bucketTxPubkeys} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("boltstore: create bucket %q: %w", name, err)
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("spv: create buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the underlying database.
func (s *BoltStore) Close() error { return s.db.Close() }

// Headers returns a HeaderStore backed by this database.
func (s *BoltStore) Headers() *BoltHeaderStore { return &BoltHeaderStore{db: s.db} }

// Txs returns a TxStore backed by this database.
func (s *BoltStore) Txs() *BoltTxStore { return &BoltTxStore{db: s.db} }

// heightKey encodes a block height as a 4-byte big-endian key for sorted storage.
func heightKey(h uint32) []byte {
	k := make([]byte, 4)
	binary.BigEndian.PutUint32(k, h)
	return k
}

// encodeGob serializes a value using gob encoding.
func encodeGob(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeGob deserializes gob-encoded data into a value.
func decodeGob(data []byte, v interface{}) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(v)
}

// ---------------------------------------------------------------------------
// BoltHeaderStore implements HeaderStore.
// ---------------------------------------------------------------------------

// BoltHeaderStore persists block headers in bbolt.
type BoltHeaderStore struct {
	db *bbolt.DB
}

// Compile-time interface check.
var _ HeaderStore = (*BoltHeaderStore)(nil)

// PutHeader stores a block header keyed by block hash and height.
func (s *BoltHeaderStore) PutHeader(header *BlockHeader) error {
	if header == nil {
		return fmt.Errorf("%w: header", ErrNilParam)
	}
	if len(header.Hash) == 0 {
		header.Hash = ComputeHeaderHash(header)
	}
	if len(header.Hash) != HashSize {
		return fmt.Errorf("%w: header hash must be %d bytes", ErrInvalidHeader, HashSize)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		hb := tx.Bucket(bucketHeaders)
		if hb.Get(header.Hash) != nil {
			return ErrDuplicateHeader
		}

		data, err := encodeGob(header)
		if err != nil {
			return fmt.Errorf("encode header: %w", err)
		}

		if err := hb.Put(header.Hash, data); err != nil {
			return fmt.Errorf("boltstore: put header by hash: %w", err)
		}
		if err := tx.Bucket(bucketHeadersHeight).Put(heightKey(header.Height), header.Hash); err != nil {
			return fmt.Errorf("boltstore: put header by height: %w", err)
		}
		return nil
	})
}

// GetHeader retrieves a header by block hash.
func (s *BoltHeaderStore) GetHeader(blockHash []byte) (*BlockHeader, error) {
	if len(blockHash) != HashSize {
		return nil, fmt.Errorf("%w: block hash must be %d bytes", ErrInvalidHeader, HashSize)
	}

	var header BlockHeader
	err := s.db.View(func(tx *bbolt.Tx) error {
		data := tx.Bucket(bucketHeaders).Get(blockHash)
		if data == nil {
			return ErrHeaderNotFound
		}
		if err := decodeGob(data, &header); err != nil {
			return fmt.Errorf("boltstore: decode header: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &header, nil
}

// GetHeaderByHeight retrieves a header by block height.
func (s *BoltHeaderStore) GetHeaderByHeight(height uint32) (*BlockHeader, error) {
	var header BlockHeader
	err := s.db.View(func(tx *bbolt.Tx) error {
		hash := tx.Bucket(bucketHeadersHeight).Get(heightKey(height))
		if hash == nil {
			return ErrHeaderNotFound
		}
		data := tx.Bucket(bucketHeaders).Get(hash)
		if data == nil {
			return ErrHeaderNotFound
		}
		if err := decodeGob(data, &header); err != nil {
			return fmt.Errorf("boltstore: decode header by height: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &header, nil
}

// GetTip returns the header with the greatest height.
func (s *BoltHeaderStore) GetTip() (*BlockHeader, error) {
	var header BlockHeader
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketHeadersHeight).Cursor()
		k, v := c.Last()
		if k == nil {
			return ErrHeaderNotFound
		}
		data := tx.Bucket(bucketHeaders).Get(v)
		if data == nil {
			return ErrHeaderNotFound
		}
		if err := decodeGob(data, &header); err != nil {
			return fmt.Errorf("boltstore: decode tip header: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &header, nil
}

// GetHeaderCount returns the total number of stored headers.
func (s *BoltHeaderStore) GetHeaderCount() (uint64, error) {
	var count uint64
	err := s.db.View(func(tx *bbolt.Tx) error {
		count = uint64(tx.Bucket(bucketHeaders).Stats().KeyN)
		return nil
	})
	return count, err
}

// ---------------------------------------------------------------------------
// BoltTxStore implements TxStore.
// ---------------------------------------------------------------------------

// BoltTxStore persists transactions in bbolt.
type BoltTxStore struct {
	db *bbolt.DB
}

// Compile-time interface check.
var _ TxStore = (*BoltTxStore)(nil)

// PutTx stores a transaction. Returns ErrDuplicateTx if the txid already exists.
func (s *BoltTxStore) PutTx(tx *StoredTx) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	return s.db.Update(func(btx *bbolt.Tx) error {
		b := btx.Bucket(bucketTxs)
		if b.Get(tx.TxID) != nil {
			return ErrDuplicateTx
		}
		data, err := encodeGob(tx)
		if err != nil {
			return fmt.Errorf("encode tx: %w", err)
		}
		if err := b.Put(tx.TxID, data); err != nil {
			return fmt.Errorf("boltstore: put tx: %w", err)
		}
		return nil
	})
}

// PutTxWithPubKey stores a transaction and indexes it by a P_node public key.
func (s *BoltTxStore) PutTxWithPubKey(tx *StoredTx, pNode []byte) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	return s.db.Update(func(btx *bbolt.Tx) error {
		b := btx.Bucket(bucketTxs)
		if b.Get(tx.TxID) != nil {
			return ErrDuplicateTx
		}
		data, err := encodeGob(tx)
		if err != nil {
			return fmt.Errorf("encode tx: %w", err)
		}
		if err := b.Put(tx.TxID, data); err != nil {
			return fmt.Errorf("boltstore: put tx: %w", err)
		}
		if len(pNode) > 0 {
			// Composite key: pNode + txID for prefix scanning.
			compositeKey := make([]byte, len(pNode)+HashSize)
			copy(compositeKey, pNode)
			copy(compositeKey[len(pNode):], tx.TxID)
			if err := btx.Bucket(bucketTxPubkeys).Put(compositeKey, []byte{}); err != nil {
				return fmt.Errorf("boltstore: put tx pubkey index: %w", err)
			}
		}
		return nil
	})
}

// UpdateTx overwrites an existing transaction entry (for proof backfill).
func (s *BoltTxStore) UpdateTx(tx *StoredTx) error {
	if tx == nil {
		return fmt.Errorf("%w: stored transaction", ErrNilParam)
	}
	if len(tx.TxID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	return s.db.Update(func(btx *bbolt.Tx) error {
		b := btx.Bucket(bucketTxs)
		if b.Get(tx.TxID) == nil {
			return ErrTxNotFound
		}
		data, err := encodeGob(tx)
		if err != nil {
			return fmt.Errorf("encode tx: %w", err)
		}
		if err := b.Put(tx.TxID, data); err != nil {
			return fmt.Errorf("boltstore: update tx: %w", err)
		}
		return nil
	})
}

// GetTx retrieves a transaction by TxID.
func (s *BoltTxStore) GetTx(txID []byte) (*StoredTx, error) {
	if len(txID) != HashSize {
		return nil, fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	var tx StoredTx
	err := s.db.View(func(btx *bbolt.Tx) error {
		data := btx.Bucket(bucketTxs).Get(txID)
		if data == nil {
			return ErrTxNotFound
		}
		if err := decodeGob(data, &tx); err != nil {
			return fmt.Errorf("boltstore: decode tx: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

// GetTxsByPubKey returns all transactions associated with a P_node public key.
func (s *BoltTxStore) GetTxsByPubKey(pNode []byte) ([]*StoredTx, error) {
	if len(pNode) == 0 {
		return nil, fmt.Errorf("%w: pNode", ErrNilParam)
	}

	var txs []*StoredTx
	err := s.db.View(func(btx *bbolt.Tx) error {
		pkBucket := btx.Bucket(bucketTxPubkeys)
		txBucket := btx.Bucket(bucketTxs)

		c := pkBucket.Cursor()
		for k, _ := c.Seek(pNode); k != nil && bytes.HasPrefix(k, pNode); k, _ = c.Next() {
			txID := k[len(pNode):]
			data := txBucket.Get(txID)
			if data == nil {
				continue // stale index entry
			}
			var tx StoredTx
			if err := decodeGob(data, &tx); err != nil {
				return fmt.Errorf("boltstore: decode tx by pubkey: %w", err)
			}
			txs = append(txs, &tx)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("boltstore: get txs by pubkey: %w", err)
	}
	return txs, nil
}

// DeleteTx removes a transaction and its pubkey index entries.
func (s *BoltTxStore) DeleteTx(txID []byte) error {
	if len(txID) != HashSize {
		return fmt.Errorf("%w: TxID must be %d bytes", ErrInvalidTxID, HashSize)
	}

	return s.db.Update(func(btx *bbolt.Tx) error {
		txBucket := btx.Bucket(bucketTxs)
		if txBucket.Get(txID) == nil {
			return ErrTxNotFound
		}
		if err := txBucket.Delete(txID); err != nil {
			return fmt.Errorf("boltstore: delete tx: %w", err)
		}

		// Clean up pubkey index entries that reference this txID.
		pkBucket := btx.Bucket(bucketTxPubkeys)
		c := pkBucket.Cursor()
		var toDelete [][]byte
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) >= HashSize && bytes.Equal(k[len(k)-HashSize:], txID) {
				keyCopy := make([]byte, len(k))
				copy(keyCopy, k)
				toDelete = append(toDelete, keyCopy)
			}
		}
		for _, k := range toDelete {
			if err := pkBucket.Delete(k); err != nil {
				return fmt.Errorf("boltstore: delete pubkey index entry: %w", err)
			}
		}
		return nil
	})
}

// ListTxs returns all stored transactions.
func (s *BoltTxStore) ListTxs() ([]*StoredTx, error) {
	var txs []*StoredTx
	err := s.db.View(func(btx *bbolt.Tx) error {
		return btx.Bucket(bucketTxs).ForEach(func(k, v []byte) error {
			var tx StoredTx
			if err := decodeGob(v, &tx); err != nil {
				return fmt.Errorf("boltstore: decode tx in list: %w", err)
			}
			txs = append(txs, &tx)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("boltstore: list txs: %w", err)
	}
	return txs, nil
}
