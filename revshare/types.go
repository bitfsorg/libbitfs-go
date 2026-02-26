package revshare

// RevShareEntry represents a shareholder's record in the registry.
type RevShareEntry struct {
	Address [20]byte // P2PKH address hash
	Share   uint64   // Number of shares held
}

// RegistryState represents the current state of a revenue share registry.
type RegistryState struct {
	NodeID      [32]byte        // SHA256(P_node || TxID) of the Metanet node
	TotalShares uint64          // Total shares issued
	Entries     []RevShareEntry // Current shareholders
	ModeFlags   uint8           // bit 0: ISO active, bit 1: locked
}

// IsISOActive returns true if the ISO pool is active.
func (s *RegistryState) IsISOActive() bool {
	return s.ModeFlags&0x01 != 0
}

// IsLocked returns true if share transfers are locked.
func (s *RegistryState) IsLocked() bool {
	return s.ModeFlags&0x02 != 0
}

// FindEntry returns the index and entry for the given address, or -1 if not found.
func (s *RegistryState) FindEntry(addr [20]byte) (int, *RevShareEntry) {
	for i := range s.Entries {
		if s.Entries[i].Address == addr {
			return i, &s.Entries[i]
		}
	}
	return -1, nil
}

// ShareData represents the data embedded in a Share UTXO.
type ShareData struct {
	NodeID [32]byte // Bound Metanet node
	Amount uint64   // Number of shares
}

// ISOPoolState represents the state of an ISO pool UTXO.
type ISOPoolState struct {
	NodeID          [32]byte // Bound Metanet node
	RemainingShares uint64   // Unsold shares
	PricePerShare   uint64   // Price in satoshis
	CreatorAddr     [20]byte // Creator's P2PKH address
}

// Distribution represents a single payout in revenue distribution.
type Distribution struct {
	Address [20]byte
	Amount  uint64
}
