package revshare

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeAddr(seed byte) [20]byte {
	var addr [20]byte
	for i := range addr {
		addr[i] = seed
	}
	return addr
}

func makeNodeID(seed byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = seed
	}
	return id
}

// --- Registry tests ---

func TestSerializeRegistry_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		state *RegistryState
	}{
		{"single entry", &RegistryState{
			NodeID: makeNodeID(0x01), TotalShares: 10000,
			Entries:   []RevShareEntry{{Address: makeAddr(0xAA), Share: 10000}},
			ModeFlags: 0,
		}},
		{"multiple entries", &RegistryState{
			NodeID: makeNodeID(0x02), TotalShares: 10000,
			Entries: []RevShareEntry{
				{Address: makeAddr(0xAA), Share: 3000},
				{Address: makeAddr(0xBB), Share: 2000},
				{Address: makeAddr(0xCC), Share: 5000},
			},
			ModeFlags: 0x01, // ISO active
		}},
		{"locked", &RegistryState{
			NodeID: makeNodeID(0x03), TotalShares: 100,
			Entries:   []RevShareEntry{{Address: makeAddr(0x01), Share: 100}},
			ModeFlags: 0x03, // ISO active + locked
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := SerializeRegistry(tt.state)
			require.NoError(t, err)

			decoded, err := DeserializeRegistry(data)
			require.NoError(t, err)

			assert.Equal(t, tt.state.NodeID, decoded.NodeID)
			assert.Equal(t, tt.state.TotalShares, decoded.TotalShares)
			assert.Equal(t, tt.state.ModeFlags, decoded.ModeFlags)
			require.Len(t, decoded.Entries, len(tt.state.Entries))
			for i := range tt.state.Entries {
				assert.Equal(t, tt.state.Entries[i].Address, decoded.Entries[i].Address)
				assert.Equal(t, tt.state.Entries[i].Share, decoded.Entries[i].Share)
			}
		})
	}
}

func TestSerializeRegistry_Size(t *testing.T) {
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 10000,
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 5000},
			{Address: makeAddr(0xBB), Share: 5000},
		},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)
	// Expected: 32 + 8 + 4 + 28*2 + 1 = 101
	assert.Len(t, data, 101)
}

func TestDeserializeRegistry_TooShort(t *testing.T) {
	_, err := DeserializeRegistry([]byte{0x01, 0x02})
	assert.ErrorIs(t, err, ErrInvalidRegistryData)
}

func TestSerializeRegistry_ZeroEntries(t *testing.T) {
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 0,
		Entries: []RevShareEntry{}, ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)
	assert.Len(t, data, 45) // header(44) + trailer(1)

	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Empty(t, decoded.Entries)
}

func TestSerializeRegistry_MaxEntries(t *testing.T) {
	entries := make([]RevShareEntry, 100)
	for i := range entries {
		entries[i] = RevShareEntry{Address: makeAddr(byte(i)), Share: 100}
	}
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 10000,
		Entries: entries, ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)
	assert.Len(t, data, 44+28*100+1)

	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Len(t, decoded.Entries, 100)
}

func TestDeserializeRegistry_TruncatedEntries(t *testing.T) {
	// Header claims 2 entries but only 1 is present
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 10000,
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 5000},
			{Address: makeAddr(0xBB), Share: 5000},
		},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)
	// Truncate: remove last entry (28 bytes) + trailer (1 byte)
	_, err = DeserializeRegistry(data[:len(data)-29])
	assert.ErrorIs(t, err, ErrInvalidRegistryData)
}

func TestDeserializeRegistry_ExactMinimum(t *testing.T) {
	// Exactly 45 bytes: header(44) + trailer(1), 0 entries
	data := make([]byte, 45)
	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Empty(t, decoded.Entries)
	assert.Equal(t, uint64(0), decoded.TotalShares)
}

func TestSerializeRegistry_AllModeFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		iso   bool
		lock  bool
	}{
		{"none", 0x00, false, false},
		{"iso only", 0x01, true, false},
		{"locked only", 0x02, false, true},
		{"iso+locked", 0x03, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &RegistryState{
				NodeID: makeNodeID(0x01), TotalShares: 100,
				Entries:   []RevShareEntry{{Address: makeAddr(0xAA), Share: 100}},
				ModeFlags: tt.flags,
			}
			data, err := SerializeRegistry(state)
			require.NoError(t, err)

			decoded, err := DeserializeRegistry(data)
			require.NoError(t, err)
			assert.Equal(t, tt.iso, decoded.IsISOActive())
			assert.Equal(t, tt.lock, decoded.IsLocked())
		})
	}
}

func TestSerializeRegistry_NodeIDPreserved(t *testing.T) {
	// Verify each byte of NodeID is preserved through round-trip
	var nodeID [32]byte
	for i := range nodeID {
		nodeID[i] = byte(i)
	}
	state := &RegistryState{
		NodeID: nodeID, TotalShares: 1,
		Entries:   []RevShareEntry{{Address: makeAddr(0x01), Share: 1}},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)

	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Equal(t, nodeID, decoded.NodeID)
}

func TestSerializeRegistry_LargeShares(t *testing.T) {
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: ^uint64(0),
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: ^uint64(0) / 2},
			{Address: makeAddr(0xBB), Share: ^uint64(0) - ^uint64(0)/2},
		},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)

	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), decoded.TotalShares)
	assert.Equal(t, ^uint64(0)/2, decoded.Entries[0].Share)
}

func TestDeserializeRegistry_ExtraTrailingBytes(t *testing.T) {
	// Valid data with extra trailing bytes — should still deserialize ok
	// (the deserializer reads exactly what it needs)
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 100,
		Entries:   []RevShareEntry{{Address: makeAddr(0xAA), Share: 100}},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)

	// Append extra bytes
	data = append(data, 0xFF, 0xFF, 0xFF)
	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	assert.Len(t, decoded.Entries, 1)
}

func TestDeserializeRegistry_OneByteTooShort(t *testing.T) {
	// 44 bytes — missing trailer
	data := make([]byte, 44)
	_, err := DeserializeRegistry(data)
	assert.ErrorIs(t, err, ErrInvalidRegistryData)
}

func TestSerializeRegistry_EntryAddressesDistinct(t *testing.T) {
	// Verify that different entry addresses don't get mixed up
	state := &RegistryState{
		NodeID: makeNodeID(0x01), TotalShares: 300,
		Entries: []RevShareEntry{
			{Address: makeAddr(0x01), Share: 100},
			{Address: makeAddr(0x02), Share: 100},
			{Address: makeAddr(0x03), Share: 100},
		},
		ModeFlags: 0,
	}
	data, err := SerializeRegistry(state)
	require.NoError(t, err)

	decoded, err := DeserializeRegistry(data)
	require.NoError(t, err)
	for i, entry := range decoded.Entries {
		assert.Equal(t, makeAddr(byte(i+1)), entry.Address, "entry %d address mismatch", i)
	}
}

// --- Share tests ---

func TestSerializeShare_RoundTrip(t *testing.T) {
	share := &ShareData{NodeID: makeNodeID(0x01), Amount: 5000}
	data := SerializeShare(share)
	assert.Len(t, data, 40)

	decoded, err := DeserializeShare(data)
	require.NoError(t, err)
	assert.Equal(t, share.NodeID, decoded.NodeID)
	assert.Equal(t, share.Amount, decoded.Amount)
}

func TestDeserializeShare_WrongSize(t *testing.T) {
	_, err := DeserializeShare([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidShareData)
}

func TestSerializeShare_ZeroAmount(t *testing.T) {
	share := &ShareData{NodeID: makeNodeID(0x01), Amount: 0}
	data := SerializeShare(share)
	decoded, err := DeserializeShare(data)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), decoded.Amount)
}

func TestSerializeShare_MaxAmount(t *testing.T) {
	share := &ShareData{NodeID: makeNodeID(0xFF), Amount: ^uint64(0)}
	data := SerializeShare(share)
	decoded, err := DeserializeShare(data)
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), decoded.Amount)
}

func TestDeserializeShare_TooLong(t *testing.T) {
	// 41 bytes — should fail (expects exactly 40)
	_, err := DeserializeShare(make([]byte, 41))
	assert.ErrorIs(t, err, ErrInvalidShareData)
}

func TestDeserializeShare_TooShort(t *testing.T) {
	_, err := DeserializeShare(make([]byte, 39))
	assert.ErrorIs(t, err, ErrInvalidShareData)
}

func TestDeserializeShare_Empty(t *testing.T) {
	_, err := DeserializeShare(nil)
	assert.ErrorIs(t, err, ErrInvalidShareData)
}

func TestSerializeShare_NodeIDPreserved(t *testing.T) {
	var nodeID [32]byte
	for i := range nodeID {
		nodeID[i] = byte(i * 7)
	}
	share := &ShareData{NodeID: nodeID, Amount: 42}
	data := SerializeShare(share)
	decoded, err := DeserializeShare(data)
	require.NoError(t, err)
	assert.Equal(t, nodeID, decoded.NodeID)
	assert.Equal(t, uint64(42), decoded.Amount)
}

func TestSerializeShare_DifferentNodeIDsDifferentData(t *testing.T) {
	share1 := &ShareData{NodeID: makeNodeID(0x01), Amount: 100}
	share2 := &ShareData{NodeID: makeNodeID(0x02), Amount: 100}
	data1 := SerializeShare(share1)
	data2 := SerializeShare(share2)
	assert.NotEqual(t, data1, data2)
}

// --- ISO Pool tests ---

func TestSerializeISOPool_RoundTrip(t *testing.T) {
	pool := &ISOPoolState{
		NodeID: makeNodeID(0x01), RemainingShares: 6000,
		PricePerShare: 100, CreatorAddr: makeAddr(0xAA),
	}
	data := SerializeISOPool(pool)
	assert.Len(t, data, 68)

	decoded, err := DeserializeISOPool(data)
	require.NoError(t, err)
	assert.Equal(t, pool.NodeID, decoded.NodeID)
	assert.Equal(t, pool.RemainingShares, decoded.RemainingShares)
	assert.Equal(t, pool.PricePerShare, decoded.PricePerShare)
	assert.Equal(t, pool.CreatorAddr, decoded.CreatorAddr)
}

func TestDeserializeISOPool_WrongSize(t *testing.T) {
	_, err := DeserializeISOPool([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidISOPoolData)
}

func TestSerializeISOPool_ZeroValues(t *testing.T) {
	pool := &ISOPoolState{}
	data := SerializeISOPool(pool)
	assert.Len(t, data, 68)

	decoded, err := DeserializeISOPool(data)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), decoded.RemainingShares)
	assert.Equal(t, uint64(0), decoded.PricePerShare)
}

func TestSerializeISOPool_MaxValues(t *testing.T) {
	pool := &ISOPoolState{
		NodeID:          makeNodeID(0xFF),
		RemainingShares: ^uint64(0),
		PricePerShare:   ^uint64(0),
		CreatorAddr:     makeAddr(0xFF),
	}
	data := SerializeISOPool(pool)
	decoded, err := DeserializeISOPool(data)
	require.NoError(t, err)
	assert.Equal(t, ^uint64(0), decoded.RemainingShares)
	assert.Equal(t, ^uint64(0), decoded.PricePerShare)
}

func TestDeserializeISOPool_TooShort(t *testing.T) {
	_, err := DeserializeISOPool(make([]byte, 67))
	assert.ErrorIs(t, err, ErrInvalidISOPoolData)
}

func TestDeserializeISOPool_TooLong(t *testing.T) {
	_, err := DeserializeISOPool(make([]byte, 69))
	assert.ErrorIs(t, err, ErrInvalidISOPoolData)
}

func TestDeserializeISOPool_Empty(t *testing.T) {
	_, err := DeserializeISOPool(nil)
	assert.ErrorIs(t, err, ErrInvalidISOPoolData)
}

func TestSerializeISOPool_CreatorAddrPreserved(t *testing.T) {
	var addr [20]byte
	for i := range addr {
		addr[i] = byte(i * 13)
	}
	pool := &ISOPoolState{
		NodeID:          makeNodeID(0x01),
		RemainingShares: 5000,
		PricePerShare:   200,
		CreatorAddr:     addr,
	}
	data := SerializeISOPool(pool)
	decoded, err := DeserializeISOPool(data)
	require.NoError(t, err)
	assert.Equal(t, addr, decoded.CreatorAddr)
}

func TestSerializeISOPool_NodeIDPreserved(t *testing.T) {
	var nodeID [32]byte
	for i := range nodeID {
		nodeID[i] = byte(i)
	}
	pool := &ISOPoolState{
		NodeID:          nodeID,
		RemainingShares: 1,
		PricePerShare:   1,
		CreatorAddr:     makeAddr(0x01),
	}
	data := SerializeISOPool(pool)
	decoded, err := DeserializeISOPool(data)
	require.NoError(t, err)
	assert.Equal(t, nodeID, decoded.NodeID)
}

// --- Distribution tests ---

func TestDistributeRevenue(t *testing.T) {
	tests := []struct {
		name         string
		totalPayment uint64
		entries      []RevShareEntry
		totalShares  uint64
		wantAmounts  []uint64
	}{
		{
			"exact division",
			10000,
			[]RevShareEntry{
				{Address: makeAddr(0xAA), Share: 3000},
				{Address: makeAddr(0xBB), Share: 2000},
				{Address: makeAddr(0xCC), Share: 5000},
			},
			10000,
			[]uint64{3000, 2000, 5000},
		},
		{
			"remainder goes to last",
			10,
			[]RevShareEntry{
				{Address: makeAddr(0xAA), Share: 3333},
				{Address: makeAddr(0xBB), Share: 3333},
				{Address: makeAddr(0xCC), Share: 3334},
			},
			10000,
			[]uint64{3, 3, 4}, // 3+3+4=10, last gets remainder
		},
		{
			"single shareholder",
			5000,
			[]RevShareEntry{
				{Address: makeAddr(0xAA), Share: 10000},
			},
			10000,
			[]uint64{5000},
		},
		{
			"two shareholders equal",
			100,
			[]RevShareEntry{
				{Address: makeAddr(0xAA), Share: 5000},
				{Address: makeAddr(0xBB), Share: 5000},
			},
			10000,
			[]uint64{50, 50},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dists, err := DistributeRevenue(tt.totalPayment, tt.entries, tt.totalShares)
			require.NoError(t, err)
			require.Len(t, dists, len(tt.entries))

			var total uint64
			for i, d := range dists {
				assert.Equal(t, tt.entries[i].Address, d.Address)
				assert.Equal(t, tt.wantAmounts[i], d.Amount, "entry %d", i)
				total += d.Amount
			}
			assert.Equal(t, tt.totalPayment, total, "total payout must equal totalPayment")
		})
	}
}

func TestDistributeRevenue_Errors(t *testing.T) {
	entries := []RevShareEntry{{Address: makeAddr(0xAA), Share: 5000}}

	_, err := DistributeRevenue(0, entries, 10000)
	assert.ErrorIs(t, err, ErrInsufficientPayment)

	_, err = DistributeRevenue(100, nil, 10000)
	assert.ErrorIs(t, err, ErrNoEntries)

	_, err = DistributeRevenue(100, entries, 0)
	assert.ErrorIs(t, err, ErrZeroTotalShares)
}

func TestDistributeRevenue_LargePayment(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 5000},
		{Address: makeAddr(0xBB), Share: 5000},
	}
	// Max uint64 / 2 to avoid overflow in the multiplication
	dists, err := DistributeRevenue(1_000_000_000, entries, 10000)
	require.NoError(t, err)
	assert.Equal(t, uint64(500_000_000), dists[0].Amount)
	assert.Equal(t, uint64(500_000_000), dists[1].Amount)
}

func TestDistributeRevenue_SingleSatoshi(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 3333},
		{Address: makeAddr(0xBB), Share: 3333},
		{Address: makeAddr(0xCC), Share: 3334},
	}
	// 1 satoshi cannot be split — all goes to last entry
	dists, err := DistributeRevenue(1, entries, 10000)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), dists[0].Amount)
	assert.Equal(t, uint64(0), dists[1].Amount)
	assert.Equal(t, uint64(1), dists[2].Amount)
}

func TestDistributeRevenue_UnevenSplit(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 1},
		{Address: makeAddr(0xBB), Share: 1},
		{Address: makeAddr(0xCC), Share: 1},
	}
	// 100 / 3 = 33 remainder 1 → last gets 34
	dists, err := DistributeRevenue(100, entries, 3)
	require.NoError(t, err)
	assert.Equal(t, uint64(33), dists[0].Amount)
	assert.Equal(t, uint64(33), dists[1].Amount)
	assert.Equal(t, uint64(34), dists[2].Amount)
}

func TestDistributeRevenue_TinyShareVsLarge(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 1},    // 0.01%
		{Address: makeAddr(0xBB), Share: 9999}, // 99.99%
	}
	dists, err := DistributeRevenue(10000, entries, 10000)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), dists[0].Amount)
	assert.Equal(t, uint64(9999), dists[1].Amount)
}

func TestDistributeRevenue_ManyEntries(t *testing.T) {
	const n = 1000
	entries := make([]RevShareEntry, n)
	for i := range entries {
		entries[i] = RevShareEntry{Address: makeAddr(byte(i % 256)), Share: 10}
	}
	dists, err := DistributeRevenue(10000, entries, uint64(n*10))
	require.NoError(t, err)
	require.Len(t, dists, n)

	var total uint64
	for _, d := range dists {
		total += d.Amount
	}
	assert.Equal(t, uint64(10000), total)
}

func TestDistributeRevenue_EmptyEntries(t *testing.T) {
	_, err := DistributeRevenue(100, []RevShareEntry{}, 10000)
	assert.ErrorIs(t, err, ErrNoEntries)
}

func TestDistributeRevenue_AddressesPreserved(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0x11), Share: 5000},
		{Address: makeAddr(0x22), Share: 5000},
	}
	dists, err := DistributeRevenue(100, entries, 10000)
	require.NoError(t, err)
	assert.Equal(t, makeAddr(0x11), dists[0].Address)
	assert.Equal(t, makeAddr(0x22), dists[1].Address)
}

func TestDistributeRevenue_TotalAlwaysConserved(t *testing.T) {
	// Test many different payment amounts to verify conservation
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 3333},
		{Address: makeAddr(0xBB), Share: 3333},
		{Address: makeAddr(0xCC), Share: 3334},
	}
	for payment := uint64(1); payment <= 100; payment++ {
		dists, err := DistributeRevenue(payment, entries, 10000)
		require.NoError(t, err)
		var total uint64
		for _, d := range dists {
			total += d.Amount
		}
		assert.Equal(t, payment, total, "conservation violated for payment=%d", payment)
	}
}

func TestDistributeRevenue_AllSharesEqualWithOddPayment(t *testing.T) {
	// 5 entries with equal shares, payment = 7, cannot divide evenly
	entries := make([]RevShareEntry, 5)
	for i := range entries {
		entries[i] = RevShareEntry{Address: makeAddr(byte(i)), Share: 2000}
	}
	dists, err := DistributeRevenue(7, entries, 10000)
	require.NoError(t, err)
	var total uint64
	for _, d := range dists {
		total += d.Amount
	}
	assert.Equal(t, uint64(7), total)
}

func TestDistributeRevenue_LastEntryGetsAllRemainder(t *testing.T) {
	// When shares are tiny and payment is small, first entries get 0
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 1},
		{Address: makeAddr(0xBB), Share: 1},
		{Address: makeAddr(0xCC), Share: 1},
		{Address: makeAddr(0xDD), Share: 1},
		{Address: makeAddr(0xEE), Share: 1},
	}
	// Payment=2, totalShares=5: each gets 2*1/5=0 except last gets 2-0=2
	dists, err := DistributeRevenue(2, entries, 5)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		assert.Equal(t, uint64(0), dists[i].Amount, "entry %d should be 0", i)
	}
	assert.Equal(t, uint64(2), dists[4].Amount)
}

// --- Validation tests ---

func TestValidateShareConservation(t *testing.T) {
	nodeID := makeNodeID(0x01)

	// Valid transfer (1:1)
	inputs := []ShareData{{NodeID: nodeID, Amount: 3000}}
	outputs := []ShareData{{NodeID: nodeID, Amount: 3000}}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))

	// Valid split (1:2)
	outputs = []ShareData{
		{NodeID: nodeID, Amount: 2000},
		{NodeID: nodeID, Amount: 1000},
	}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))

	// Valid merge (2:1)
	inputs = []ShareData{
		{NodeID: nodeID, Amount: 2000},
		{NodeID: nodeID, Amount: 1000},
	}
	outputs = []ShareData{{NodeID: nodeID, Amount: 3000}}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))

	// Invalid: shares created
	inputs = []ShareData{{NodeID: nodeID, Amount: 1000}}
	outputs = []ShareData{{NodeID: nodeID, Amount: 2000}}
	assert.ErrorIs(t, ValidateShareConservation(inputs, outputs), ErrShareConservationViolation)

	// Invalid: shares destroyed
	inputs = []ShareData{{NodeID: nodeID, Amount: 2000}}
	outputs = []ShareData{{NodeID: nodeID, Amount: 1000}}
	assert.ErrorIs(t, ValidateShareConservation(inputs, outputs), ErrShareConservationViolation)
}

func TestValidateDistribution(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 3000},
		{Address: makeAddr(0xBB), Share: 7000},
	}

	// Valid distribution
	dists := []Distribution{
		{Address: makeAddr(0xAA), Amount: 3000},
		{Address: makeAddr(0xBB), Amount: 7000},
	}
	assert.NoError(t, ValidateDistribution(dists, entries, 10000, 10000))

	// Wrong amount
	dists[0].Amount = 5000
	assert.Error(t, ValidateDistribution(dists, entries, 10000, 10000))
}

func TestRegistryState_FindEntry(t *testing.T) {
	state := &RegistryState{
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 3000},
			{Address: makeAddr(0xBB), Share: 7000},
		},
	}

	idx, entry := state.FindEntry(makeAddr(0xBB))
	assert.Equal(t, 1, idx)
	assert.Equal(t, uint64(7000), entry.Share)

	idx, entry = state.FindEntry(makeAddr(0xCC))
	assert.Equal(t, -1, idx)
	assert.Nil(t, entry)
}

func TestValidateShareConservation_Empty(t *testing.T) {
	// Both empty — valid (0 == 0)
	assert.NoError(t, ValidateShareConservation(nil, nil))
}

func TestValidateShareConservation_ManyToMany(t *testing.T) {
	nodeID := makeNodeID(0x01)
	inputs := []ShareData{
		{NodeID: nodeID, Amount: 1000},
		{NodeID: nodeID, Amount: 2000},
		{NodeID: nodeID, Amount: 3000},
	}
	outputs := []ShareData{
		{NodeID: nodeID, Amount: 2500},
		{NodeID: nodeID, Amount: 3500},
	}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))
}

func TestValidateShareConservation_OneInputNilOutputs(t *testing.T) {
	nodeID := makeNodeID(0x01)
	inputs := []ShareData{{NodeID: nodeID, Amount: 1000}}
	assert.ErrorIs(t, ValidateShareConservation(inputs, nil), ErrShareConservationViolation)
}

func TestValidateShareConservation_NilInputsOneOutput(t *testing.T) {
	nodeID := makeNodeID(0x01)
	outputs := []ShareData{{NodeID: nodeID, Amount: 1000}}
	assert.ErrorIs(t, ValidateShareConservation(nil, outputs), ErrShareConservationViolation)
}

func TestValidateShareConservation_LargeAmounts(t *testing.T) {
	nodeID := makeNodeID(0x01)
	half := ^uint64(0) / 2
	inputs := []ShareData{
		{NodeID: nodeID, Amount: half},
		{NodeID: nodeID, Amount: half},
	}
	outputs := []ShareData{
		{NodeID: nodeID, Amount: half},
		{NodeID: nodeID, Amount: half},
	}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))
}

func TestValidateShareConservation_SingleUnit(t *testing.T) {
	nodeID := makeNodeID(0x01)
	inputs := []ShareData{{NodeID: nodeID, Amount: 1}}
	outputs := []ShareData{{NodeID: nodeID, Amount: 1}}
	assert.NoError(t, ValidateShareConservation(inputs, outputs))
}

func TestValidateShareConservation_OffByOne(t *testing.T) {
	nodeID := makeNodeID(0x01)
	inputs := []ShareData{{NodeID: nodeID, Amount: 1000}}
	outputs := []ShareData{{NodeID: nodeID, Amount: 1001}}
	assert.ErrorIs(t, ValidateShareConservation(inputs, outputs), ErrShareConservationViolation)

	outputs = []ShareData{{NodeID: nodeID, Amount: 999}}
	assert.ErrorIs(t, ValidateShareConservation(inputs, outputs), ErrShareConservationViolation)
}

func TestValidateDistribution_LengthMismatch(t *testing.T) {
	entries := []RevShareEntry{{Address: makeAddr(0xAA), Share: 10000}}
	dists := []Distribution{
		{Address: makeAddr(0xAA), Amount: 5000},
		{Address: makeAddr(0xBB), Amount: 5000},
	}
	assert.Error(t, ValidateDistribution(dists, entries, 10000, 10000))
}

func TestValidateDistribution_AddressMismatch(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 5000},
		{Address: makeAddr(0xBB), Share: 5000},
	}
	dists := []Distribution{
		{Address: makeAddr(0xBB), Amount: 5000}, // swapped
		{Address: makeAddr(0xAA), Amount: 5000}, // swapped
	}
	assert.Error(t, ValidateDistribution(dists, entries, 10000, 10000))
}

func TestValidateDistribution_CorrectWithRemainder(t *testing.T) {
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 3333},
		{Address: makeAddr(0xBB), Share: 3333},
		{Address: makeAddr(0xCC), Share: 3334},
	}
	// Compute expected via DistributeRevenue
	expected, err := DistributeRevenue(10, entries, 10000)
	require.NoError(t, err)
	assert.NoError(t, ValidateDistribution(expected, entries, 10, 10000))
}

func TestRegistryState_FindEntry_NotFound(t *testing.T) {
	state := &RegistryState{
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 10000},
		},
	}
	idx, entry := state.FindEntry(makeAddr(0xFF))
	assert.Equal(t, -1, idx)
	assert.Nil(t, entry)
}

func TestRegistryState_FindEntry_First(t *testing.T) {
	state := &RegistryState{
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 5000},
			{Address: makeAddr(0xBB), Share: 5000},
		},
	}
	idx, entry := state.FindEntry(makeAddr(0xAA))
	assert.Equal(t, 0, idx)
	assert.Equal(t, uint64(5000), entry.Share)
}

func TestRegistryState_FindEntry_Last(t *testing.T) {
	state := &RegistryState{
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 3000},
			{Address: makeAddr(0xBB), Share: 3000},
			{Address: makeAddr(0xCC), Share: 4000},
		},
	}
	idx, entry := state.FindEntry(makeAddr(0xCC))
	assert.Equal(t, 2, idx)
	assert.Equal(t, uint64(4000), entry.Share)
}

func TestRegistryState_FindEntry_Empty(t *testing.T) {
	state := &RegistryState{Entries: nil}
	idx, entry := state.FindEntry(makeAddr(0xAA))
	assert.Equal(t, -1, idx)
	assert.Nil(t, entry)
}

func TestRegistryState_FindEntry_Mutate(t *testing.T) {
	// Verify returned entry pointer allows mutation
	state := &RegistryState{
		Entries: []RevShareEntry{
			{Address: makeAddr(0xAA), Share: 5000},
		},
	}
	_, entry := state.FindEntry(makeAddr(0xAA))
	require.NotNil(t, entry)
	entry.Share = 9999
	assert.Equal(t, uint64(9999), state.Entries[0].Share)
}

func TestRegistryState_IsISOActive_AllCombinations(t *testing.T) {
	for flags := uint8(0); flags < 4; flags++ {
		state := &RegistryState{ModeFlags: flags}
		assert.Equal(t, flags&0x01 != 0, state.IsISOActive(), "flags=%d", flags)
		assert.Equal(t, flags&0x02 != 0, state.IsLocked(), "flags=%d", flags)
	}
}

func TestRegistryState_IsISOActive_HighBitsIgnored(t *testing.T) {
	// Bits above 1 should not affect ISO/Lock status
	state := &RegistryState{ModeFlags: 0xFC} // bits 2-7 set, bits 0-1 clear
	assert.False(t, state.IsISOActive())
	assert.False(t, state.IsLocked())

	state.ModeFlags = 0xFF // all bits set
	assert.True(t, state.IsISOActive())
	assert.True(t, state.IsLocked())
}

func TestValidateDistribution_ZeroPayment(t *testing.T) {
	entries := []RevShareEntry{{Address: makeAddr(0xAA), Share: 10000}}
	dists := []Distribution{{Address: makeAddr(0xAA), Amount: 0}}
	// ValidateDistribution calls DistributeRevenue which rejects zero payment
	assert.Error(t, ValidateDistribution(dists, entries, 0, 10000))
}

func TestValidateDistribution_ZeroTotalShares(t *testing.T) {
	entries := []RevShareEntry{{Address: makeAddr(0xAA), Share: 10000}}
	dists := []Distribution{{Address: makeAddr(0xAA), Amount: 10000}}
	assert.Error(t, ValidateDistribution(dists, entries, 10000, 0))
}

// --- Integer safety tests (C-1, C-2, C-3, H-1, H-2 fixes) ---

func TestDistributeRevenue_ShareSumMismatch(t *testing.T) {
	// C-3: sum(entries.Share) != totalShares must return error.
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 80},
		{Address: makeAddr(0xBB), Share: 80},
		{Address: makeAddr(0xCC), Share: 80},
	}
	_, err := DistributeRevenue(1000, entries, 100)
	assert.ErrorIs(t, err, ErrShareSumMismatch)
}

func TestDistributeRevenue_ShareSumOverflow(t *testing.T) {
	// C-3: entries whose shares overflow uint64 must return error.
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: ^uint64(0)},
		{Address: makeAddr(0xBB), Share: 1},
	}
	_, err := DistributeRevenue(1000, entries, ^uint64(0))
	assert.ErrorIs(t, err, ErrOverflow)
}

func TestDistributeRevenue_LargeMultiplication(t *testing.T) {
	// C-1: Values that would overflow naive uint64 multiplication.
	// totalPayment * entry.Share > 2^64, but result fits in uint64.
	maxU64 := ^uint64(0)
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: maxU64 / 2},
		{Address: makeAddr(0xBB), Share: maxU64 - maxU64/2},
	}
	dists, err := DistributeRevenue(maxU64, entries, maxU64)
	require.NoError(t, err)
	assert.Equal(t, maxU64/2, dists[0].Amount)
	// Last entry gets remainder
	assert.Equal(t, maxU64-maxU64/2, dists[1].Amount)
}

func TestDistributeRevenue_128BitIntermediate(t *testing.T) {
	// Test that 128-bit intermediate multiplication works correctly.
	// totalPayment=18446744073709551615, entry.Share=10000, totalShares=10000
	// Naive: 18446744073709551615 * 10000 overflows uint64
	// Expected: 18446744073709551615
	maxU64 := ^uint64(0)
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 10000},
	}
	dists, err := DistributeRevenue(maxU64, entries, 10000)
	require.NoError(t, err)
	assert.Equal(t, maxU64, dists[0].Amount)
}

func TestValidateShareConservation_Overflow(t *testing.T) {
	// H-1: inputs that would overflow uint64 sum must return error.
	nodeID := makeNodeID(0x01)
	inputs := []ShareData{
		{NodeID: nodeID, Amount: ^uint64(0)},
		{NodeID: nodeID, Amount: 1},
	}
	outputs := []ShareData{{NodeID: nodeID, Amount: 0}}
	err := ValidateShareConservation(inputs, outputs)
	assert.ErrorIs(t, err, ErrOverflow)
}

func TestDistributeRevenue_SingleShareEqualsTotal(t *testing.T) {
	// Edge case: single entry where share == totalShares.
	entries := []RevShareEntry{
		{Address: makeAddr(0xAA), Share: 1},
	}
	dists, err := DistributeRevenue(999, entries, 1)
	require.NoError(t, err)
	assert.Equal(t, uint64(999), dists[0].Amount)
}
