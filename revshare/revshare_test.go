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
