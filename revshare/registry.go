package revshare

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	registryHeaderSize  = 44 // node_id(32) + total_shares(8) + num_entries(4)
	registryEntrySize   = 28 // address(20) + share(8)
	registryTrailerSize = 1  // mode_flags(1)
)

// SerializeRegistry serializes a RegistryState to binary format.
func SerializeRegistry(state *RegistryState) ([]byte, error) {
	if len(state.Entries) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %d entries", ErrTooManyEntries, len(state.Entries))
	}
	size := registryHeaderSize + registryEntrySize*len(state.Entries) + registryTrailerSize
	buf := make([]byte, size)
	offset := 0

	copy(buf[offset:offset+32], state.NodeID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], state.TotalShares)
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(state.Entries)))
	offset += 4

	for _, entry := range state.Entries {
		copy(buf[offset:offset+20], entry.Address[:])
		offset += 20
		binary.BigEndian.PutUint64(buf[offset:offset+8], entry.Share)
		offset += 8
	}

	buf[offset] = state.ModeFlags
	return buf, nil
}

// DeserializeRegistry deserializes binary data into a RegistryState.
func DeserializeRegistry(data []byte) (*RegistryState, error) {
	if len(data) < registryHeaderSize+registryTrailerSize {
		return nil, fmt.Errorf("%w: too short (%d bytes)", ErrInvalidRegistryData, len(data))
	}
	offset := 0

	state := &RegistryState{}
	copy(state.NodeID[:], data[offset:offset+32])
	offset += 32

	state.TotalShares = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	numEntries := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4

	expectedSize := registryHeaderSize + registryEntrySize*numEntries + registryTrailerSize
	if len(data) < expectedSize {
		return nil, fmt.Errorf("%w: expected %d bytes for %d entries, got %d",
			ErrInvalidRegistryData, expectedSize, numEntries, len(data))
	}

	state.Entries = make([]RevShareEntry, numEntries)
	for i := 0; i < numEntries; i++ {
		copy(state.Entries[i].Address[:], data[offset:offset+20])
		offset += 20
		state.Entries[i].Share = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	state.ModeFlags = data[offset]
	return state, nil
}
