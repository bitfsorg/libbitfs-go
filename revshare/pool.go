package revshare

import (
	"encoding/binary"
	"fmt"
)

const isoPoolSize = 68 // node_id(32) + remaining(8) + price(8) + creator(20)

// SerializeISOPool encodes ISOPoolState to binary format.
func SerializeISOPool(state *ISOPoolState) []byte {
	buf := make([]byte, isoPoolSize)
	copy(buf[0:32], state.NodeID[:])
	binary.BigEndian.PutUint64(buf[32:40], state.RemainingShares)
	binary.BigEndian.PutUint64(buf[40:48], state.PricePerShare)
	copy(buf[48:68], state.CreatorAddr[:])
	return buf
}

// DeserializeISOPool decodes binary data into ISOPoolState.
func DeserializeISOPool(data []byte) (*ISOPoolState, error) {
	if len(data) != isoPoolSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidISOPoolData, isoPoolSize, len(data))
	}
	state := &ISOPoolState{}
	copy(state.NodeID[:], data[0:32])
	state.RemainingShares = binary.BigEndian.Uint64(data[32:40])
	state.PricePerShare = binary.BigEndian.Uint64(data[40:48])
	copy(state.CreatorAddr[:], data[48:68])
	return state, nil
}
