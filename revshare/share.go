package revshare

import (
	"encoding/binary"
	"fmt"
)

const shareDataSize = 40 // node_id(32) + share_amount(8)

// SerializeShare encodes ShareData to binary format.
func SerializeShare(data *ShareData) []byte {
	buf := make([]byte, shareDataSize)
	copy(buf[0:32], data.NodeID[:])
	binary.BigEndian.PutUint64(buf[32:40], data.Amount)
	return buf
}

// DeserializeShare decodes binary data into ShareData.
func DeserializeShare(data []byte) (*ShareData, error) {
	if len(data) != shareDataSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidShareData, shareDataSize, len(data))
	}
	share := &ShareData{}
	copy(share.NodeID[:], data[0:32])
	share.Amount = binary.BigEndian.Uint64(data[32:40])
	return share, nil
}
