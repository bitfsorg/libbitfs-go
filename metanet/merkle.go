package metanet

import (
	"github.com/tongxiaofeng/libbitfs/spv"
)

// ComputeChildLeafHash computes the Merkle leaf hash for a single ChildEntry.
// The leaf hash is DoubleHash(serialize(entry)), reusing the existing
// ChildEntry binary format and Bitcoin's double-SHA256.
func ComputeChildLeafHash(entry *ChildEntry) []byte {
	serialized := serializeChildEntry(entry)
	return spv.DoubleHash(serialized)
}
