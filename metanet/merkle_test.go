package metanet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tongxiaofeng/libbitfs/spv"
)

func TestComputeChildLeafHash(t *testing.T) {
	entry := ChildEntry{
		Index:    0,
		Name:     "hello.txt",
		Type:     NodeTypeFile,
		PubKey:   makePubKey(0x01),
		Hardened: false,
	}

	hash := ComputeChildLeafHash(&entry)
	require.Len(t, hash, 32)

	// Must equal DoubleHash of the serialized ChildEntry
	serialized := serializeChildEntry(&entry)
	expected := spv.DoubleHash(serialized)
	assert.Equal(t, expected, hash)
}

func TestComputeChildLeafHash_Deterministic(t *testing.T) {
	entry := ChildEntry{
		Index:    5,
		Name:     "doc.pdf",
		Type:     NodeTypeDir,
		PubKey:   makePubKey(0x42),
		Hardened: true,
	}

	h1 := ComputeChildLeafHash(&entry)
	h2 := ComputeChildLeafHash(&entry)
	assert.Equal(t, h1, h2, "same entry must produce same hash")
}

func TestComputeChildLeafHash_DifferentEntries(t *testing.T) {
	e1 := ChildEntry{Index: 0, Name: "a.txt", Type: NodeTypeFile, PubKey: makePubKey(0x01)}
	e2 := ChildEntry{Index: 1, Name: "b.txt", Type: NodeTypeFile, PubKey: makePubKey(0x02)}

	h1 := ComputeChildLeafHash(&e1)
	h2 := ComputeChildLeafHash(&e2)
	assert.NotEqual(t, h1, h2, "different entries must produce different hashes")
}
