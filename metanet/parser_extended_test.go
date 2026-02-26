package metanet

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializePayload_Metadata_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
	}{
		{"empty", map[string]string{}},
		{"single entry", map[string]string{"author": "alice"}},
		{"multiple entries", map[string]string{
			"author":  "alice",
			"license": "MIT",
			"version": "1.0",
		}},
		{"utf8 values", map[string]string{"名前": "太郎", "描述": "テスト"}},
		{"empty value", map[string]string{"tag": ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{
				Version:  1,
				Type:     NodeTypeFile,
				Metadata: tt.metadata,
			}

			payload, err := SerializePayload(node)
			require.NoError(t, err)

			decoded := &Node{Metadata: make(map[string]string)}
			err = deserializePayload(payload, decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.metadata, decoded.Metadata)
		})
	}
}

func TestSerializePayload_Metadata_BackwardCompat(t *testing.T) {
	// Node with no metadata should still parse (no metadata tag emitted)
	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Metadata: map[string]string{},
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	// Verify tagMetadata not present in payload
	for i := 0; i < len(payload); i++ {
		if payload[i] == tagMetadata {
			t.Fatal("tagMetadata should not be emitted for empty metadata")
		}
	}
}

func TestSerializePayload_ExtendedFields_RoundTrip(t *testing.T) {
	node := &Node{
		Version:           1,
		Type:              NodeTypeFile,
		Metadata:          make(map[string]string),
		VersionLog:        makePubKey(0xA1),
		ShareList:         makePubKey(0xA2),
		ChunkIndex:        3,
		TotalChunks:       10,
		RecombinationHash: bytes.Repeat([]byte{0xCC}, 32),
		RabinSignature:    bytes.Repeat([]byte{0xDD}, 64),
		RabinPubKey:       bytes.Repeat([]byte{0xEE}, 128),
		RegistryTxID:      makeTxID(0xF1),
		RegistryVout:      2,
		ACLRef:            bytes.Repeat([]byte{0xAA}, 32),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, node.VersionLog, decoded.VersionLog)
	assert.Equal(t, node.ShareList, decoded.ShareList)
	assert.Equal(t, node.ChunkIndex, decoded.ChunkIndex)
	assert.Equal(t, node.TotalChunks, decoded.TotalChunks)
	assert.Equal(t, node.RecombinationHash, decoded.RecombinationHash)
	assert.Equal(t, node.RabinSignature, decoded.RabinSignature)
	assert.Equal(t, node.RabinPubKey, decoded.RabinPubKey)
	assert.Equal(t, node.RegistryTxID, decoded.RegistryTxID)
	assert.Equal(t, node.RegistryVout, decoded.RegistryVout)
	assert.Equal(t, node.ACLRef, decoded.ACLRef)
}

func TestSerializePayload_ExtendedFields_ZeroValues(t *testing.T) {
	// Zero/nil values should not emit tags
	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		Metadata: make(map[string]string),
		// All extended fields at zero/nil
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	// None of the new tags should be present
	newTags := []byte{
		tagVersionLog, tagShareList, tagChunkIndex, tagTotalChunks,
		tagRecombinationHash, tagRabinSignature, tagRabinPubKey,
		tagRegistryTxID, tagRegistryVout, tagISOConfig, tagACLRef,
	}
	for _, tag := range newTags {
		for i := 0; i < len(payload); i++ {
			assert.NotEqual(t, tag, payload[i],
				"tag 0x%02x should not be present for zero value", tag)
		}
	}
}

func TestSerializePayload_ISOConfig_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		iso  *ISOConfig
	}{
		{"open", &ISOConfig{
			TotalShares: 10000, PricePerShare: 100,
			CreatorAddr: bytes.Repeat([]byte{0xAB}, 20), Status: ISOStatusOpen,
		}},
		{"partial", &ISOConfig{
			TotalShares: 1000000, PricePerShare: 1,
			CreatorAddr: bytes.Repeat([]byte{0x01}, 20), Status: ISOStatusPartial,
		}},
		{"closed", &ISOConfig{
			TotalShares: 100, PricePerShare: 50000,
			CreatorAddr: bytes.Repeat([]byte{0xFF}, 20), Status: ISOStatusClosed,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{
				Version:  1,
				Type:     NodeTypeFile,
				Metadata: make(map[string]string),
				ISO:      tt.iso,
			}

			payload, err := SerializePayload(node)
			require.NoError(t, err)

			decoded := &Node{Metadata: make(map[string]string)}
			err = deserializePayload(payload, decoded)
			require.NoError(t, err)

			require.NotNil(t, decoded.ISO)
			assert.Equal(t, tt.iso.TotalShares, decoded.ISO.TotalShares)
			assert.Equal(t, tt.iso.PricePerShare, decoded.ISO.PricePerShare)
			assert.Equal(t, tt.iso.CreatorAddr, decoded.ISO.CreatorAddr)
			assert.Equal(t, tt.iso.Status, decoded.ISO.Status)
		})
	}
}

func TestSerializePayload_ISOConfig_NilOmitted(t *testing.T) {
	node := &Node{Version: 1, Type: NodeTypeFile, Metadata: make(map[string]string)}
	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)
	assert.Nil(t, decoded.ISO)
}
