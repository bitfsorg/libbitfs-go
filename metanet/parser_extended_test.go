package metanet

import (
	"bytes"
	"sync"
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

// =============================================================================
// R06-M1 / R03-M1: TLV field length validation tests
// =============================================================================

// buildTLV constructs a single TLV field: tag(1) + LEB128(length) + value.
func buildTLV(tag byte, value []byte) []byte {
	var buf []byte
	buf = append(buf, tag)
	buf = appendUvarint(buf, uint64(len(value)))
	buf = append(buf, value...)
	return buf
}

func TestValidateTLVFieldLength_Uint32Fields(t *testing.T) {
	// All uint32 fields must be exactly 4 bytes. Test with wrong lengths.
	uint32Tags := []struct {
		name string
		tag  byte
	}{
		{"Version", tagVersion},
		{"Type", tagType},
		{"Op", tagOp},
		{"Access", tagAccess},
		{"LinkType", tagLinkType},
		{"Index", tagIndex},
		{"NextChildIndex", tagNextChildIndex},
		{"Encrypted", tagEncrypted},
		{"OnChain", tagOnChain},
		{"Compression", tagCompression},
		{"CltvHeight", tagCltvHeight},
		{"RevenueShare", tagRevenueShare},
		{"ChunkIndex", tagChunkIndex},
		{"TotalChunks", tagTotalChunks},
		{"RegistryVout", tagRegistryVout},
		{"FileMode", tagFileMode},
	}

	for _, tt := range uint32Tags {
		t.Run(tt.name+"_too_short", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 2)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 4 bytes")
		})
		t.Run(tt.name+"_too_long", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 8)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 4 bytes")
		})
		t.Run(tt.name+"_correct", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 4)
			assert.NoError(t, err)
		})
	}
}

func TestValidateTLVFieldLength_Uint64Fields(t *testing.T) {
	uint64Tags := []struct {
		name string
		tag  byte
	}{
		{"FileSize", tagFileSize},
		{"PricePerKB", tagPricePerKB},
		{"Timestamp", tagTimestamp},
	}

	for _, tt := range uint64Tags {
		t.Run(tt.name+"_too_short", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 4)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 8 bytes")
		})
		t.Run(tt.name+"_too_long", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 16)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 8 bytes")
		})
		t.Run(tt.name+"_correct", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 8)
			assert.NoError(t, err)
		})
	}
}

func TestValidateTLVFieldLength_HashFields(t *testing.T) {
	hash32Tags := []struct {
		name string
		tag  byte
	}{
		{"MerkleRoot", tagMerkleRoot},
		{"RecombinationHash", tagRecombinationHash},
		{"RegistryTxID", tagRegistryTxID},
		{"TreeRootTxID", tagTreeRootTxID},
		{"KeyHash", tagKeyHash},
		{"ContentTxID", tagContentTxID},
		{"ParentAnchorTxID", tagParentAnchorTxID},
	}

	for _, tt := range hash32Tags {
		t.Run(tt.name+"_wrong_length", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 16)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 32 bytes")
		})
		t.Run(tt.name+"_correct", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 32)
			assert.NoError(t, err)
		})
	}
}

func TestValidateTLVFieldLength_PubKeyFields(t *testing.T) {
	pubkey33Tags := []struct {
		name string
		tag  byte
	}{
		{"Parent", tagParent},
		{"VersionLog", tagVersionLog},
		{"ShareList", tagShareList},
		{"TreeRootPNode", tagTreeRootPNode},
	}

	for _, tt := range pubkey33Tags {
		t.Run(tt.name+"_wrong_length", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 32)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "expected 33 bytes")
		})
		t.Run(tt.name+"_correct", func(t *testing.T) {
			err := validateTLVFieldLength(tt.tag, 33)
			assert.NoError(t, err)
		})
	}
}

func TestValidateTLVFieldLength_SpecialSizes(t *testing.T) {
	t.Run("GitCommitSHA_wrong", func(t *testing.T) {
		err := validateTLVFieldLength(tagGitCommitSHA, 32)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 20 bytes")
	})
	t.Run("GitCommitSHA_correct", func(t *testing.T) {
		err := validateTLVFieldLength(tagGitCommitSHA, 20)
		assert.NoError(t, err)
	})
	t.Run("ISOConfig_wrong", func(t *testing.T) {
		err := validateTLVFieldLength(tagISOConfig, 32)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 37 bytes")
	})
	t.Run("ISOConfig_correct", func(t *testing.T) {
		err := validateTLVFieldLength(tagISOConfig, 37)
		assert.NoError(t, err)
	})
}

func TestValidateTLVFieldLength_VariableLengthTags(t *testing.T) {
	// Variable-length tags should pass with any length.
	variableTags := []byte{
		tagMimeType, tagDomain, tagKeywords, tagDescription,
		tagNetworkName, tagChildEntry, tagMetadata, tagEncPayload,
		tagLinkTarget, tagRabinSignature, tagRabinPubKey, tagACLRef,
		tagAuthor, tagCommitMessage,
	}

	for _, tag := range variableTags {
		for _, length := range []int{0, 1, 100, 1000} {
			err := validateTLVFieldLength(tag, length)
			assert.NoError(t, err, "variable-length tag 0x%02x should accept length %d", tag, length)
		}
	}
}

func TestValidateTLVFieldLength_UnknownTag(t *testing.T) {
	// Unknown tags should not trigger validation errors.
	err := validateTLVFieldLength(0xFE, 42)
	assert.NoError(t, err)
}

// TestDeserializePayload_RejectsWrongFieldLength tests that deserializePayload
// rejects TLV entries with known tags but wrong value lengths.
func TestDeserializePayload_RejectsWrongFieldLength(t *testing.T) {
	tests := []struct {
		name  string
		tag   byte
		value []byte
	}{
		{"Version_2bytes", tagVersion, []byte{0x01, 0x00}},
		{"Type_1byte", tagType, []byte{0x01}},
		{"FileSize_4bytes", tagFileSize, make([]byte, 4)},
		{"KeyHash_16bytes", tagKeyHash, make([]byte, 16)},
		{"Parent_32bytes", tagParent, make([]byte, 32)},
		{"MerkleRoot_16bytes", tagMerkleRoot, make([]byte, 16)},
		{"GitCommitSHA_32bytes", tagGitCommitSHA, make([]byte, 32)},
		{"ISOConfig_32bytes", tagISOConfig, make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlv := buildTLV(tt.tag, tt.value)
			node := &Node{Metadata: make(map[string]string)}
			err := deserializePayload(tlv, node)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid field length")
		})
	}
}

// =============================================================================
// R06-M5: MaxPayloadSize enforcement
// =============================================================================

func TestDeserializePayload_MaxPayloadSize(t *testing.T) {
	// Craft a TLV where the LEB128-encoded length exceeds MaxPayloadSize
	// but doesn't overflow. We encode length = MaxPayloadSize + 1.
	bigLen := uint64(MaxPayloadSize) + 1
	var buf []byte
	buf = append(buf, tagMimeType) // variable-length tag
	buf = appendUvarint(buf, bigLen)
	// Append some dummy bytes (fewer than claimed, but the size check fires first).
	buf = append(buf, make([]byte, 100)...)

	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload(buf, node)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "payload too large")
}

func TestDeserializePayload_MaxPayloadSizeExact(t *testing.T) {
	// Length exactly at MaxPayloadSize should NOT trigger "payload too large"
	// (but will trigger "truncated" since we don't provide that much data).
	exactLen := uint64(MaxPayloadSize)
	var buf []byte
	buf = append(buf, tagMimeType)
	buf = appendUvarint(buf, exactLen)
	buf = append(buf, make([]byte, 100)...) // much less than claimed

	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload(buf, node)
	assert.Error(t, err)
	// Should be "truncated", not "payload too large"
	assert.Contains(t, err.Error(), "truncated")
}

// =============================================================================
// R06-M4: serializeChildEntry concurrent safety
// =============================================================================

func TestSerializeChildEntry_ConcurrentSafety(t *testing.T) {
	const goroutines = 50
	entries := make([]ChildEntry, goroutines)
	for i := range entries {
		pk := make([]byte, CompressedPubKeyLen)
		pk[0] = byte(i)
		entries[i] = ChildEntry{
			Index:    uint32(i),
			Name:     "file_" + string(rune('A'+i%26)),
			Type:     NodeType(i % 3),
			PubKey:   pk,
			Hardened: i%2 == 0,
		}
	}

	results := make([][]byte, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx] = serializeChildEntry(&entries[idx])
		}(i)
	}

	wg.Wait()

	// Verify each result deserializes correctly back to its original entry.
	for i, data := range results {
		entry, err := deserializeChildEntry(data)
		require.NoError(t, err, "entry %d", i)
		assert.Equal(t, entries[i].Index, entry.Index, "entry %d index", i)
		assert.Equal(t, entries[i].Name, entry.Name, "entry %d name", i)
		assert.Equal(t, entries[i].Type, entry.Type, "entry %d type", i)
		assert.Equal(t, entries[i].PubKey, entry.PubKey, "entry %d pubkey", i)
		assert.Equal(t, entries[i].Hardened, entry.Hardened, "entry %d hardened", i)
	}
}

// =============================================================================
// R06-M1: Deserialized values are independent copies (byte slice safety)
// =============================================================================

func TestDeserializePayload_ByteSliceIndependence(t *testing.T) {
	// Verify that deserialized byte slices are independent copies of the
	// input buffer, not subslices that share underlying memory.
	keyHash := bytes.Repeat([]byte{0xAB}, 32)
	node := &Node{
		Version:  1,
		Type:     NodeTypeFile,
		KeyHash:  keyHash,
		Metadata: make(map[string]string),
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	// Mutate the original payload buffer.
	for i := range payload {
		payload[i] = 0xFF
	}

	// Decoded values must not have changed.
	assert.Equal(t, keyHash, decoded.KeyHash,
		"deserialized KeyHash must be independent of payload buffer")
}

// =============================================================================
// Anchor fields TLV round-trip
// =============================================================================

func TestSerializePayload_AnchorFields_RoundTrip(t *testing.T) {
	node := &Node{
		Version:          1,
		Type:             NodeTypeAnchor,
		Op:               OpCreate,
		Metadata:         make(map[string]string),
		TreeRootPNode:    makePubKey(0xA1),
		TreeRootTxID:     makeTxID(0xB1),
		ParentAnchorTxID: [][]byte{makeTxID(0xC1), makeTxID(0xC2)},
		Author:           "alice",
		CommitMessage:    "initial commit",
		GitCommitSHA:     bytes.Repeat([]byte{0xDD}, 20),
		FileMode:         0o100644,
	}

	payload, err := SerializePayload(node)
	require.NoError(t, err)

	decoded := &Node{Metadata: make(map[string]string)}
	err = deserializePayload(payload, decoded)
	require.NoError(t, err)

	assert.Equal(t, node.TreeRootPNode, decoded.TreeRootPNode)
	assert.Equal(t, node.TreeRootTxID, decoded.TreeRootTxID)
	require.Len(t, decoded.ParentAnchorTxID, 2)
	assert.Equal(t, node.ParentAnchorTxID[0], decoded.ParentAnchorTxID[0])
	assert.Equal(t, node.ParentAnchorTxID[1], decoded.ParentAnchorTxID[1])
	assert.Equal(t, node.Author, decoded.Author)
	assert.Equal(t, node.CommitMessage, decoded.CommitMessage)
	assert.Equal(t, node.GitCommitSHA, decoded.GitCommitSHA)
	assert.Equal(t, node.FileMode, decoded.FileMode)
}

// =============================================================================
// Edge: SerializePayload nil node
// =============================================================================

func TestSerializePayload_NilNode(t *testing.T) {
	_, err := SerializePayload(nil)
	assert.ErrorIs(t, err, ErrNilParam)
}

// =============================================================================
// Edge: deserializeChildEntry truncated input
// =============================================================================

func TestDeserializeChildEntry_TruncatedInputs(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"only_index", make([]byte, 4)},
		{"index_plus_partial_nameLen", make([]byte, 5)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := deserializeChildEntry(tt.data)
			assert.Error(t, err)
		})
	}
}

// =============================================================================
// Edge: deserializePayload invalid varint
// =============================================================================

func TestDeserializePayload_InvalidVarint(t *testing.T) {
	// 10 bytes of 0xFF is an unterminated varint (never has MSB clear).
	buf := []byte{tagVersion}
	buf = append(buf, bytes.Repeat([]byte{0xFF}, 10)...)
	buf = append(buf, 0x00) // terminate but this makes it > MaxVarintLen64

	node := &Node{Metadata: make(map[string]string)}
	err := deserializePayload(buf, node)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid varint")
}
