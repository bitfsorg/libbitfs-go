package metanet

import (
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
