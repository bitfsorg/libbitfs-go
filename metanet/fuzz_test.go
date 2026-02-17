package metanet

import (
	"bytes"
	"testing"

	"github.com/tongxiaofeng/libbitfs/tx"
)

// FuzzDeserializePayload ensures the TLV parser never panics on arbitrary input.
func FuzzDeserializePayload(f *testing.F) {
	// Empty
	f.Add([]byte{})
	// Valid single uint32 field: tag=0x01(Version) len=4,0 val=1,0,0,0
	f.Add([]byte{0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00})
	// Truncated TLV (tag + partial length)
	f.Add([]byte{0x01, 0x04})
	// Truncated value
	f.Add([]byte{0x01, 0x08, 0x00, 0x01, 0x02})
	// Unknown tag (should be skipped)
	f.Add([]byte{0xFF, 0x02, 0x00, 0xAB, 0xCD})
	// Multiple fields
	f.Add([]byte{
		0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // Version=1
		0x02, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // Type=DIR
		0x04, 0x05, 0x00, 'h', 'e', 'l', 'l', 'o', // MimeType="hello"
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		node := &Node{Metadata: make(map[string]string)}
		// Must not panic; errors are expected
		deserializePayload(data, node)
	})
}

// FuzzDeserializeChildEntry ensures child entry parsing never panics.
func FuzzDeserializeChildEntry(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // min valid: index=0, nameLen=0
	f.Add(make([]byte, 50))

	// Build a valid child entry seed
	valid := serializeChildEntry(&ChildEntry{
		Index:    1,
		Name:     "test.txt",
		Type:     NodeTypeFile,
		PubKey:   make([]byte, CompressedPubKeyLen),
		Hardened: true,
	})
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		deserializeChildEntry(data)
	})
}

// FuzzSerializeParseRoundTrip verifies that serializing a Node and parsing it
// back preserves all fields.
func FuzzSerializeParseRoundTrip(f *testing.F) {
	f.Add(
		uint8(0),  // nodeType: FILE
		uint8(0),  // op: CREATE
		uint8(0),  // access: PRIVATE
		"text/plain",
		uint64(1024),
		uint64(100),
		"example.com",
		"test file",
		true,  // encrypted
		false, // onChain
	)
	f.Add(
		uint8(1),  // DIR
		uint8(1),  // UPDATE
		uint8(1),  // FREE
		"",
		uint64(0),
		uint64(0),
		"",
		"",
		false,
		true,
	)

	f.Fuzz(func(t *testing.T,
		nodeType uint8, op uint8, access uint8,
		mimeType string, fileSize uint64, pricePerKB uint64,
		domain string, description string,
		encrypted bool, onChain bool,
	) {
		// Constrain enums to valid ranges
		nt := NodeType(nodeType % 3)
		opType := OpType(op % 3)
		al := AccessLevel(access % 3)

		original := &Node{
			Version:     1,
			Type:        nt,
			Op:          opType,
			MimeType:    mimeType,
			FileSize:    fileSize,
			Access:      al,
			PricePerKB:  pricePerKB,
			Domain:      domain,
			Description: description,
			Encrypted:   encrypted,
			OnChain:     onChain,
			PNode:       make([]byte, CompressedPubKeyLen),
			Metadata:    make(map[string]string),
		}

		payload, err := SerializePayload(original)
		if err != nil {
			t.Fatal(err)
		}

		// Wrap in valid OP_RETURN pushes for ParseNode
		pushes := [][]byte{
			tx.MetaFlagBytes,
			original.PNode,
			{}, // root node (no parent)
			payload,
		}

		parsed, err := ParseNode(pushes)
		if err != nil {
			t.Fatalf("ParseNode failed on serialized payload: %v", err)
		}

		// Verify round-trip field equality
		if parsed.Version != original.Version {
			t.Errorf("Version: got %d, want %d", parsed.Version, original.Version)
		}
		if parsed.Type != original.Type {
			t.Errorf("Type: got %d, want %d", parsed.Type, original.Type)
		}
		if parsed.Op != original.Op {
			t.Errorf("Op: got %d, want %d", parsed.Op, original.Op)
		}
		if parsed.MimeType != original.MimeType {
			t.Errorf("MimeType: got %q, want %q", parsed.MimeType, original.MimeType)
		}
		if parsed.FileSize != original.FileSize {
			t.Errorf("FileSize: got %d, want %d", parsed.FileSize, original.FileSize)
		}
		if parsed.Access != original.Access {
			t.Errorf("Access: got %d, want %d", parsed.Access, original.Access)
		}
		if parsed.PricePerKB != original.PricePerKB {
			t.Errorf("PricePerKB: got %d, want %d", parsed.PricePerKB, original.PricePerKB)
		}
		if parsed.Domain != original.Domain {
			t.Errorf("Domain: got %q, want %q", parsed.Domain, original.Domain)
		}
		if parsed.Description != original.Description {
			t.Errorf("Description: got %q, want %q", parsed.Description, original.Description)
		}
		if parsed.Encrypted != original.Encrypted {
			t.Errorf("Encrypted: got %v, want %v", parsed.Encrypted, original.Encrypted)
		}
		if parsed.OnChain != original.OnChain {
			t.Errorf("OnChain: got %v, want %v", parsed.OnChain, original.OnChain)
		}
		if !bytes.Equal(parsed.PNode, original.PNode) {
			t.Error("PNode mismatch")
		}
	})
}

// FuzzParseNodeNoPanic ensures ParseNode never panics on arbitrary push data.
func FuzzParseNodeNoPanic(f *testing.F) {
	f.Add([]byte("meta"), []byte{}, []byte{}, []byte{})
	f.Add([]byte("meta"), make([]byte, CompressedPubKeyLen), []byte{}, []byte{0x01})
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, p0, p1, p2, p3 []byte) {
		pushes := [][]byte{p0, p1, p2, p3}
		ParseNode(pushes)
	})
}
