package metanet

import (
	"encoding/binary"
	"fmt"

	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// Payload field tag constants for the TLV binary format.
// Each field is: tag(1 byte) + length(unsigned varint / LEB128) + value(length bytes).
const (
	tagVersion        = 0x01
	tagType           = 0x02
	tagOp             = 0x03
	tagMimeType       = 0x04
	tagFileSize       = 0x05
	tagKeyHash        = 0x06
	tagAccess         = 0x07
	tagPricePerKB     = 0x08
	tagLinkTarget     = 0x09
	tagLinkType       = 0x0A
	tagTimestamp      = 0x0B
	tagParent         = 0x0C
	tagIndex          = 0x0D
	tagChildEntry     = 0x0E
	tagNextChildIndex = 0x0F
	tagDomain         = 0x10
	tagKeywords       = 0x11
	tagDescription    = 0x12
	tagEncrypted      = 0x13
	tagOnChain        = 0x14
	tagContentTxID    = 0x15
	tagCompression    = 0x16
	tagCltvHeight     = 0x17
	tagRevenueShare   = 0x18
	tagNetworkName    = 0x19
	tagMerkleRoot     = 0x1A // 32 bytes, directory Merkle root of children
	tagEncPayload     = 0x1B // inline encrypted content (small files)

	// Anchor node tags (NodeTypeAnchor)
	tagTreeRootPNode    = 0x20 // 33 bytes, root directory's P_node
	tagTreeRootTxID     = 0x21 // 32 bytes, root directory's latest TxID
	tagParentAnchorTxID = 0x22 // 32 bytes each, repeated for merge commits
	tagAuthor           = 0x23 // string, git commit author
	tagCommitMessage    = 0x24 // string, git commit message
	tagGitCommitSHA     = 0x25 // 20 bytes, git commit SHA
	tagFileMode         = 0x26 // uint32, git file mode
)

// ParseNode parses OP_RETURN push data (as produced by tx.ParseOPReturnData)
// into a Metanet Node. The pushes should be the 4-element array:
// [MetaFlag, P_node, TxID_parent, Payload].
func ParseNode(pushes [][]byte) (*Node, error) {
	pNode, parentTxID, payload, err := tx.ParseOPReturnData(pushes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOPReturn, err)
	}

	node := &Node{
		PNode:      make([]byte, CompressedPubKeyLen),
		ParentTxID: make([]byte, len(parentTxID)),
		Metadata:   make(map[string]string),
	}
	copy(node.PNode, pNode)
	copy(node.ParentTxID, parentTxID)

	if err := deserializePayload(payload, node); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPayload, err)
	}

	return node, nil
}

// ParseNodeFromPushesWithTxID is like ParseNode but also sets the TxID.
func ParseNodeFromPushesWithTxID(pushes [][]byte, txID []byte) (*Node, error) {
	node, err := ParseNode(pushes)
	if err != nil {
		return nil, err
	}
	if len(txID) == TxIDLen {
		node.TxID = make([]byte, TxIDLen)
		copy(node.TxID, txID)
	}
	return node, nil
}

// SerializePayload serializes Node fields into the simple TLV binary format
// that can be used as the payload in OP_RETURN.
func SerializePayload(node *Node) ([]byte, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: node", ErrNilParam)
	}

	var buf []byte

	// Version
	buf = appendUint32Field(buf, tagVersion, node.Version)

	// Type
	buf = appendUint32Field(buf, tagType, uint32(node.Type))

	// Op
	buf = appendUint32Field(buf, tagOp, uint32(node.Op))

	// MimeType
	if node.MimeType != "" {
		buf = appendStringField(buf, tagMimeType, node.MimeType)
	}

	// FileSize
	if node.FileSize > 0 {
		buf = appendUint64Field(buf, tagFileSize, node.FileSize)
	}

	// KeyHash
	if len(node.KeyHash) > 0 {
		buf = appendBytesField(buf, tagKeyHash, node.KeyHash)
	}

	// Access
	buf = appendUint32Field(buf, tagAccess, uint32(node.Access))

	// PricePerKB
	if node.PricePerKB > 0 {
		buf = appendUint64Field(buf, tagPricePerKB, node.PricePerKB)
	}

	// LinkTarget
	if len(node.LinkTarget) > 0 {
		buf = appendBytesField(buf, tagLinkTarget, node.LinkTarget)
	}

	// LinkType
	if node.Type == NodeTypeLink {
		buf = appendUint32Field(buf, tagLinkType, uint32(node.LinkType))
	}

	// Timestamp
	if node.Timestamp > 0 {
		buf = appendUint64Field(buf, tagTimestamp, node.Timestamp)
	}

	// Parent P_node
	if len(node.Parent) > 0 {
		buf = appendBytesField(buf, tagParent, node.Parent)
	}

	// Index
	buf = appendUint32Field(buf, tagIndex, node.Index)

	// Children
	for _, child := range node.Children {
		childBytes := serializeChildEntry(&child)
		buf = appendBytesField(buf, tagChildEntry, childBytes)
	}

	// NextChildIndex
	if node.Type == NodeTypeDir {
		buf = appendUint32Field(buf, tagNextChildIndex, node.NextChildIndex)
	}

	// Domain
	if node.Domain != "" {
		buf = appendStringField(buf, tagDomain, node.Domain)
	}

	// Keywords
	if node.Keywords != "" {
		buf = appendStringField(buf, tagKeywords, node.Keywords)
	}

	// Description
	if node.Description != "" {
		buf = appendStringField(buf, tagDescription, node.Description)
	}

	// Encrypted
	if node.Encrypted {
		buf = appendUint32Field(buf, tagEncrypted, 1)
	}

	// OnChain
	if node.OnChain {
		buf = appendUint32Field(buf, tagOnChain, 1)
	}

	// ContentTxIDs
	for _, contentTxID := range node.ContentTxIDs {
		buf = appendBytesField(buf, tagContentTxID, contentTxID)
	}

	// Compression
	if node.Compression > 0 {
		buf = appendUint32Field(buf, tagCompression, uint32(node.Compression))
	}

	// CltvHeight
	if node.CltvHeight > 0 {
		buf = appendUint32Field(buf, tagCltvHeight, node.CltvHeight)
	}

	// RevenueShare
	if node.RevenueShare > 0 {
		buf = appendUint32Field(buf, tagRevenueShare, node.RevenueShare)
	}

	// NetworkName
	if node.NetworkName != "" {
		buf = appendStringField(buf, tagNetworkName, node.NetworkName)
	}

	// MerkleRoot (directory only, present only when non-nil)
	if len(node.MerkleRoot) > 0 {
		buf = appendBytesField(buf, tagMerkleRoot, node.MerkleRoot)
	}

	// EncPayload (inline encrypted content for small files)
	if len(node.EncPayload) > 0 {
		buf = appendBytesField(buf, tagEncPayload, node.EncPayload)
	}

	// Anchor-specific fields (NodeTypeAnchor only)
	if len(node.TreeRootPNode) > 0 {
		buf = appendBytesField(buf, tagTreeRootPNode, node.TreeRootPNode)
	}
	if len(node.TreeRootTxID) > 0 {
		buf = appendBytesField(buf, tagTreeRootTxID, node.TreeRootTxID)
	}
	for _, parentAnchor := range node.ParentAnchorTxID {
		buf = appendBytesField(buf, tagParentAnchorTxID, parentAnchor)
	}
	if node.Author != "" {
		buf = appendStringField(buf, tagAuthor, node.Author)
	}
	if node.CommitMessage != "" {
		buf = appendStringField(buf, tagCommitMessage, node.CommitMessage)
	}
	if len(node.GitCommitSHA) > 0 {
		buf = appendBytesField(buf, tagGitCommitSHA, node.GitCommitSHA)
	}
	if node.FileMode > 0 {
		buf = appendUint32Field(buf, tagFileMode, node.FileMode)
	}

	return buf, nil
}

// --- TLV serialization helpers ---

// appendUvarint appends x as an unsigned LEB128 varint.
func appendUvarint(buf []byte, x uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], x)
	return append(buf, tmp[:n]...)
}

func appendUint32Field(buf []byte, tag byte, val uint32) []byte {
	buf = append(buf, tag)
	buf = appendUvarint(buf, 4)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	return append(buf, b...)
}

func appendUint64Field(buf []byte, tag byte, val uint64) []byte {
	buf = append(buf, tag)
	buf = appendUvarint(buf, 8)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, val)
	return append(buf, b...)
}

func appendStringField(buf []byte, tag byte, val string) []byte {
	return appendBytesField(buf, tag, []byte(val))
}

func appendBytesField(buf []byte, tag byte, data []byte) []byte {
	buf = append(buf, tag)
	buf = appendUvarint(buf, uint64(len(data)))
	return append(buf, data...)
}

func serializeChildEntry(entry *ChildEntry) []byte {
	// index(4) + nameLen(2) + name + type(4) + pubkeyLen(1) + pubkey + hardened(1)
	var buf []byte

	// Index
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, entry.Index)
	buf = append(buf, b...)

	// Name (length-prefixed)
	nameBytes := []byte(entry.Name)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(nameBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, nameBytes...)

	// Type
	binary.LittleEndian.PutUint32(b, uint32(entry.Type))
	buf = append(buf, b...)

	// PubKey (length-prefixed with 1 byte)
	buf = append(buf, byte(len(entry.PubKey)))
	buf = append(buf, entry.PubKey...)

	// Hardened flag
	if entry.Hardened {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	return buf
}

// --- TLV deserialization ---

func deserializePayload(data []byte, node *Node) error {
	offset := 0
	for offset < len(data) {
		if offset >= len(data) {
			return fmt.Errorf("truncated TLV at offset %d", offset)
		}

		tag := data[offset]
		offset++

		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return fmt.Errorf("invalid varint length for tag 0x%02x at offset %d", tag, offset)
		}
		offset += n

		if length > uint64(len(data)-offset) {
			return fmt.Errorf("truncated value for tag 0x%02x at offset %d", tag, offset)
		}
		intLen := int(length)

		value := data[offset : offset+intLen]
		offset += intLen

		switch tag {
		case tagVersion:
			if length == 4 {
				node.Version = binary.LittleEndian.Uint32(value)
			}
		case tagType:
			if length == 4 {
				node.Type = NodeType(binary.LittleEndian.Uint32(value))
			}
		case tagOp:
			if length == 4 {
				node.Op = OpType(binary.LittleEndian.Uint32(value))
			}
		case tagMimeType:
			node.MimeType = string(value)
		case tagFileSize:
			if length == 8 {
				node.FileSize = binary.LittleEndian.Uint64(value)
			}
		case tagKeyHash:
			node.KeyHash = make([]byte, length)
			copy(node.KeyHash, value)
		case tagAccess:
			if length == 4 {
				node.Access = AccessLevel(binary.LittleEndian.Uint32(value))
			}
		case tagPricePerKB:
			if length == 8 {
				node.PricePerKB = binary.LittleEndian.Uint64(value)
			}
		case tagLinkTarget:
			node.LinkTarget = make([]byte, length)
			copy(node.LinkTarget, value)
		case tagLinkType:
			if length == 4 {
				node.LinkType = LinkType(binary.LittleEndian.Uint32(value))
			}
		case tagTimestamp:
			if length == 8 {
				node.Timestamp = binary.LittleEndian.Uint64(value)
			}
		case tagParent:
			node.Parent = make([]byte, length)
			copy(node.Parent, value)
		case tagIndex:
			if length == 4 {
				node.Index = binary.LittleEndian.Uint32(value)
			}
		case tagChildEntry:
			entry, err := deserializeChildEntry(value)
			if err != nil {
				return fmt.Errorf("invalid child entry: %w", err)
			}
			node.Children = append(node.Children, *entry)
		case tagNextChildIndex:
			if length == 4 {
				node.NextChildIndex = binary.LittleEndian.Uint32(value)
			}
		case tagDomain:
			node.Domain = string(value)
		case tagKeywords:
			node.Keywords = string(value)
		case tagDescription:
			node.Description = string(value)
		case tagEncrypted:
			if length == 4 {
				node.Encrypted = binary.LittleEndian.Uint32(value) != 0
			}
		case tagOnChain:
			if length == 4 {
				node.OnChain = binary.LittleEndian.Uint32(value) != 0
			}
		case tagContentTxID:
			contentTxID := make([]byte, length)
			copy(contentTxID, value)
			node.ContentTxIDs = append(node.ContentTxIDs, contentTxID)
		case tagCompression:
			if length == 4 {
				node.Compression = int32(binary.LittleEndian.Uint32(value))
			}
		case tagCltvHeight:
			if length == 4 {
				node.CltvHeight = binary.LittleEndian.Uint32(value)
			}
		case tagRevenueShare:
			if length == 4 {
				node.RevenueShare = binary.LittleEndian.Uint32(value)
			}
		case tagNetworkName:
			node.NetworkName = string(value)
		case tagMerkleRoot:
			node.MerkleRoot = make([]byte, length)
			copy(node.MerkleRoot, value)
		case tagEncPayload:
			node.EncPayload = make([]byte, length)
			copy(node.EncPayload, value)

		// Anchor node fields
		case tagTreeRootPNode:
			node.TreeRootPNode = make([]byte, length)
			copy(node.TreeRootPNode, value)
		case tagTreeRootTxID:
			node.TreeRootTxID = make([]byte, length)
			copy(node.TreeRootTxID, value)
		case tagParentAnchorTxID:
			parentAnchor := make([]byte, length)
			copy(parentAnchor, value)
			node.ParentAnchorTxID = append(node.ParentAnchorTxID, parentAnchor)
		case tagAuthor:
			node.Author = string(value)
		case tagCommitMessage:
			node.CommitMessage = string(value)
		case tagGitCommitSHA:
			node.GitCommitSHA = make([]byte, length)
			copy(node.GitCommitSHA, value)
		case tagFileMode:
			if length == 4 {
				node.FileMode = binary.LittleEndian.Uint32(value)
			}

		default:
			// Skip unknown tags for forward compatibility
		}
	}

	return nil
}

func deserializeChildEntry(data []byte) (*ChildEntry, error) {
	if len(data) < 4+2 {
		return nil, fmt.Errorf("child entry too short")
	}

	offset := 0
	entry := &ChildEntry{}

	// Index
	entry.Index = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Name
	nameLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+nameLen > len(data) {
		return nil, fmt.Errorf("child entry name truncated")
	}
	entry.Name = string(data[offset : offset+nameLen])
	offset += nameLen

	// Type
	if offset+4 > len(data) {
		return nil, fmt.Errorf("child entry type truncated")
	}
	entry.Type = NodeType(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// PubKey
	if offset+1 > len(data) {
		return nil, fmt.Errorf("child entry pubkey length truncated")
	}
	pkLen := int(data[offset])
	offset++
	if offset+pkLen > len(data) {
		return nil, fmt.Errorf("child entry pubkey truncated")
	}
	entry.PubKey = make([]byte, pkLen)
	copy(entry.PubKey, data[offset:offset+pkLen])
	offset += pkLen

	// Hardened
	if offset+1 > len(data) {
		return nil, fmt.Errorf("child entry hardened flag truncated")
	}
	entry.Hardened = data[offset] != 0

	return entry, nil
}
