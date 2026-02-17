package tx

import (
	"bytes"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Metanet protocol constants.
var (
	// MetaFlagBytes is the Metanet protocol flag: "meta" in ASCII.
	MetaFlagBytes = []byte{0x6d, 0x65, 0x74, 0x61}
)

const (
	// MetaFlag is the string representation of the Metanet flag.
	MetaFlag = "meta"

	// DustLimit is the minimum P2PKH output value in satoshis.
	DustLimit = uint64(546)

	// DefaultFeeRate is the default fee rate in sat/KB.
	DefaultFeeRate = uint64(1)

	// CompressedPubKeyLen is the length of a compressed public key.
	CompressedPubKeyLen = 33

	// TxIDLen is the length of a transaction ID.
	TxIDLen = 32
)

// BuildOPReturnData constructs the OP_RETURN data pushes for a Metanet node.
//
// Layout:
//
//	pushdata[0]: MetaFlag    (4 bytes, "meta")
//	pushdata[1]: P_node      (33 bytes, compressed pubkey)
//	pushdata[2]: TxID_parent (0 bytes for root, 32 bytes otherwise)
//	pushdata[3]: Payload     (variable length, Protobuf)
//
// Returns the data pushes as a slice of byte slices.
func BuildOPReturnData(pNode *ec.PublicKey, parentTxID []byte, payload []byte) ([][]byte, error) {
	if pNode == nil {
		return nil, fmt.Errorf("%w: P_node public key", ErrNilParam)
	}
	if len(payload) == 0 {
		return nil, ErrInvalidPayload
	}
	if len(parentTxID) != 0 && len(parentTxID) != TxIDLen {
		return nil, ErrInvalidParentTxID
	}

	pNodeBytes := pNode.Compressed()
	if len(pNodeBytes) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: invalid compressed public key length", ErrNilParam)
	}

	pushes := [][]byte{
		MetaFlagBytes,  // pushdata[0]: "meta"
		pNodeBytes,     // pushdata[1]: P_node
		parentTxID,     // pushdata[2]: TxID_parent (empty for root)
		payload,        // pushdata[3]: Protobuf payload
	}

	return pushes, nil
}

// ParseOPReturnData extracts Metanet fields from OP_RETURN data pushes.
// Returns (P_node compressed bytes, TxID_parent, payload bytes, error).
func ParseOPReturnData(pushes [][]byte) (pNode []byte, parentTxID []byte, payload []byte, err error) {
	if len(pushes) < 4 {
		return nil, nil, nil, fmt.Errorf("%w: expected 4 data pushes, got %d", ErrInvalidOPReturn, len(pushes))
	}

	// Verify MetaFlag
	if !bytes.Equal(pushes[0], MetaFlagBytes) {
		return nil, nil, nil, fmt.Errorf("%w: missing Metanet flag", ErrNotMetanetTx)
	}

	// P_node (33 bytes compressed pubkey)
	pNode = pushes[1]
	if len(pNode) != CompressedPubKeyLen {
		return nil, nil, nil, fmt.Errorf("%w: P_node must be %d bytes, got %d", ErrInvalidOPReturn, CompressedPubKeyLen, len(pNode))
	}

	// TxID_parent (0 or 32 bytes)
	parentTxID = pushes[2]
	if len(parentTxID) != 0 && len(parentTxID) != TxIDLen {
		return nil, nil, nil, fmt.Errorf("%w: parent TxID must be 0 or %d bytes, got %d", ErrInvalidOPReturn, TxIDLen, len(parentTxID))
	}

	// Payload
	payload = pushes[3]
	if len(payload) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: payload is empty", ErrInvalidOPReturn)
	}

	return pNode, parentTxID, payload, nil
}

// EstimateFee estimates the transaction fee for a given size and fee rate.
// Returns ceil(txSizeBytes * feeRate / 1000).
func EstimateFee(txSizeBytes int, feeRate uint64) uint64 {
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}
	fee := uint64(txSizeBytes) * feeRate
	// Ceiling division by 1000
	return (fee + 999) / 1000
}

// EstimateTxSize provides a rough estimate of transaction size in bytes.
// This is a simplified estimate based on typical Metanet transaction structure.
func EstimateTxSize(numInputs, numOutputs int, payloadSize int) int {
	// Base: version(4) + locktime(4) + input count varint(1) + output count varint(1) = 10
	// Per input: prevhash(32) + previndex(4) + scriptlen varint(1) + script(~107 for P2PKH) + sequence(4) = 148
	// Per output: value(8) + scriptlen varint(1) + script(~25 for P2PKH) = 34
	// OP_RETURN output: value(8) + scriptlen varint(3) + OP_FALSE(1) + OP_RETURN(1) + pushdata = 13 + pushdata
	// pushdata: MetaFlag(5) + P_node(34) + TxID_parent(33) + payload(varies) + pushdata headers

	base := 10
	inputs := numInputs * 148
	outputs := numOutputs * 34
	opReturn := 13 + 4 + 1 + CompressedPubKeyLen + 1 + TxIDLen + 1 + payloadSize + 4 // rough

	return base + inputs + outputs + opReturn
}
