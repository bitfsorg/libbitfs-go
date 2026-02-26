package tx

import (
	"bytes"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
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
	// BSV has removed the dust limit; 1 sat is the protocol minimum.
	DustLimit = uint64(1)

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
//	pushdata[3]: Payload     (variable length, TLV-encoded)
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
		MetaFlagBytes, // pushdata[0]: "meta"
		pNodeBytes,    // pushdata[1]: P_node
		parentTxID,    // pushdata[2]: TxID_parent (empty for root)
		payload,       // pushdata[3]: TLV payload
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

// TxOutput is a minimal representation of a transaction output for parsing.
type TxOutput struct {
	Value        uint64
	ScriptPubKey []byte
}

// ParsedNodeOp represents one parsed Metanet node operation from a TX.
type ParsedNodeOp struct {
	PNode      []byte // Compressed public key (33 bytes)
	ParentTxID []byte // 0 or 32 bytes
	Payload    []byte
	Vout       uint32 // Output index of the OP_RETURN
	NodeVout   uint32 // Output index of the following P2PKH
}

// ParseTxNodeOps scans all outputs of a transaction and extracts Metanet
// node operations. Each OP_RETURN with MetaFlag is paired with the following
// P2PKH output.
//
// This supports the multi-OP_RETURN format used by MutationBatch where a
// single TX contains multiple node operations.
func ParseTxNodeOps(outputs []TxOutput) ([]ParsedNodeOp, error) {
	var ops []ParsedNodeOp

	for i := 0; i < len(outputs); i++ {
		out := outputs[i]

		// Check if this output is an OP_RETURN with Metanet flag.
		pushes, ok := parseMetanetOPReturn(out.ScriptPubKey)
		if !ok {
			continue
		}

		// Parse the push data.
		pNode, parentTxID, payload, err := ParseOPReturnData(pushes)
		if err != nil {
			// Skip malformed OP_RETURN outputs.
			continue
		}

		// The next output should be the P2PKH dust output.
		if i+1 >= len(outputs) {
			return nil, fmt.Errorf("%w: OP_RETURN at output %d has no following P2PKH output",
				ErrInvalidOPReturn, i)
		}

		nodeVout := uint32(i + 1)

		op := ParsedNodeOp{
			PNode:      pNode,
			ParentTxID: parentTxID,
			Payload:    payload,
			Vout:       uint32(i),
			NodeVout:   nodeVout,
		}
		ops = append(ops, op)

		// Skip the P2PKH output we just paired.
		i++
	}

	return ops, nil
}

// parseMetanetOPReturn checks if a script is an OP_FALSE OP_RETURN script
// with Metanet flag and returns the push data elements if so.
func parseMetanetOPReturn(scriptBytes []byte) ([][]byte, bool) {
	if len(scriptBytes) < 6 {
		return nil, false
	}

	// Check OP_FALSE (0x00) OP_RETURN (0x6a) prefix.
	if scriptBytes[0] != script.Op0 || scriptBytes[1] != script.OpRETURN {
		return nil, false
	}

	// Parse the push data portion after OP_0 OP_RETURN.
	// The remaining bytes are standard push data opcodes.
	afterReturn := scriptBytes[2:]
	pushScript := script.NewFromBytes(afterReturn)
	chunks, err := pushScript.Chunks()
	if err != nil || len(chunks) < 4 {
		return nil, false
	}

	pushes := make([][]byte, 4)
	for j := 0; j < 4; j++ {
		pushes[j] = chunks[j].Data
	}

	// Verify MetaFlag.
	if !bytes.Equal(pushes[0], MetaFlagBytes) {
		return nil, false
	}

	return pushes, true
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
