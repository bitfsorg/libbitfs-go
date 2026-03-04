package tx

import (
	"bytes"
	"fmt"
	"math"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

// metaFlagBytes is the internal Metanet protocol flag: "meta" in ASCII.
// It is never exposed directly to prevent external mutation.
var metaFlagBytes = [4]byte{0x6d, 0x65, 0x74, 0x61}

// MetaFlagBytes returns a copy of the Metanet protocol flag bytes ("meta").
// A fresh copy is returned each call to prevent callers from mutating the
// protocol constant. [Audit fix M-6]
func MetaFlagBytes() []byte {
	b := metaFlagBytes
	return b[:]
}

const (
	// MetaFlag is the string representation of the Metanet flag.
	MetaFlag = "meta"

	// DustLimit is the minimum P2PKH output value in satoshis.
	// BSV has removed the dust limit; 1 sat is the protocol minimum.
	DustLimit = uint64(1)

	// DefaultFeeRate is the fallback fee rate in sat/KB when callers pass 0.
	// 100 sat/KB == 0.1 sat/byte.
	DefaultFeeRate = uint64(100)

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
		MetaFlagBytes(), // pushdata[0]: "meta"
		pNodeBytes,      // pushdata[1]: P_node
		parentTxID,      // pushdata[2]: TxID_parent (empty for root)
		payload,         // pushdata[3]: TLV payload
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
	if !bytes.Equal(pushes[0], MetaFlagBytes()) {
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
	NodeVout   uint32 // Output index of the following P2PKH (0 for deletes)
	IsDelete   bool   // True if this is an OpDelete (no P2PKH refresh output)
}

// ParseTxNodeOps scans all outputs of a transaction and extracts Metanet
// node operations. Each OP_RETURN with MetaFlag is paired with the following
// P2PKH output if present. An OP_RETURN followed by another OP_RETURN, a
// non-P2PKH output, or at the end of the output list is treated as an
// OpDelete (no P2PKH refresh). [Audit fix M-1]
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

		// Check if the next output is a P2PKH dust output (node refresh).
		// Node refresh outputs are always exactly DustLimit (1 sat) P2PKH.
		// Change outputs have value > DustLimit and are not paired.
		// If the next output is not a dust P2PKH, treat this as a delete.
		if i+1 < len(outputs) && isDustP2PKHOutput(outputs[i+1]) {
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
		} else {
			// OpDelete: OP_RETURN with no following P2PKH.
			op := ParsedNodeOp{
				PNode:      pNode,
				ParentTxID: parentTxID,
				Payload:    payload,
				Vout:       uint32(i),
				NodeVout:   0,
				IsDelete:   true,
			}
			ops = append(ops, op)
		}
	}

	return ops, nil
}

// isDustP2PKHOutput returns true if the output is a standard P2PKH output
// with exactly DustLimit (1 sat) value -- the signature of a node refresh output.
// Change outputs have value > DustLimit and are never matched.
func isDustP2PKHOutput(out TxOutput) bool {
	if out.Value != DustLimit {
		return false
	}
	s := out.ScriptPubKey
	if len(s) != 25 {
		return false
	}
	return s[0] == script.OpDUP &&
		s[1] == script.OpHASH160 &&
		s[2] == 0x14 && // OP_DATA_20
		s[23] == script.OpEQUALVERIFY &&
		s[24] == script.OpCHECKSIG
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
	if !bytes.Equal(pushes[0], MetaFlagBytes()) {
		return nil, false
	}

	return pushes, true
}

// EstimateFee estimates the transaction fee for a given size and fee rate.
// Returns ceil(txSizeBytes * feeRate / 1000). Saturates to math.MaxUint64 on overflow.
func EstimateFee(txSizeBytes int, feeRate uint64) uint64 {
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}
	size := uint64(txSizeBytes)
	if size > math.MaxUint64/feeRate {
		return math.MaxUint64 // Saturate on overflow.
	}
	fee := size * feeRate
	// Ceiling division by 1000
	return (fee + 999) / 1000
}

// EstimateTxSize provides a rough estimate of transaction size in bytes.
// This is a simplified estimate based on typical Metanet transaction structure.
//
// numOps is the number of OP_RETURN outputs in the batch. Each OP_RETURN carries
// its own fixed overhead (MetaFlag + P_node + TxID_parent + pushdata headers).
// payloadSize is the sum of all payload bytes across all ops.
// [Audit fix M-3: account for per-op OP_RETURN overhead]
func EstimateTxSize(numInputs, numOutputs int, payloadSize int, numOps ...int) int {
	// Base: version(4) + locktime(4) + input count varint(1) + output count varint(1) = 10
	// Per input: prevhash(32) + previndex(4) + scriptlen varint(1) + script(~107 for P2PKH) + sequence(4) = 148
	// Per output: value(8) + scriptlen varint(1) + script(~25 for P2PKH) = 34
	// Per OP_RETURN output: value(8) + scriptlen varint(3) + OP_FALSE(1) + OP_RETURN(1) + pushdata headers = 13
	//   + MetaFlag(5) + P_node(34) + TxID_parent(33) + pushdata overhead(~4) = ~89 fixed per OP_RETURN
	// payload bytes are shared across all OP_RETURN outputs.

	ops := 1
	if len(numOps) > 0 && numOps[0] > 1 {
		ops = numOps[0]
	}

	base := 10
	inputs := numInputs * 148
	outputs := numOutputs * 34
	// Fixed per-OP_RETURN overhead: 13 (output header) + 5 (MetaFlag push) + 34 (P_node push)
	//   + 33 (TxID_parent push) + 4 (pushdata headers) = 89 bytes
	perOpReturnFixed := 89
	opReturnTotal := ops*perOpReturnFixed + payloadSize

	return base + inputs + outputs + opReturnTotal
}
