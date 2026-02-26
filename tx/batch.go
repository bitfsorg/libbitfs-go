package tx

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// BatchOpType identifies the kind of operation in a batch.
type BatchOpType int

const (
	OpCreate     BatchOpType = iota // Create a new child node (OP_RETURN + P2PKH refresh)
	OpUpdate                        // Update existing node (OP_RETURN + P2PKH refresh)
	OpDelete                        // Delete node (OP_RETURN only, no P2PKH — UTXO dies)
	OpCreateRoot                    // Create root node (no input UTXO, OP_RETURN + P2PKH refresh)
)

// Aliases for backward compatibility during migration. Deprecated.
const (
	BatchOpParentUpdate = OpUpdate
	BatchOpChildCreate  = OpCreate
	BatchOpChildDelete  = OpDelete
	BatchOpNodeUpdate   = OpUpdate
)

// BatchNodeOp represents one node operation within a MutationBatch.
type BatchNodeOp struct {
	Type       BatchOpType
	PubKey     *ec.PublicKey  // Node's public key
	ParentTxID []byte         // Parent's TxID (for OP_RETURN field 2)
	Payload    []byte         // Serialized TLV payload
	InputUTXO  *UTXO          // UTXO to spend (nil for new creates — no existing UTXO)
	PrivateKey *ec.PrivateKey // Signing key for this node's input
}

// MutationBatch collects multiple node operations into a single TX.
type MutationBatch struct {
	ops        []BatchNodeOp
	feeInputs  []*UTXO
	changeAddr []byte
	feeRate    uint64
}

// BatchResult holds the built transaction and per-op output mapping.
type BatchResult struct {
	RawTx      []byte            // Serialized unsigned TX
	TxID       []byte            // TX hash (computed after all outputs known)
	NodeOps    []BatchNodeResult // One per op, in order
	ChangeUTXO *UTXO             // Change output (nil if dust)
}

// BatchNodeResult tracks the outputs for one operation.
type BatchNodeResult struct {
	OpReturnVout uint32 // Output index of the OP_RETURN
	NodeVout     uint32 // Output index of the P2PKH dust output
	NodeUTXO     *UTXO  // The produced P_node UTXO
}

// NewMutationBatch creates a new empty MutationBatch.
func NewMutationBatch() *MutationBatch {
	return &MutationBatch{
		feeRate: DefaultFeeRate,
	}
}

// AddNodeOp appends one node operation to the batch.
func (b *MutationBatch) AddNodeOp(op BatchNodeOp) {
	b.ops = append(b.ops, op)
}

// AddFeeInput adds a UTXO to be used as fee input.
func (b *MutationBatch) AddFeeInput(utxo *UTXO) {
	b.feeInputs = append(b.feeInputs, utxo)
}

// SetChange sets the 20-byte P2PKH hash for the change output.
func (b *MutationBatch) SetChange(addr []byte) {
	b.changeAddr = addr
}

// SetFeeRate sets the fee rate in sat/KB.
func (b *MutationBatch) SetFeeRate(rate uint64) {
	b.feeRate = rate
}

// Build constructs the transaction.
//
// Output layout:
//
//	For each op:
//	  [i]   OP_RETURN [MetaFlag, P_node, ParentTxID, Payload]
//	  [i+1] P2PKH -> P_node (1 sat)
//	[last] P2PKH -> Change
//
// Inputs:
//
//	One input per op that has InputUTXO (spending existing P_node UTXO)
//	Fee inputs at the end
func (b *MutationBatch) Build() (*BatchResult, error) {
	if len(b.ops) == 0 {
		return nil, fmt.Errorf("%w: no operations in batch", ErrInvalidPayload)
	}
	if len(b.feeInputs) == 0 {
		return nil, fmt.Errorf("%w: no fee inputs", ErrNilParam)
	}

	// Validate all ops.
	for i, op := range b.ops {
		if op.PubKey == nil {
			return nil, fmt.Errorf("%w: op[%d] PubKey", ErrNilParam, i)
		}
		if len(op.Payload) == 0 {
			return nil, fmt.Errorf("%w: op[%d] has empty payload", ErrInvalidPayload, i)
		}
		if len(op.ParentTxID) != 0 && len(op.ParentTxID) != TxIDLen {
			return nil, fmt.Errorf("%w: op[%d] parent TxID length %d", ErrInvalidParentTxID, i, len(op.ParentTxID))
		}
		// OpCreateRoot: no InputUTXO or PrivateKey needed.
		// All other types with InputUTXO must have PrivateKey.
		if op.Type != OpCreateRoot && op.InputUTXO != nil && op.PrivateKey == nil {
			return nil, fmt.Errorf("%w: op[%d] has InputUTXO but nil PrivateKey", ErrNilParam, i)
		}
	}

	// Validate fee inputs.
	for i, fi := range b.feeInputs {
		if fi == nil {
			return nil, fmt.Errorf("%w: feeInput[%d]", ErrNilParam, i)
		}
	}

	feeRate := b.feeRate
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}

	// Dedup: track unique (TxID, Vout) pairs for node inputs.
	type utxoKey struct {
		txid string
		vout uint32
	}
	seenInputs := make(map[utxoKey]bool)
	numNodeInputs := 0
	for _, op := range b.ops {
		if op.InputUTXO == nil {
			continue
		}
		key := utxoKey{hex.EncodeToString(op.InputUTXO.TxID), op.InputUTXO.Vout}
		if !seenInputs[key] {
			seenInputs[key] = true
			numNodeInputs++
		}
	}
	numInputs := numNodeInputs + len(b.feeInputs)
	// Count outputs: 2 per non-delete op (OP_RETURN + P2PKH), 1 per delete op (OP_RETURN only), + 1 change.
	numDeleteOps := 0
	for _, op := range b.ops {
		if op.Type == OpDelete {
			numDeleteOps++
		}
	}
	numOutputs := (len(b.ops)-numDeleteOps)*2 + numDeleteOps + 1

	// Total payload size for fee estimation.
	totalPayloadSize := 0
	for _, op := range b.ops {
		totalPayloadSize += len(op.Payload)
	}

	// Estimate fee. Use EstimateTxSize for the base and add extra for additional OP_RETURN outputs.
	// Each additional op beyond the first adds one OP_RETURN output overhead.
	baseEstimate := EstimateTxSize(numInputs, numOutputs, totalPayloadSize)
	estFee := EstimateFee(baseEstimate, feeRate)

	// Calculate total available funds (deduped node inputs + fee inputs).
	totalAvailable := uint64(0)
	seenFunds := make(map[utxoKey]bool)
	for _, op := range b.ops {
		if op.InputUTXO == nil {
			continue
		}
		key := utxoKey{hex.EncodeToString(op.InputUTXO.TxID), op.InputUTXO.Vout}
		if !seenFunds[key] {
			seenFunds[key] = true
			totalAvailable += op.InputUTXO.Amount
		}
	}
	for _, fi := range b.feeInputs {
		totalAvailable += fi.Amount
	}

	// Total needed: DustLimit per non-delete op + fee.
	totalDust := uint64(len(b.ops)-numDeleteOps) * DustLimit
	totalNeeded := totalDust + estFee

	if totalAvailable < totalNeeded {
		return nil, fmt.Errorf("%w: need %d sat, have %d sat",
			ErrInsufficientFunds, totalNeeded, totalAvailable)
	}

	// Build the go-sdk Transaction.
	sdkTx := transaction.NewTransaction()

	// --- Add inputs ---

	// First: deduped node UTXO inputs (ops with existing UTXOs).
	addedInputs := make(map[utxoKey]bool)
	for _, op := range b.ops {
		if op.InputUTXO == nil {
			continue
		}
		key := utxoKey{hex.EncodeToString(op.InputUTXO.TxID), op.InputUTXO.Vout}
		if addedInputs[key] {
			continue // skip duplicate
		}
		addedInputs[key] = true
		utxoHash, err := chainhash.NewHash(op.InputUTXO.TxID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid UTXO TxID: %w", ErrScriptBuild, err)
		}
		sdkTx.AddInput(&transaction.TransactionInput{
			SourceTXID:       utxoHash,
			SourceTxOutIndex: op.InputUTXO.Vout,
			SequenceNumber:   transaction.DefaultSequenceNumber,
		})
	}

	// Then: fee inputs.
	for _, fi := range b.feeInputs {
		feeHash, err := chainhash.NewHash(fi.TxID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid fee UTXO TxID: %w", ErrScriptBuild, err)
		}
		sdkTx.AddInput(&transaction.TransactionInput{
			SourceTXID:       feeHash,
			SourceTxOutIndex: fi.Vout,
			SequenceNumber:   transaction.DefaultSequenceNumber,
		})
	}

	// --- Add outputs ---

	nodeResults := make([]BatchNodeResult, len(b.ops))
	vout := uint32(0)

	for i, op := range b.ops {
		// OP_RETURN output.
		opReturnData, err := BuildOPReturnData(op.PubKey, op.ParentTxID, op.Payload)
		if err != nil {
			return nil, fmt.Errorf("tx: op[%d] failed to build OP_RETURN: %w", i, err)
		}
		opReturnScript, err := buildOPReturnScript(opReturnData)
		if err != nil {
			return nil, fmt.Errorf("tx: op[%d] failed to build OP_RETURN script: %w", i, err)
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      0,
			LockingScript: opReturnScript,
		})
		nodeResults[i].OpReturnVout = vout
		vout++

		// OpDelete: no P2PKH output — node UTXO dies.
		if op.Type == OpDelete {
			nodeResults[i].NodeUTXO = nil
			continue
		}

		// P2PKH dust output for this node.
		nodeLockScript, err := BuildP2PKHScript(op.PubKey)
		if err != nil {
			return nil, fmt.Errorf("tx: op[%d] failed to build P2PKH script: %w", i, err)
		}
		nodeScript := script.NewFromBytes(nodeLockScript)
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      DustLimit,
			LockingScript: nodeScript,
		})
		nodeResults[i].NodeVout = vout
		nodeResults[i].NodeUTXO = &UTXO{
			Vout:         vout,
			Amount:       DustLimit,
			ScriptPubKey: nodeLockScript,
		}
		vout++
	}

	// Change output.
	changeAmount := totalAvailable - totalDust - estFee
	var changeUTXO *UTXO

	if changeAmount > DustLimit {
		var changeLockScript *script.Script
		if len(b.changeAddr) == 20 {
			addr, err := script.NewAddressFromPublicKeyHash(b.changeAddr, true)
			if err != nil {
				return nil, fmt.Errorf("%w: change address: %w", ErrScriptBuild, err)
			}
			changeLockScript, err = p2pkh.Lock(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: change lock script: %w", ErrScriptBuild, err)
			}
		} else {
			// Fall back to first op's node key as change destination.
			firstNodeScript, err := BuildP2PKHScript(b.ops[0].PubKey)
			if err != nil {
				return nil, fmt.Errorf("%w: fallback change script: %w", ErrScriptBuild, err)
			}
			changeLockScript = script.NewFromBytes(firstNodeScript)
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      changeAmount,
			LockingScript: changeLockScript,
		})
		changeUTXO = &UTXO{
			Vout:   vout,
			Amount: changeAmount,
		}
	}

	// Serialize the unsigned transaction.
	rawTx := sdkTx.Bytes()

	return &BatchResult{
		RawTx:      rawTx,
		NodeOps:    nodeResults,
		ChangeUTXO: changeUTXO,
	}, nil
}
