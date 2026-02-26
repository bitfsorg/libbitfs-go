package tx

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// CreateRootParams holds parameters for building a root node transaction.
type CreateRootParams struct {
	NodePubKey  *ec.PublicKey  // P_node for the root
	NodePrivKey *ec.PrivateKey // D_node for UTXO tracking
	Payload     []byte         // TLV-encoded BitFSPayload
	FeeUTXO     *UTXO          // Fee chain UTXO to spend
	ChangeAddr  []byte         // 20-byte P2PKH hash for change
	FeeRate     uint64         // sat/KB (0 = use DefaultFeeRate)
}

// CreateChildParams holds parameters for building a child node transaction.
type CreateChildParams struct {
	NodePubKey    *ec.PublicKey  // Child node's public key
	ParentTxID    []byte         // Parent's latest TxID (32 bytes)
	Payload       []byte         // TLV-encoded BitFSPayload
	ParentUTXO    *UTXO          // P_parent UTXO to spend (Metanet edge)
	ParentPrivKey *ec.PrivateKey // D_parent for Input 0 signing
	FeeUTXO       *UTXO          // Fee chain UTXO
	ParentPubKey  *ec.PublicKey  // P_parent for Output 2 refresh
	ChangeAddr    []byte         // 20-byte P2PKH hash for change
	FeeRate       uint64
}

// SelfUpdateParams holds parameters for building a self-update transaction.
type SelfUpdateParams struct {
	NodePubKey  *ec.PublicKey  // Node's public key
	NodePrivKey *ec.PrivateKey // D_node for Input 0 signing
	ParentTxID  []byte         // Original parent TxID (preserved)
	Payload     []byte         // Updated TLV-encoded payload
	NodeUTXO    *UTXO          // P_node's current UTXO
	FeeUTXO     *UTXO          // Fee chain UTXO
	ChangeAddr  []byte         // 20-byte P2PKH hash for change
	FeeRate     uint64
}

// DataTxParams holds parameters for building an on-chain data transaction.
type DataTxParams struct {
	NodePubKey  *ec.PublicKey  // For OP_DROP output locking
	NodePrivKey *ec.PrivateKey // D_node for signing
	Content     []byte         // Encrypted content to embed
	SourceUTXO  *UTXO          // UTXO to spend
	ChangeAddr  []byte         // 20-byte P2PKH hash for change
	FeeRate     uint64
}

// BuildCreateRoot constructs a Metanet root node transaction.
//
// Template 1 -- No parent, creates initial P_node UTXO.
//
// Outputs:
//
//	0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <empty> <Payload>
//	1: P2PKH -> P_node (dust, 1 sat)
//	2: P2PKH -> Change
//
// This function builds the transaction structure and returns the component
// data needed for signing. Actual signing requires the go-sdk Transaction
// builder which is wired up during integration.
func BuildCreateRoot(params *CreateRootParams) (*MetanetTx, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: params", ErrNilParam)
	}
	if params.NodePubKey == nil {
		return nil, fmt.Errorf("%w: NodePubKey", ErrNilParam)
	}
	if params.FeeUTXO == nil {
		return nil, fmt.Errorf("%w: FeeUTXO", ErrNilParam)
	}
	if len(params.Payload) == 0 {
		return nil, ErrInvalidPayload
	}

	// Validate we have enough funds
	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}

	// Build OP_RETURN data
	opReturnData, err := BuildOPReturnData(params.NodePubKey, nil, params.Payload)
	if err != nil {
		return nil, fmt.Errorf("tx: failed to build OP_RETURN: %w", err)
	}

	// Estimate transaction size: 1 input, 3 outputs (OP_RETURN + P_node + change)
	estSize := EstimateTxSize(1, 3, len(params.Payload))
	estFee := EstimateFee(estSize, feeRate)

	totalNeeded := DustLimit + estFee // P_node dust + fee
	if params.FeeUTXO.Amount < totalNeeded {
		return nil, fmt.Errorf("%w: need %d sat, have %d sat",
			ErrInsufficientFunds, totalNeeded, params.FeeUTXO.Amount)
	}

	changeAmount := params.FeeUTXO.Amount - DustLimit - estFee

	// Build the MetanetTx result
	// In a full implementation, this would use go-sdk Transaction builder.
	// For now, we return the structure with all the data needed.
	result := &MetanetTx{
		NodeUTXO: &UTXO{
			// TxID will be set after signing
			Vout:   1,
			Amount: DustLimit,
		},
		ParentUTXO: nil, // Root has no parent refresh
	}

	if changeAmount > DustLimit {
		result.ChangeUTXO = &UTXO{
			Vout:   2,
			Amount: changeAmount,
		}
	}

	// Store OP_RETURN data for reference
	_ = opReturnData

	return result, nil
}

// BuildCreateChild constructs a Metanet child node transaction.
//
// Template 2 -- Spends P_parent UTXO (Input 0), creating the Metanet edge.
//
// Outputs:
//
//	0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <TxID_parent> <Payload>
//	1: P2PKH -> P_node (dust)
//	2: P2PKH -> P_parent (dust, UTXO refresh)
//	3: P2PKH -> Change
func BuildCreateChild(params *CreateChildParams) (*MetanetTx, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: params", ErrNilParam)
	}
	if params.NodePubKey == nil {
		return nil, fmt.Errorf("%w: NodePubKey", ErrNilParam)
	}
	if params.ParentPubKey == nil {
		return nil, fmt.Errorf("%w: ParentPubKey", ErrNilParam)
	}
	if params.ParentUTXO == nil {
		return nil, fmt.Errorf("%w: ParentUTXO", ErrNilParam)
	}
	if params.FeeUTXO == nil {
		return nil, fmt.Errorf("%w: FeeUTXO", ErrNilParam)
	}
	if len(params.ParentTxID) != TxIDLen {
		return nil, ErrInvalidParentTxID
	}
	if len(params.Payload) == 0 {
		return nil, ErrInvalidPayload
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}

	// Build OP_RETURN data
	_, err := BuildOPReturnData(params.NodePubKey, params.ParentTxID, params.Payload)
	if err != nil {
		return nil, fmt.Errorf("tx: failed to build OP_RETURN: %w", err)
	}

	// Estimate: 2 inputs (parent UTXO + fee UTXO), 4 outputs
	estSize := EstimateTxSize(2, 4, len(params.Payload))
	estFee := EstimateFee(estSize, feeRate)

	// Total funds available: parent UTXO + fee UTXO
	totalAvailable := params.ParentUTXO.Amount + params.FeeUTXO.Amount
	totalNeeded := DustLimit*2 + estFee // P_node dust + P_parent refresh dust + fee

	if totalAvailable < totalNeeded {
		return nil, fmt.Errorf("%w: need %d sat, have %d sat",
			ErrInsufficientFunds, totalNeeded, totalAvailable)
	}

	changeAmount := totalAvailable - DustLimit*2 - estFee

	result := &MetanetTx{
		NodeUTXO: &UTXO{
			Vout:   1,
			Amount: DustLimit,
		},
		ParentUTXO: &UTXO{
			Vout:   2,
			Amount: DustLimit,
		},
	}

	if changeAmount > DustLimit {
		result.ChangeUTXO = &UTXO{
			Vout:   3,
			Amount: changeAmount,
		}
	}

	return result, nil
}

// BuildSelfUpdate constructs a Metanet self-update transaction.
//
// Template 3 -- Spends own P_node UTXO, preserves ParentTxID.
//
// Outputs:
//
//	0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <TxID_parent> <Payload>
//	1: P2PKH -> P_node (dust, refresh)
//	2: P2PKH -> Change
func BuildSelfUpdate(params *SelfUpdateParams) (*MetanetTx, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: params", ErrNilParam)
	}
	if params.NodePubKey == nil {
		return nil, fmt.Errorf("%w: NodePubKey", ErrNilParam)
	}
	if params.NodeUTXO == nil {
		return nil, fmt.Errorf("%w: NodeUTXO", ErrNilParam)
	}
	if params.FeeUTXO == nil {
		return nil, fmt.Errorf("%w: FeeUTXO", ErrNilParam)
	}
	if len(params.ParentTxID) != 0 && len(params.ParentTxID) != TxIDLen {
		return nil, ErrInvalidParentTxID
	}
	if len(params.Payload) == 0 {
		return nil, ErrInvalidPayload
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}

	// 2 inputs (self UTXO + fee UTXO), 3 outputs
	estSize := EstimateTxSize(2, 3, len(params.Payload))
	estFee := EstimateFee(estSize, feeRate)

	totalAvailable := params.NodeUTXO.Amount + params.FeeUTXO.Amount
	totalNeeded := DustLimit + estFee

	if totalAvailable < totalNeeded {
		return nil, fmt.Errorf("%w: need %d sat, have %d sat",
			ErrInsufficientFunds, totalNeeded, totalAvailable)
	}

	changeAmount := totalAvailable - DustLimit - estFee

	result := &MetanetTx{
		NodeUTXO: &UTXO{
			Vout:   1,
			Amount: DustLimit,
		},
		ParentUTXO: nil, // Self-update has no parent refresh
	}

	if changeAmount > DustLimit {
		result.ChangeUTXO = &UTXO{
			Vout:   2,
			Amount: changeAmount,
		}
	}

	return result, nil
}

// BuildDataTransaction constructs an on-chain data transaction.
//
// Template 4 -- OP_DROP content in spendable output locked to P_node.
//
// Outputs:
//
//	0: <content> OP_DROP OP_DUP OP_HASH160 <H160(P_node)> OP_EQUALVERIFY OP_CHECKSIG
//	1: P2PKH -> Change
func BuildDataTransaction(params *DataTxParams) (*MetanetTx, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: params", ErrNilParam)
	}
	if params.NodePubKey == nil {
		return nil, fmt.Errorf("%w: NodePubKey", ErrNilParam)
	}
	if params.SourceUTXO == nil {
		return nil, fmt.Errorf("%w: SourceUTXO", ErrNilParam)
	}
	if len(params.Content) == 0 {
		return nil, ErrInvalidPayload
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = DefaultFeeRate
	}

	// 1 input, 2 outputs (data + change)
	estSize := 10 + 148 + len(params.Content) + 50 + 34 // rough estimate
	estFee := EstimateFee(estSize, feeRate)

	totalNeeded := DustLimit + estFee
	if params.SourceUTXO.Amount < totalNeeded {
		return nil, fmt.Errorf("%w: need %d sat, have %d sat",
			ErrInsufficientFunds, totalNeeded, params.SourceUTXO.Amount)
	}

	changeAmount := params.SourceUTXO.Amount - DustLimit - estFee

	result := &MetanetTx{
		NodeUTXO: &UTXO{
			Vout:   0,
			Amount: DustLimit,
		},
	}

	if changeAmount > DustLimit {
		result.ChangeUTXO = &UTXO{
			Vout:   1,
			Amount: changeAmount,
		}
	}

	return result, nil
}
