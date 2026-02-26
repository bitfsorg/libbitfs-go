package tx

import (
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// DataTxParams holds parameters for building an on-chain data transaction.
type DataTxParams struct {
	NodePubKey  *ec.PublicKey  // For OP_DROP output locking
	NodePrivKey *ec.PrivateKey // D_node for signing
	Content     []byte         // Encrypted content to embed
	SourceUTXO  *UTXO          // UTXO to spend
	ChangeAddr  []byte         // 20-byte P2PKH hash for change
	FeeRate     uint64
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
