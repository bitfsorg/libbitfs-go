package tx

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
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
// [Audit fix H-2: was a stub returning RawTx: nil. Now fully implemented.]
//
// Template 4 -- OP_DROP content in spendable output locked to P_node.
//
// Outputs:
//
//	0: <content> OP_DROP OP_DUP OP_HASH160 <H160(P_node)> OP_EQUALVERIFY OP_CHECKSIG
//	1: P2PKH -> Change (if above dust)
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

	// Build the go-sdk Transaction.
	sdkTx := transaction.NewTransaction()

	// Add the source UTXO as input.
	utxoHash, err := chainhash.NewHash(params.SourceUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid SourceUTXO TxID: %w", ErrScriptBuild, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       utxoHash,
		SourceTxOutIndex: params.SourceUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Output 0: <content> OP_DROP OP_DUP OP_HASH160 <H160(P_node)> OP_EQUALVERIFY OP_CHECKSIG
	dataScript, err := buildOPDropP2PKHScript(params.Content, params.NodePubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: OP_DROP script: %w", ErrScriptBuild, err)
	}
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: dataScript,
	})

	nodeScriptBytes := []byte(*dataScript)

	result := &MetanetTx{
		NodeUTXO: &UTXO{
			Vout:         0,
			Amount:       DustLimit,
			ScriptPubKey: nodeScriptBytes,
		},
	}

	// Output 1: P2PKH change (if above dust).
	if changeAmount > DustLimit {
		var changeLockScript *script.Script
		if len(params.ChangeAddr) == 20 {
			addr, addrErr := script.NewAddressFromPublicKeyHash(params.ChangeAddr, true)
			if addrErr != nil {
				return nil, fmt.Errorf("%w: change address: %w", ErrScriptBuild, addrErr)
			}
			changeLockScript, err = p2pkh.Lock(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: change lock: %w", ErrScriptBuild, err)
			}
		} else {
			// Fallback: send change to the node key.
			changeLockScript, err = func() (*script.Script, error) {
				bs, e := BuildP2PKHScript(params.NodePubKey)
				if e != nil {
					return nil, e
				}
				return script.NewFromBytes(bs), nil
			}()
			if err != nil {
				return nil, fmt.Errorf("%w: fallback change script: %w", ErrScriptBuild, err)
			}
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      changeAmount,
			LockingScript: changeLockScript,
		})
		result.ChangeUTXO = &UTXO{
			Vout:         1,
			Amount:       changeAmount,
			ScriptPubKey: []byte(*changeLockScript),
		}
	}

	// Serialize the unsigned transaction.
	result.RawTx = sdkTx.Bytes()

	return result, nil
}

// buildOPDropP2PKHScript builds: <content> OP_DROP OP_DUP OP_HASH160 <H160(P_node)> OP_EQUALVERIFY OP_CHECKSIG
func buildOPDropP2PKHScript(content []byte, pubKey *ec.PublicKey) (*script.Script, error) {
	// Get the standard P2PKH script for the pubkey.
	p2pkhBytes, err := BuildP2PKHScript(pubKey)
	if err != nil {
		return nil, err
	}

	s := &script.Script{}
	// Push content data.
	if err := s.AppendPushData(content); err != nil {
		return nil, fmt.Errorf("push content: %w", err)
	}
	// OP_DROP
	*s = append(*s, script.OpDROP)
	// Append the standard P2PKH opcodes (OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG).
	*s = append(*s, p2pkhBytes...)

	return s, nil
}
