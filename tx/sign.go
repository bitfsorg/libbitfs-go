package tx

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// SignMetanetTx signs all inputs of a MetanetTx using the private keys from UTXOs.
//
// If mtx.RawTx contains unsigned transaction bytes, the function parses them
// into a go-sdk Transaction, attaches source output info and P2PKH unlockers
// from the provided UTXOs, signs all inputs, and returns the signed hex.
//
// The utxos slice must have the same length as the number of transaction inputs,
// and each UTXO must carry a non-nil PrivateKey and ScriptPubKey. The UTXOs are
// matched to inputs by position (utxos[i] signs input i).
func SignMetanetTx(mtx *MetanetTx, utxos []*UTXO) (string, error) {
	if mtx == nil {
		return "", fmt.Errorf("%w: MetanetTx", ErrNilParam)
	}
	if len(mtx.RawTx) == 0 {
		return "", fmt.Errorf("%w: RawTx is empty", ErrSigningFailed)
	}
	if len(utxos) == 0 {
		return "", fmt.Errorf("%w: utxos", ErrNilParam)
	}

	// 1. Parse the raw unsigned tx bytes into a go-sdk Transaction.
	sdkTx, err := transaction.NewTransactionFromBytes(mtx.RawTx)
	if err != nil {
		return "", fmt.Errorf("%w: failed to parse raw tx: %w", ErrSigningFailed, err)
	}

	// 2. Validate that UTXO count matches input count.
	if len(utxos) != len(sdkTx.Inputs) {
		return "", fmt.Errorf("%w: have %d UTXOs but tx has %d inputs",
			ErrSigningFailed, len(utxos), len(sdkTx.Inputs))
	}

	// 3. For each input, attach source output info and P2PKH unlocker.
	for i, utxo := range utxos {
		if utxo == nil {
			return "", fmt.Errorf("%w: utxo[%d] is nil", ErrNilParam, i)
		}
		if utxo.PrivateKey == nil {
			return "", fmt.Errorf("%w: utxo[%d] has nil PrivateKey", ErrSigningFailed, i)
		}
		if len(utxo.ScriptPubKey) == 0 {
			return "", fmt.Errorf("%w: utxo[%d] has empty ScriptPubKey", ErrSigningFailed, i)
		}

		// Create the P2PKH unlocker from the UTXO's private key.
		unlocker, err := p2pkh.Unlock(utxo.PrivateKey, nil)
		if err != nil {
			return "", fmt.Errorf("%w: failed to create unlocker for input %d: %w",
				ErrSigningFailed, i, err)
		}

		// Attach the source output information so the sighash can be computed.
		lockingScript := script.NewFromBytes(utxo.ScriptPubKey)
		sdkTx.Inputs[i].SetSourceTxOutput(&transaction.TransactionOutput{
			Satoshis:      utxo.Amount,
			LockingScript: lockingScript,
		})

		// Attach the unlocking script template.
		sdkTx.Inputs[i].UnlockingScriptTemplate = unlocker
	}

	// 4. Sign all inputs.
	if err := sdkTx.Sign(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}

	// 5. Update the MetanetTx with signed transaction data.
	signedBytes := sdkTx.Bytes()
	mtx.RawTx = signedBytes
	mtx.TxID = sdkTx.TxID().CloneBytes()

	// Update TxIDs on the output UTXOs.
	if mtx.NodeUTXO != nil {
		mtx.NodeUTXO.TxID = mtx.TxID
	}
	if mtx.ParentUTXO != nil {
		mtx.ParentUTXO.TxID = mtx.TxID
	}
	if mtx.ChangeUTXO != nil {
		mtx.ChangeUTXO.TxID = mtx.TxID
	}

	return sdkTx.Hex(), nil
}

// BuildP2PKHScript creates a P2PKH locking script for the given public key.
// Returns the raw script bytes suitable for use as UTXO.ScriptPubKey.
func BuildP2PKHScript(pubKey *ec.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("%w: public key", ErrNilParam)
	}
	addr, err := script.NewAddressFromPublicKey(pubKey, true)
	if err != nil {
		return nil, fmt.Errorf("%w: address from pubkey: %w", ErrScriptBuild, err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: P2PKH lock script: %w", ErrScriptBuild, err)
	}
	return []byte(*lockScript), nil
}

// buildOPReturnScript creates an OP_FALSE OP_RETURN script from data pushes.
func buildOPReturnScript(pushes [][]byte) (*script.Script, error) {
	s := &script.Script{}
	// OP_FALSE OP_RETURN prefix
	*s = append(*s, script.Op0, script.OpRETURN)
	// Append each data push
	for _, push := range pushes {
		if err := s.AppendPushData(push); err != nil {
			return nil, fmt.Errorf("%w: OP_RETURN push data: %w", ErrScriptBuild, err)
		}
	}
	return s, nil
}

// BuildP2PKHOutput creates a TransactionOutput with a P2PKH locking script
// for the given public key hash (20 bytes) and satoshi amount.
func BuildP2PKHOutput(pubKeyHash []byte, satoshis uint64) (*transaction.TransactionOutput, error) {
	addr, err := script.NewAddressFromPublicKeyHash(pubKeyHash, true)
	if err != nil {
		return nil, fmt.Errorf("%w: address from hash: %w", ErrScriptBuild, err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: P2PKH lock: %w", ErrScriptBuild, err)
	}
	return &transaction.TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: lockScript,
	}, nil
}

// TxHexFromBytes converts raw transaction bytes to a hex string.
func TxHexFromBytes(rawTx []byte) string {
	return hex.EncodeToString(rawTx)
}
