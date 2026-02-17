package tx

import (
	"encoding/hex"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
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
		return "", fmt.Errorf("%w: failed to parse raw tx: %v", ErrSigningFailed, err)
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
			return "", fmt.Errorf("%w: failed to create unlocker for input %d: %v",
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
		return "", fmt.Errorf("%w: %v", ErrSigningFailed, err)
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
		return nil, fmt.Errorf("%w: address from pubkey: %v", ErrScriptBuild, err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: P2PKH lock script: %v", ErrScriptBuild, err)
	}
	return []byte(*lockScript), nil
}

// BuildUnsignedCreateRootTx constructs a real go-sdk Transaction for a CreateRoot
// and stores the unsigned bytes in the returned MetanetTx.RawTx.
//
// This extends BuildCreateRoot by producing actual serialized transaction bytes
// that can be passed to SignMetanetTx for signing.
func BuildUnsignedCreateRootTx(params *CreateRootParams) (*MetanetTx, error) {
	// First, use the existing BuildCreateRoot for validation and fee calculation.
	mtx, err := BuildCreateRoot(params)
	if err != nil {
		return nil, err
	}

	// Now build the real go-sdk Transaction.
	sdkTx := transaction.NewTransaction()

	// Input 0: Fee UTXO.
	feeUTXOHash, err := chainhash.NewHash(params.FeeUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid fee UTXO TxID: %v", ErrSigningFailed, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       feeUTXOHash,
		SourceTxOutIndex: params.FeeUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Output 0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <empty> <Payload>
	opReturnData, err := BuildOPReturnData(params.NodePubKey, nil, params.Payload)
	if err != nil {
		return nil, fmt.Errorf("tx: failed to build OP_RETURN: %w", err)
	}
	opReturnScript, err := buildOPReturnScript(opReturnData)
	if err != nil {
		return nil, err
	}
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnScript,
	})

	// Output 1: P2PKH -> P_node (dust)
	nodeLockScript, err := BuildP2PKHScript(params.NodePubKey)
	if err != nil {
		return nil, err
	}
	nodeScript := script.NewFromBytes(nodeLockScript)
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: nodeScript,
	})

	// Output 2: P2PKH -> Change (if above dust)
	if mtx.ChangeUTXO != nil {
		var changeLockScript *script.Script
		if len(params.ChangeAddr) == 20 {
			addr, err := script.NewAddressFromPublicKeyHash(params.ChangeAddr, true)
			if err != nil {
				return nil, fmt.Errorf("%w: change address: %v", ErrScriptBuild, err)
			}
			changeLockScript, err = p2pkh.Lock(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: change lock script: %v", ErrScriptBuild, err)
			}
		} else {
			// Fall back to P_node as change destination.
			changeLockScript = nodeScript
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      mtx.ChangeUTXO.Amount,
			LockingScript: changeLockScript,
		})
	}

	// Store the unsigned raw transaction bytes.
	mtx.RawTx = sdkTx.Bytes()

	return mtx, nil
}

// BuildUnsignedCreateChildTx constructs a real go-sdk Transaction for a CreateChild
// and stores the unsigned bytes in the returned MetanetTx.RawTx.
//
// This extends BuildCreateChild by producing actual serialized transaction bytes
// that can be passed to SignMetanetTx for signing.
//
// Inputs:
//
//	0: P_parent UTXO (Metanet edge — spends parent's node output)
//	1: Fee UTXO
//
// Outputs:
//
//	0: OP_FALSE OP_RETURN <MetaFlag> <P_child> <TxID_parent> <Payload>
//	1: P2PKH -> P_child (dust)
//	2: P2PKH -> P_parent (dust, UTXO refresh)
//	3: P2PKH -> Change (if above dust)
func BuildUnsignedCreateChildTx(params *CreateChildParams) (*MetanetTx, error) {
	// First, use the existing BuildCreateChild for validation and fee calculation.
	mtx, err := BuildCreateChild(params)
	if err != nil {
		return nil, err
	}

	// Now build the real go-sdk Transaction.
	sdkTx := transaction.NewTransaction()

	// Input 0: P_parent UTXO (Metanet edge).
	parentUTXOHash, err := chainhash.NewHash(params.ParentUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid parent UTXO TxID: %v", ErrSigningFailed, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       parentUTXOHash,
		SourceTxOutIndex: params.ParentUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Input 1: Fee UTXO.
	feeUTXOHash, err := chainhash.NewHash(params.FeeUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid fee UTXO TxID: %v", ErrSigningFailed, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       feeUTXOHash,
		SourceTxOutIndex: params.FeeUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Output 0: OP_FALSE OP_RETURN <MetaFlag> <P_child> <TxID_parent> <Payload>
	opReturnData, err := BuildOPReturnData(params.NodePubKey, params.ParentTxID, params.Payload)
	if err != nil {
		return nil, fmt.Errorf("tx: failed to build OP_RETURN: %w", err)
	}
	opReturnScript, err := buildOPReturnScript(opReturnData)
	if err != nil {
		return nil, err
	}
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnScript,
	})

	// Output 1: P2PKH -> P_child (dust)
	childLockScript, err := BuildP2PKHScript(params.NodePubKey)
	if err != nil {
		return nil, err
	}
	childScript := script.NewFromBytes(childLockScript)
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: childScript,
	})

	// Output 2: P2PKH -> P_parent (dust, UTXO refresh)
	parentLockScript, err := BuildP2PKHScript(params.ParentPubKey)
	if err != nil {
		return nil, err
	}
	parentScript := script.NewFromBytes(parentLockScript)
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: parentScript,
	})

	// Output 3: P2PKH -> Change (if above dust)
	if mtx.ChangeUTXO != nil {
		var changeLockScript *script.Script
		if len(params.ChangeAddr) == 20 {
			addr, err := script.NewAddressFromPublicKeyHash(params.ChangeAddr, true)
			if err != nil {
				return nil, fmt.Errorf("%w: change address: %v", ErrScriptBuild, err)
			}
			changeLockScript, err = p2pkh.Lock(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: change lock script: %v", ErrScriptBuild, err)
			}
		} else {
			// Fall back to P_child as change destination.
			changeLockScript = childScript
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      mtx.ChangeUTXO.Amount,
			LockingScript: changeLockScript,
		})
	}

	// Store the unsigned raw transaction bytes.
	mtx.RawTx = sdkTx.Bytes()

	return mtx, nil
}

// BuildUnsignedSelfUpdateTx constructs a real go-sdk Transaction for a SelfUpdate
// and stores the unsigned bytes in the returned MetanetTx.RawTx.
//
// This extends BuildSelfUpdate by producing actual serialized transaction bytes
// that can be passed to SignMetanetTx for signing.
//
// Inputs:
//
//	0: P_node UTXO (spends own node output)
//	1: Fee UTXO
//
// Outputs:
//
//	0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <TxID_parent> <Payload>
//	1: P2PKH -> P_node (dust, refresh)
//	2: P2PKH -> Change (if above dust)
func BuildUnsignedSelfUpdateTx(params *SelfUpdateParams) (*MetanetTx, error) {
	// First, use the existing BuildSelfUpdate for validation and fee calculation.
	mtx, err := BuildSelfUpdate(params)
	if err != nil {
		return nil, err
	}

	// Now build the real go-sdk Transaction.
	sdkTx := transaction.NewTransaction()

	// Input 0: P_node UTXO (self).
	nodeUTXOHash, err := chainhash.NewHash(params.NodeUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid node UTXO TxID: %v", ErrSigningFailed, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       nodeUTXOHash,
		SourceTxOutIndex: params.NodeUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Input 1: Fee UTXO.
	feeUTXOHash, err := chainhash.NewHash(params.FeeUTXO.TxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid fee UTXO TxID: %v", ErrSigningFailed, err)
	}
	sdkTx.AddInput(&transaction.TransactionInput{
		SourceTXID:       feeUTXOHash,
		SourceTxOutIndex: params.FeeUTXO.Vout,
		SequenceNumber:   transaction.DefaultSequenceNumber,
	})

	// Output 0: OP_FALSE OP_RETURN <MetaFlag> <P_node> <TxID_parent> <Payload>
	opReturnData, err := BuildOPReturnData(params.NodePubKey, params.ParentTxID, params.Payload)
	if err != nil {
		return nil, fmt.Errorf("tx: failed to build OP_RETURN: %w", err)
	}
	opReturnScript, err := buildOPReturnScript(opReturnData)
	if err != nil {
		return nil, err
	}
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnScript,
	})

	// Output 1: P2PKH -> P_node (dust, refresh)
	nodeLockScript, err := BuildP2PKHScript(params.NodePubKey)
	if err != nil {
		return nil, err
	}
	nodeScript := script.NewFromBytes(nodeLockScript)
	sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
		Satoshis:      DustLimit,
		LockingScript: nodeScript,
	})

	// Output 2: P2PKH -> Change (if above dust)
	if mtx.ChangeUTXO != nil {
		var changeLockScript *script.Script
		if len(params.ChangeAddr) == 20 {
			addr, err := script.NewAddressFromPublicKeyHash(params.ChangeAddr, true)
			if err != nil {
				return nil, fmt.Errorf("%w: change address: %v", ErrScriptBuild, err)
			}
			changeLockScript, err = p2pkh.Lock(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: change lock script: %v", ErrScriptBuild, err)
			}
		} else {
			// Fall back to P_node as change destination.
			changeLockScript = nodeScript
		}
		sdkTx.Outputs = append(sdkTx.Outputs, &transaction.TransactionOutput{
			Satoshis:      mtx.ChangeUTXO.Amount,
			LockingScript: changeLockScript,
		})
	}

	// Store the unsigned raw transaction bytes.
	mtx.RawTx = sdkTx.Bytes()

	return mtx, nil
}

// buildOPReturnScript creates an OP_FALSE OP_RETURN script from data pushes.
func buildOPReturnScript(pushes [][]byte) (*script.Script, error) {
	s := &script.Script{}
	// OP_FALSE (OP_0)
	*s = append(*s, script.Op0)
	// OP_RETURN
	*s = append(*s, script.OpRETURN)
	// Append each data push
	for _, push := range pushes {
		if err := s.AppendPushData(push); err != nil {
			return nil, fmt.Errorf("%w: OP_RETURN push data: %v", ErrScriptBuild, err)
		}
	}
	return s, nil
}

// BuildP2PKHOutput creates a TransactionOutput with a P2PKH locking script
// for the given public key hash (20 bytes) and satoshi amount.
func BuildP2PKHOutput(pubKeyHash []byte, satoshis uint64) (*transaction.TransactionOutput, error) {
	addr, err := script.NewAddressFromPublicKeyHash(pubKeyHash, true)
	if err != nil {
		return nil, fmt.Errorf("%w: address from hash: %v", ErrScriptBuild, err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: P2PKH lock: %v", ErrScriptBuild, err)
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
