package x402

import (
	"bytes"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// HTLCUTXO represents an unspent output for HTLC funding.
type HTLCUTXO struct {
	TxID         []byte // 32 bytes, internal byte order
	Vout         uint32
	Amount       uint64
	ScriptPubKey []byte // Locking script bytes
}

// HTLCFundingParams holds parameters for building an HTLC funding transaction.
type HTLCFundingParams struct {
	BuyerPrivKey *ec.PrivateKey // Signs the P2PKH inputs
	SellerAddr   []byte         // 20-byte P2PKH hash
	CapsuleHash  []byte         // 32-byte SHA256(capsule)
	Amount       uint64         // HTLC output satoshis
	Timeout      uint32         // Block height for refund
	UTXOs        []*HTLCUTXO    // Buyer's unspent outputs
	ChangeAddr   []byte         // 20-byte change address hash
	FeeRate      uint64         // Satoshis per byte (0 = use default)
}

// HTLCFundingResult holds the result of building an HTLC funding transaction.
type HTLCFundingResult struct {
	RawTx      []byte // Signed serialized transaction
	TxID       []byte // 32-byte transaction hash
	HTLCVout   uint32 // Index of the HTLC output
	HTLCScript []byte // HTLC locking script bytes
	HTLCAmount uint64 // Actual HTLC output amount (may differ if dust-adjusted)
}

// SellerClaimParams holds parameters for the seller claim transaction.
type SellerClaimParams struct {
	FundingTxID   []byte         // 32-byte HTLC funding tx hash
	FundingVout   uint32         // HTLC output index in funding tx
	FundingAmount uint64         // HTLC output amount
	HTLCScript    []byte         // HTLC locking script bytes
	Capsule       []byte         // Preimage to reveal (32 bytes)
	SellerPrivKey *ec.PrivateKey // Signs the claim
	OutputAddr    []byte         // 20-byte destination P2PKH hash
	FeeRate       uint64         // Satoshis per byte (0 = use default)
}

// BuyerRefundParams holds parameters for the buyer refund transaction.
type BuyerRefundParams struct {
	FundingTxID   []byte         // 32-byte HTLC funding tx hash
	FundingVout   uint32         // HTLC output index in funding tx
	FundingAmount uint64         // HTLC output amount
	HTLCScript    []byte         // HTLC locking script bytes
	BuyerPrivKey  *ec.PrivateKey // Signs the refund
	OutputAddr    []byte         // 20-byte destination P2PKH hash
	Locktime      uint32         // Must be >= HTLC timeout
	FeeRate       uint64         // Satoshis per byte (0 = use default)
}

// defaultHTLCFeeRate is the default fee rate for HTLC transactions.
const defaultHTLCFeeRate = uint64(1) // 1 sat/byte

// dustLimit is the minimum output value in satoshis.
const dustLimit = uint64(546)

// VerifyHTLCFunding verifies a funding transaction has an output whose locking
// script matches the expected HTLC script with at least minAmount satoshis.
// Returns the output index (vout) of the matching HTLC output.
func VerifyHTLCFunding(rawTx []byte, expectedScript []byte, minAmount uint64) (uint32, error) {
	if len(rawTx) == 0 {
		return 0, fmt.Errorf("%w: empty raw transaction", ErrInvalidTx)
	}
	if len(expectedScript) == 0 {
		return 0, fmt.Errorf("%w: nil expected script", ErrInvalidParams)
	}

	tx, err := transaction.NewTransactionFromBytes(rawTx)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	for i, output := range tx.Outputs {
		if output.LockingScript == nil {
			continue
		}
		if !bytes.Equal(output.LockingScript.Bytes(), expectedScript) {
			continue
		}
		if output.Satoshis < minAmount {
			return 0, fmt.Errorf("%w: output has %d satoshis, need %d",
				ErrInsufficientPayment, output.Satoshis, minAmount)
		}
		return uint32(i), nil
	}

	return 0, ErrNoMatchingOutput
}

// BuildHTLCFundingTx creates a signed transaction with an HTLC output.
// Input: buyer's P2PKH UTXOs. Output 0: HTLC script. Output 1: change (if above dust).
func BuildHTLCFundingTx(params *HTLCFundingParams) (*HTLCFundingResult, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: nil params", ErrInvalidParams)
	}
	if params.BuyerPrivKey == nil {
		return nil, fmt.Errorf("%w: nil buyer private key", ErrInvalidParams)
	}
	if len(params.UTXOs) == 0 {
		return nil, fmt.Errorf("%w: no UTXOs provided", ErrInvalidParams)
	}
	if len(params.SellerAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: seller address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}
	if len(params.CapsuleHash) != CapsuleHashLen {
		return nil, fmt.Errorf("%w: capsule hash must be %d bytes", ErrInvalidParams, CapsuleHashLen)
	}
	if len(params.ChangeAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: change address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}

	// Enforce dust limit on HTLC amount.
	htlcAmount := params.Amount
	if htlcAmount < dustLimit {
		htlcAmount = dustLimit
	}

	timeout := params.Timeout
	if timeout == 0 {
		timeout = DefaultHTLCTimeout
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Build the HTLC locking script.
	buyerPubKey := params.BuyerPrivKey.PubKey().Compressed()
	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey: buyerPubKey,
		SellerAddr:  params.SellerAddr,
		CapsuleHash: params.CapsuleHash,
		Amount:      htlcAmount,
		Timeout:     timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("build HTLC script: %w", err)
	}

	// Calculate total input amount.
	var totalInput uint64
	for _, utxo := range params.UTXOs {
		totalInput += utxo.Amount
	}

	// Estimate fee: ~148 bytes per input + ~40 bytes per output + 10 overhead.
	estSize := uint64(10 + len(params.UTXOs)*148 + 2*40)
	estFee := estSize * feeRate

	totalNeeded := htlcAmount + estFee
	if totalInput < totalNeeded {
		return nil, fmt.Errorf("%w: have %d satoshis, need %d (amount=%d + fee~%d)",
			ErrInsufficientPayment, totalInput, totalNeeded, htlcAmount, estFee)
	}

	// Build the transaction.
	tx := transaction.NewTransaction()

	// Add inputs.
	for _, utxo := range params.UTXOs {
		txidHash, hashErr := chainhash.NewHash(utxo.TxID)
		if hashErr != nil {
			return nil, fmt.Errorf("%w: invalid UTXO txid: %w", ErrInvalidParams, hashErr)
		}
		tx.AddInput(&transaction.TransactionInput{
			SourceTXID:       txidHash,
			SourceTxOutIndex: utxo.Vout,
			SequenceNumber:   0xffffffff,
		})
	}

	// Output 0: HTLC.
	htlcLockingScript := script.Script(htlcScript)
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: &htlcLockingScript,
		Satoshis:      htlcAmount,
	})

	// Output 1: change (if above dust).
	changeAmount := totalInput - htlcAmount - estFee
	if changeAmount > dustLimit {
		changeScript, changeErr := buildP2PKHLockScript(params.ChangeAddr)
		if changeErr != nil {
			return nil, fmt.Errorf("build change script: %w", changeErr)
		}
		tx.AddOutput(&transaction.TransactionOutput{
			LockingScript: changeScript,
			Satoshis:      changeAmount,
		})
	}

	// Set source outputs and sign each input.
	for i, utxo := range params.UTXOs {
		lockScript := script.NewFromBytes(utxo.ScriptPubKey)
		tx.Inputs[i].SetSourceTxOutput(&transaction.TransactionOutput{
			Satoshis:      utxo.Amount,
			LockingScript: lockScript,
		})

		unlocker, unlockErr := p2pkh.Unlock(params.BuyerPrivKey, nil)
		if unlockErr != nil {
			return nil, fmt.Errorf("create P2PKH unlocker for input %d: %w", i, unlockErr)
		}
		tx.Inputs[i].UnlockingScriptTemplate = unlocker
	}

	if err := tx.Sign(); err != nil {
		return nil, fmt.Errorf("sign funding tx: %w", err)
	}

	txIDHash := tx.TxID()

	return &HTLCFundingResult{
		RawTx:      tx.Bytes(),
		TxID:       txIDHash[:],
		HTLCVout:   0,
		HTLCScript: htlcScript,
		HTLCAmount: htlcAmount,
	}, nil
}

// BuildSellerClaimTx creates a signed transaction spending the HTLC via the seller claim path.
// Unlocking script: <sig+flag> <seller_pubkey> <capsule> OP_TRUE
func BuildSellerClaimTx(params *SellerClaimParams) (*transaction.Transaction, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: nil params", ErrInvalidParams)
	}
	if params.SellerPrivKey == nil {
		return nil, fmt.Errorf("%w: nil seller private key", ErrInvalidParams)
	}
	if len(params.FundingTxID) != 32 {
		return nil, fmt.Errorf("%w: funding txid must be 32 bytes", ErrInvalidParams)
	}
	if len(params.HTLCScript) == 0 {
		return nil, fmt.Errorf("%w: empty HTLC script", ErrInvalidParams)
	}
	if len(params.Capsule) == 0 {
		return nil, fmt.Errorf("%w: empty capsule", ErrInvalidParams)
	}
	if len(params.OutputAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: output address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Estimate claim tx size: ~10 overhead + ~(73+33+32+1) unlocking + script + ~40 output.
	estSize := uint64(10 + 73 + 33 + 32 + 1 + uint64(len(params.HTLCScript)) + 40)
	estFee := estSize * feeRate

	if params.FundingAmount <= estFee {
		return nil, fmt.Errorf("%w: funding amount %d too small for fee %d",
			ErrInsufficientPayment, params.FundingAmount, estFee)
	}

	outputAmount := params.FundingAmount - estFee
	if outputAmount < dustLimit {
		return nil, fmt.Errorf("%w: output would be %d (below dust limit %d)",
			ErrInsufficientPayment, outputAmount, dustLimit)
	}

	txidHash, err := chainhash.NewHash(params.FundingTxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid funding txid: %w", ErrInvalidParams, err)
	}

	tx := transaction.NewTransaction()

	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       txidHash,
		SourceTxOutIndex: params.FundingVout,
		SequenceNumber:   0xffffffff,
	})

	// Set source output for sighash computation.
	htlcLockingScript := script.NewFromBytes(params.HTLCScript)
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      params.FundingAmount,
		LockingScript: htlcLockingScript,
	})

	// Output: P2PKH to seller.
	outputScript, err := buildP2PKHLockScript(params.OutputAddr)
	if err != nil {
		return nil, fmt.Errorf("build output script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: outputScript,
		Satoshis:      outputAmount,
	})

	// Compute sighash and sign manually (not using template — HTLC is custom).
	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, fmt.Errorf("calc sighash: %w", err)
	}

	sig, err := params.SellerPrivKey.Sign(sigHash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Build unlocking script: <sig+flag> <seller_pubkey> <capsule> OP_TRUE
	sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))
	sellerPubKey := params.SellerPrivKey.PubKey().Compressed()

	unlockScript := &script.Script{}
	if err := unlockScript.AppendPushData(sigBytes); err != nil {
		return nil, fmt.Errorf("push sig: %w", err)
	}
	if err := unlockScript.AppendPushData(sellerPubKey); err != nil {
		return nil, fmt.Errorf("push seller pubkey: %w", err)
	}
	if err := unlockScript.AppendPushData(params.Capsule); err != nil {
		return nil, fmt.Errorf("push capsule: %w", err)
	}
	if err := unlockScript.AppendOpcodes(script.OpTRUE); err != nil {
		return nil, fmt.Errorf("push OP_TRUE: %w", err)
	}

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx, nil
}

// BuildBuyerRefundTx creates a signed transaction spending the HTLC via the buyer refund path.
// Unlocking script: <sig+flag> OP_FALSE
// nLockTime must be >= the HTLC timeout, and input sequence must be < 0xffffffff.
func BuildBuyerRefundTx(params *BuyerRefundParams) (*transaction.Transaction, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: nil params", ErrInvalidParams)
	}
	if params.BuyerPrivKey == nil {
		return nil, fmt.Errorf("%w: nil buyer private key", ErrInvalidParams)
	}
	if len(params.FundingTxID) != 32 {
		return nil, fmt.Errorf("%w: funding txid must be 32 bytes", ErrInvalidParams)
	}
	if len(params.HTLCScript) == 0 {
		return nil, fmt.Errorf("%w: empty HTLC script", ErrInvalidParams)
	}
	if len(params.OutputAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: output address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}
	if params.Locktime == 0 {
		return nil, fmt.Errorf("%w: locktime must be > 0 for refund path", ErrInvalidParams)
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Estimate refund tx size: ~10 overhead + ~(73+1) unlocking + script + ~40 output.
	estSize := uint64(10 + 73 + 1 + uint64(len(params.HTLCScript)) + 40)
	estFee := estSize * feeRate

	if params.FundingAmount <= estFee {
		return nil, fmt.Errorf("%w: funding amount %d too small for fee %d",
			ErrInsufficientPayment, params.FundingAmount, estFee)
	}

	outputAmount := params.FundingAmount - estFee
	if outputAmount < dustLimit {
		return nil, fmt.Errorf("%w: output would be %d (below dust limit %d)",
			ErrInsufficientPayment, outputAmount, dustLimit)
	}

	txidHash, err := chainhash.NewHash(params.FundingTxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid funding txid: %w", ErrInvalidParams, err)
	}

	tx := transaction.NewTransaction()
	tx.LockTime = params.Locktime

	// Sequence must be < 0xffffffff for CLTV to work.
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       txidHash,
		SourceTxOutIndex: params.FundingVout,
		SequenceNumber:   0xfffffffe, // enables nLockTime
	})

	// Set source output for sighash.
	htlcLockingScript := script.NewFromBytes(params.HTLCScript)
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{
		Satoshis:      params.FundingAmount,
		LockingScript: htlcLockingScript,
	})

	// Output: P2PKH to buyer.
	outputScript, err := buildP2PKHLockScript(params.OutputAddr)
	if err != nil {
		return nil, fmt.Errorf("build output script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		LockingScript: outputScript,
		Satoshis:      outputAmount,
	})

	// Compute sighash and sign manually.
	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, fmt.Errorf("calc sighash: %w", err)
	}

	sig, err := params.BuyerPrivKey.Sign(sigHash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Build unlocking script: <sig+flag> OP_FALSE
	sigBytes := append(sig.Serialize(), byte(sighash.AllForkID))

	unlockScript := &script.Script{}
	if err := unlockScript.AppendPushData(sigBytes); err != nil {
		return nil, fmt.Errorf("push sig: %w", err)
	}
	if err := unlockScript.AppendOpcodes(script.OpFALSE); err != nil {
		return nil, fmt.Errorf("push OP_FALSE: %w", err)
	}

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx, nil
}

// buildP2PKHLockScript creates a P2PKH locking script from a 20-byte public key hash.
func buildP2PKHLockScript(pubKeyHash []byte) (*script.Script, error) {
	s := &script.Script{}
	if err := s.AppendOpcodes(script.OpDUP); err != nil {
		return nil, err
	}
	if err := s.AppendOpcodes(script.OpHASH160); err != nil {
		return nil, err
	}
	if err := s.AppendPushData(pubKeyHash); err != nil {
		return nil, err
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, err
	}
	if err := s.AppendOpcodes(script.OpCHECKSIG); err != nil {
		return nil, err
	}
	return s, nil
}
