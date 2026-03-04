package payment

import (
	"bytes"
	"fmt"

	"github.com/bitfsorg/libbitfs-go/method42"
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
	SellerPubKey []byte         // 33-byte compressed public key (for 2-of-2 multisig refund)
	CapsuleHash  []byte         // 32-byte SHA256(capsule)
	Amount       uint64         // HTLC output satoshis
	Timeout      uint32         // Refund timeout in blocks (0 = DefaultHTLCTimeout). Must be in [MinHTLCTimeout, MaxHTLCTimeout].
	UTXOs        []*HTLCUTXO    // Buyer's unspent outputs
	ChangeAddr   []byte         // 20-byte change address hash
	FeeRate      uint64         // Satoshis per KB (0 = use default)
	InvoiceID    []byte         // 16-byte invoice ID for replay protection (mandatory)
}

// HTLCFundingResult holds the result of building an HTLC funding transaction.
type HTLCFundingResult struct {
	RawTx      []byte // Signed serialized transaction
	TxID       []byte // 32-byte transaction hash
	HTLCVout   uint32 // Index of the HTLC output
	HTLCScript []byte // HTLC locking script bytes
	HTLCAmount uint64 // Actual HTLC output amount
}

// SellerClaimParams holds parameters for the seller claim transaction.
type SellerClaimParams struct {
	FundingTxID   []byte         // 32-byte HTLC funding tx hash
	FundingVout   uint32         // HTLC output index in funding tx
	FundingAmount uint64         // HTLC output amount
	HTLCScript    []byte         // HTLC locking script bytes
	Capsule       []byte         // Preimage to reveal (32 bytes)
	FileTxID      []byte         // 32-byte file transaction ID (binds capsule hash to file identity)
	SellerPrivKey *ec.PrivateKey // Signs the claim
	OutputAddr    []byte         // 20-byte destination P2PKH hash
	FeeRate       uint64         // Satoshis per KB (0 = use default)
}

// BuyerRefundParams holds parameters for building an on-chain refund transaction.
// The buyer can refund unilaterally after the timeout -- no seller cooperation needed.
// The timeout is enforced at the transaction level via nLockTime (not in the script).
type BuyerRefundParams struct {
	FundingTxID   []byte         // 32-byte HTLC funding tx hash
	FundingVout   uint32         // HTLC output index
	FundingAmount uint64         // HTLC output amount (satoshis)
	HTLCScript    []byte         // HTLC locking script bytes
	BuyerPrivKey  *ec.PrivateKey // Signs the refund
	OutputAddr    []byte         // 20-byte destination P2PKH hash
	Timeout       uint32         // Block height for nLockTime
	FeeRate       uint64         // Satoshis per KB (0 = default)
}

// defaultHTLCFeeRate is the default fee rate for HTLC transactions.
const defaultHTLCFeeRate = uint64(100) // 100 sat/KB == 0.1 sat/byte

// estimateFeeByKB returns ceil(txSizeBytes * satPerKB / 1000).
func estimateFeeByKB(txSizeBytes, satPerKB uint64) uint64 {
	if satPerKB == 0 {
		satPerKB = defaultHTLCFeeRate
	}
	return (txSizeBytes*satPerKB + 999) / 1000
}

// VerifyHTLCFunding verifies a funding transaction has an output whose locking
// script matches the expected HTLC script with at least minAmount satoshis.
// Returns the output index (vout) of the first matching HTLC output.
// If multiple outputs match, the first (lowest index) is returned deterministically.
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
// Input: buyer's P2PKH UTXOs. Output 0: HTLC script. Output 1: change (if any).
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
	if len(params.SellerPubKey) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: seller pubkey must be %d bytes", ErrInvalidParams, CompressedPubKeyLen)
	}
	if len(params.CapsuleHash) != CapsuleHashLen {
		return nil, fmt.Errorf("%w: capsule hash must be %d bytes", ErrInvalidParams, CapsuleHashLen)
	}
	if len(params.ChangeAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: change address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}
	if params.Amount == 0 {
		return nil, fmt.Errorf("%w: amount must be greater than zero", ErrInvalidParams)
	}
	if len(params.InvoiceID) != InvoiceIDLen {
		return nil, fmt.Errorf("%w: invoiceID is mandatory (%d bytes), got %d",
			ErrInvalidParams, InvoiceIDLen, len(params.InvoiceID))
	}

	htlcAmount := params.Amount

	timeout := params.Timeout
	if timeout == 0 {
		timeout = DefaultHTLCTimeout
	}
	if timeout < MinHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d below minimum %d blocks",
			ErrInvalidParams, timeout, MinHTLCTimeout)
	}
	if timeout > MaxHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d exceeds maximum %d blocks",
			ErrInvalidParams, timeout, MaxHTLCTimeout)
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Build the HTLC locking script.
	buyerPubKey := params.BuyerPrivKey.PubKey().Compressed()
	htlcScript, err := BuildHTLC(&HTLCParams{
		BuyerPubKey:  buyerPubKey,
		SellerPubKey: params.SellerPubKey,
		SellerAddr:   params.SellerAddr,
		CapsuleHash:  params.CapsuleHash,
		Amount:       htlcAmount,
		Timeout:      timeout,
		InvoiceID:    params.InvoiceID,
	})
	if err != nil {
		return nil, fmt.Errorf("build HTLC script: %w", err)
	}

	// Calculate total input amount.
	var totalInput uint64
	for _, utxo := range params.UTXOs {
		totalInput += utxo.Amount
	}

	// Estimate fee using actual HTLC script size.
	// First estimate without change output to check if change is needed.
	htlcOutputSize := uint64(8 + 1 + len(htlcScript)) // satoshis + varint + script
	changeOutputSize := uint64(8 + 1 + 25)            // P2PKH: 8 + varint + OP_DUP..OP_CHECKSIG
	baseTxSize := uint64(10+len(params.UTXOs)*148) + htlcOutputSize

	// Estimate with change output first.
	estSizeWithChange := baseTxSize + changeOutputSize
	estFeeWithChange := estimateFeeByKB(estSizeWithChange, feeRate)

	// Determine if a change output is warranted.
	totalNeededWithChange := htlcAmount + estFeeWithChange
	var estFee uint64
	hasChange := totalInput > totalNeededWithChange
	if hasChange {
		estFee = estFeeWithChange
	} else {
		// No change output: recalculate fee without the change output size.
		estFee = estimateFeeByKB(baseTxSize, feeRate)
	}

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

	// Output 1: change (if any surplus remains after HTLC amount + fee).
	if hasChange {
		changeAmount := totalInput - htlcAmount - estFee
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

// BuildSellerClaimTx creates a signed transaction spending the HTLC via the
// claim path (OP_IF branch). The unlocking script format is:
//
//	<sig> <pubkey> <fileTxID||capsule> OP_TRUE
//
// Where OP_TRUE selects the IF branch (claim). The preimage is 64 bytes:
// fileTxID (32) concatenated with capsule (32). The locking script verifies
// OP_SHA256(preimage) == capsuleHash, where capsuleHash = SHA256(fileTxID||capsule).
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
	if len(params.FileTxID) != 32 {
		return nil, fmt.Errorf("%w: fileTxID must be 32 bytes, got %d", ErrInvalidParams, len(params.FileTxID))
	}
	if len(params.OutputAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: output address must be %d bytes", ErrInvalidParams, PubKeyHashLen)
	}

	// Verify capsule matches the hash embedded in the HTLC script.
	capsuleHashFromScript, err := ExtractCapsuleHashFromHTLC(params.HTLCScript)
	if err != nil {
		return nil, fmt.Errorf("%w: extract capsule hash: %w", ErrInvalidParams, err)
	}
	computedHash, hashErr := method42.ComputeCapsuleHash(params.FileTxID, params.Capsule)
	if hashErr != nil {
		return nil, fmt.Errorf("%w: compute capsule hash: %w", ErrInvalidParams, hashErr)
	}
	if !bytes.Equal(computedHash, capsuleHashFromScript) {
		return nil, fmt.Errorf("%w: capsule hash mismatch", ErrInvalidParams)
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Estimate claim tx size: ~10 overhead + ~(73+33+64+1) unlocking + script + ~40 output.
	// The preimage is 64 bytes (fileTxID 32 + capsule 32).
	estSize := 10 + 73 + 33 + 64 + 1 + uint64(len(params.HTLCScript)) + 40
	estFee := estimateFeeByKB(estSize, feeRate)

	if params.FundingAmount <= estFee {
		return nil, fmt.Errorf("%w: funding amount %d too small for fee %d",
			ErrInsufficientPayment, params.FundingAmount, estFee)
	}

	outputAmount := params.FundingAmount - estFee

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

	// Build unlocking script for claim path (OP_IF branch):
	//   <sig> <pubkey> <fileTxID||capsule> OP_TRUE
	// The preimage is fileTxID (32 bytes) concatenated with capsule (32 bytes).
	// The locking script does OP_SHA256 on this 64-byte preimage and verifies
	// against the embedded capsuleHash = SHA256(fileTxID || capsule).
	sigBytes := appendSighashFlag(sig.Serialize())
	sellerPubKey := params.SellerPrivKey.PubKey().Compressed()

	// Build 64-byte preimage: fileTxID || capsule
	preimage := make([]byte, 0, 64)
	preimage = append(preimage, params.FileTxID...)
	preimage = append(preimage, params.Capsule...)

	unlockScript := &script.Script{}
	if err := unlockScript.AppendPushData(sigBytes); err != nil {
		return nil, fmt.Errorf("push sig: %w", err)
	}
	if err := unlockScript.AppendPushData(sellerPubKey); err != nil {
		return nil, fmt.Errorf("push seller pubkey: %w", err)
	}
	if err := unlockScript.AppendPushData(preimage); err != nil {
		return nil, fmt.Errorf("push preimage: %w", err)
	}
	if err := unlockScript.AppendOpcodes(script.OpTRUE); err != nil {
		return nil, fmt.Errorf("push branch selector OP_TRUE: %w", err)
	}

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx, nil
}

// BuildBuyerRefundTx creates a signed refund transaction spending the HTLC via
// the refund path (OP_ELSE branch). The buyer can refund unilaterally after the
// timeout -- no seller cooperation is needed.
//
// The transaction sets nLockTime = params.Timeout and sequence = 0xfffffffe to
// enable nLockTime enforcement. The unlocking script format is:
//
//	<sig> <pubkey> OP_FALSE
//
// Where OP_FALSE selects the ELSE branch (refund). The timeout is enforced at
// the transaction level via nLockTime (consensus-enforced by miners). BSV
// post-Genesis treats OP_CLTV as OP_NOP2 which is rejected by mempool policy,
// so the timelock is not embedded in the script.
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
	if params.FundingAmount == 0 {
		return nil, fmt.Errorf("%w: funding amount must be greater than zero", ErrInvalidParams)
	}

	timeout := params.Timeout
	if timeout == 0 {
		timeout = DefaultHTLCTimeout
	}
	if timeout < MinHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d below minimum %d blocks",
			ErrInvalidParams, timeout, MinHTLCTimeout)
	}
	if timeout > MaxHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d exceeds maximum %d blocks",
			ErrInvalidParams, timeout, MaxHTLCTimeout)
	}

	feeRate := params.FeeRate
	if feeRate == 0 {
		feeRate = defaultHTLCFeeRate
	}

	// Estimate refund tx size: ~10 overhead + ~(73 + 33 + 1) unlocking
	// + script + ~40 output. No sighash preimage needed.
	estSize := 10 + 73 + 33 + 1 + uint64(len(params.HTLCScript)) + 40
	estFee := estimateFeeByKB(estSize, feeRate)

	if params.FundingAmount <= estFee {
		return nil, fmt.Errorf("%w: funding amount %d too small for fee %d",
			ErrInsufficientPayment, params.FundingAmount, estFee)
	}

	outputAmount := params.FundingAmount - estFee

	txidHash, err := chainhash.NewHash(params.FundingTxID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid funding txid: %w", ErrInvalidParams, err)
	}

	tx := transaction.NewTransaction()
	tx.LockTime = timeout

	// Sequence must be < 0xffffffff for nLockTime to be enforced by miners.
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       txidHash,
		SourceTxOutIndex: params.FundingVout,
		SequenceNumber:   0xfffffffe,
	})

	// Set source output for sighash computation.
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

	// Compute sighash and sign with buyer's key.
	sigHash, err := tx.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		return nil, fmt.Errorf("calc sighash: %w", err)
	}

	sig, err := params.BuyerPrivKey.Sign(sigHash)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	buyerSigBytes := appendSighashFlag(sig.Serialize())
	buyerPubKey := params.BuyerPrivKey.PubKey().Compressed()

	// Build unlocking script for refund path (OP_ELSE branch):
	//   <sig> <pubkey> OP_FALSE
	unlockScript := &script.Script{}
	if err := unlockScript.AppendPushData(buyerSigBytes); err != nil {
		return nil, fmt.Errorf("push sig: %w", err)
	}
	if err := unlockScript.AppendPushData(buyerPubKey); err != nil {
		return nil, fmt.Errorf("push buyer pubkey: %w", err)
	}
	if err := unlockScript.AppendOpcodes(script.OpFALSE); err != nil {
		return nil, fmt.Errorf("push branch selector OP_FALSE: %w", err)
	}

	tx.Inputs[0].UnlockingScript = unlockScript

	return tx, nil
}

// appendSighashFlag safely appends a sighash type flag to a DER-encoded
// signature without mutating the original slice.
func appendSighashFlag(sigDER []byte) []byte {
	result := make([]byte, len(sigDER)+1)
	copy(result, sigDER)
	result[len(sigDER)] = byte(sighash.AllForkID)
	return result
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
