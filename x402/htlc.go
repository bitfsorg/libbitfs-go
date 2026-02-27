package x402

import (
	"bytes"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/tongxiaofeng/libbitfs-go/method42"
)

// HTLCParams holds parameters for creating an HTLC transaction.
type HTLCParams struct {
	BuyerPubKey  []byte // Buyer's compressed public key (33 bytes)
	SellerPubKey []byte // Seller's compressed public key (33 bytes)
	SellerAddr   []byte // Seller's P2PKH address hash (20 bytes)
	CapsuleHash  []byte // SHA256(capsule), 32 bytes
	Amount       uint64 // Payment amount in satoshis
	Timeout      uint32 // Refund timeout in blocks (default 72 = ~12h), used as nLockTime. Must be in [MinHTLCTimeout, MaxHTLCTimeout].
	InvoiceID    []byte // Optional invoice ID for replay protection (16 bytes). If nil/empty, script omits the prefix.
}

const (
	// DefaultHTLCTimeout is the default HTLC refund timeout in blocks (~12 hours at
	// ~10 min/block). This balances security (seller has time to claim) with usability
	// (buyer's wallet does not need to stay online for an entire day). The buyer must
	// broadcast the refund transaction before this timeout expires; the seller can
	// broadcast a competing claim transaction at any point before the timeout.
	DefaultHTLCTimeout = 72

	// MinHTLCTimeout is the minimum allowed HTLC timeout in blocks (~1 hour).
	// Setting the timeout too low risks the seller not having enough time to claim,
	// or the refund becoming broadcastable before the buyer receives the capsule.
	MinHTLCTimeout = 6

	// MaxHTLCTimeout is the maximum allowed HTLC timeout in blocks (~2 days).
	// Excessively long timeouts force the buyer's wallet to remain online and keep
	// funds locked for an unreasonable duration.
	MaxHTLCTimeout = 288

	// CompressedPubKeyLen is the expected length of a compressed public key.
	CompressedPubKeyLen = 33

	// PubKeyHashLen is the expected length of a P2PKH address hash.
	PubKeyHashLen = 20

	// CapsuleHashLen is the expected length of a capsule hash (SHA256).
	CapsuleHashLen = 32

	// InvoiceIDLen is the expected length of an invoice ID for HTLC replay protection.
	InvoiceIDLen = 16
)

// BuildHTLC constructs an HTLC locking script. When InvoiceID is provided,
// the script is prefixed with <invoice_id_16> OP_DROP for replay protection,
// binding the HTLC to a specific invoice:
//
//	[<invoice_id_16> OP_DROP]   // optional, present when InvoiceID is non-empty
//	OP_IF
//	  // Seller claim: reveal capsule + seller sig (P2PKH-style)
//	  OP_SHA256 <capsule_hash> OP_EQUALVERIFY
//	  OP_DUP OP_HASH160 <seller_addr> OP_EQUALVERIFY OP_CHECKSIG
//	OP_ELSE
//	  // Buyer refund: 2-of-2 multisig (spent via pre-signed refund tx)
//	  OP_2 <buyer_pubkey> <seller_pubkey> OP_2 OP_CHECKMULTISIG
//	OP_ENDIF
//
// The seller claims by providing the capsule preimage and their signature.
// The buyer refunds via a pre-signed 2-of-2 multisig transaction with nLockTime.
func BuildHTLC(params *HTLCParams) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: nil params", ErrHTLCBuildFailed)
	}
	if len(params.BuyerPubKey) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: buyer pubkey must be %d bytes, got %d",
			ErrHTLCBuildFailed, CompressedPubKeyLen, len(params.BuyerPubKey))
	}
	if len(params.SellerPubKey) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: seller pubkey must be %d bytes, got %d",
			ErrHTLCBuildFailed, CompressedPubKeyLen, len(params.SellerPubKey))
	}
	if len(params.SellerAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: seller address must be %d bytes, got %d",
			ErrHTLCBuildFailed, PubKeyHashLen, len(params.SellerAddr))
	}
	if len(params.CapsuleHash) != CapsuleHashLen {
		return nil, fmt.Errorf("%w: capsule hash must be %d bytes, got %d",
			ErrHTLCBuildFailed, CapsuleHashLen, len(params.CapsuleHash))
	}
	if params.Amount == 0 {
		return nil, fmt.Errorf("%w: amount must be > 0", ErrHTLCBuildFailed)
	}
	if params.Timeout == 0 {
		return nil, fmt.Errorf("%w: timeout must be > 0", ErrHTLCBuildFailed)
	}
	if params.Timeout < MinHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d below minimum %d blocks",
			ErrHTLCBuildFailed, params.Timeout, MinHTLCTimeout)
	}
	if params.Timeout > MaxHTLCTimeout {
		return nil, fmt.Errorf("%w: timeout %d exceeds maximum %d blocks",
			ErrHTLCBuildFailed, params.Timeout, MaxHTLCTimeout)
	}
	if len(params.InvoiceID) > 0 && len(params.InvoiceID) != InvoiceIDLen {
		return nil, fmt.Errorf("%w: invoice ID must be %d bytes, got %d",
			ErrHTLCBuildFailed, InvoiceIDLen, len(params.InvoiceID))
	}

	s := &script.Script{}

	// Optional replay protection prefix: <invoice_id_16> OP_DROP
	if len(params.InvoiceID) == InvoiceIDLen {
		if err := s.AppendPushData(params.InvoiceID); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
		}
		if err := s.AppendOpcodes(script.OpDROP); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
		}
	}

	// OP_IF
	if err := s.AppendOpcodes(script.OpIF); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	// Seller claim path: OP_SHA256 <capsule_hash> OP_EQUALVERIFY
	if err := s.AppendOpcodes(script.OpSHA256); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.CapsuleHash); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	// Seller verification: OP_DUP OP_HASH160 <seller_addr> OP_EQUALVERIFY OP_CHECKSIG
	if err := s.AppendOpcodes(script.OpDUP); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpHASH160); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.SellerAddr); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpCHECKSIG); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	// OP_ELSE
	if err := s.AppendOpcodes(script.OpELSE); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	// Buyer refund path: OP_2 <buyer_pubkey> <seller_pubkey> OP_2 OP_CHECKMULTISIG
	if err := s.AppendOpcodes(script.Op2); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.BuyerPubKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.SellerPubKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.Op2); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpCHECKMULTISIG); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	// OP_ENDIF
	if err := s.AppendOpcodes(script.OpENDIF); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHTLCBuildFailed, err)
	}

	return s.Bytes(), nil
}

// ParseHTLCPreimage extracts the capsule (preimage) from a spent HTLC input.
// The spending transaction's unlocking script for the seller claim path is:
//
//	<sig> <seller_pubkey> <capsule> OP_TRUE
//
// Where OP_TRUE selects the IF branch.
// If expectedCapsuleHash is non-nil, verifies SHA256(fileTxID ‖ preimage) matches before returning.
// fileTxID binds the capsule hash to the file's transaction identity.
func ParseHTLCPreimage(spendingTx []byte, expectedCapsuleHash []byte, fileTxID ...[]byte) ([]byte, error) {
	if len(spendingTx) == 0 {
		return nil, fmt.Errorf("%w: empty spending transaction", ErrInvalidPreimage)
	}

	tx, err := transaction.NewTransactionFromBytes(spendingTx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	// Look through all inputs for an HTLC spend
	for _, input := range tx.Inputs {
		if input.UnlockingScript == nil {
			continue
		}

		chunks, err := input.UnlockingScript.Chunks()
		if err != nil {
			continue
		}

		// Seller claim unlocking script: <sig> <pubkey> <preimage> OP_TRUE
		// We expect at least 4 chunks: sig, pubkey, preimage, OP_TRUE
		if len(chunks) < 4 {
			continue
		}

		// The last chunk should be OP_TRUE (0x51) selecting the IF branch
		lastChunk := chunks[len(chunks)-1]
		if lastChunk.Op != script.OpTRUE && lastChunk.Op != script.Op1 {
			continue
		}

		// The preimage is the third-from-last element (before OP_TRUE)
		preimageChunk := chunks[len(chunks)-2]
		if len(preimageChunk.Data) == 0 {
			continue
		}

		// Verify hash if expected hash provided.
		if expectedCapsuleHash != nil {
			var ftxid []byte
			if len(fileTxID) > 0 {
				ftxid = fileTxID[0]
			}
			h := method42.ComputeCapsuleHash(ftxid, preimageChunk.Data)
			if !bytes.Equal(h, expectedCapsuleHash) {
				continue // Hash mismatch — try next input.
			}
		}

		return preimageChunk.Data, nil
	}

	return nil, fmt.Errorf("%w: no HTLC preimage found in transaction inputs", ErrInvalidPreimage)
}

// ExtractCapsuleHashFromHTLC extracts the capsule hash embedded in an HTLC locking script.
// Supports both formats:
//   - Legacy:  OP_IF OP_SHA256 <capsule_hash_32> OP_EQUALVERIFY ...
//   - With ID: <invoice_id_16> OP_DROP OP_IF OP_SHA256 <capsule_hash_32> OP_EQUALVERIFY ...
func ExtractCapsuleHashFromHTLC(htlcScript []byte) ([]byte, error) {
	s := script.NewFromBytes(htlcScript)
	chunks, err := s.Chunks()
	if err != nil {
		return nil, fmt.Errorf("parse HTLC script: %w", err)
	}

	// Determine the offset: skip optional <invoice_id> OP_DROP prefix.
	offset := htlcInvoiceIDOffset(chunks)

	if len(chunks) < offset+3 {
		return nil, fmt.Errorf("HTLC script too short: %d chunks", len(chunks))
	}
	if chunks[offset].Op != script.OpIF {
		return nil, fmt.Errorf("expected OP_IF at position %d, got 0x%02x", offset, chunks[offset].Op)
	}
	if chunks[offset+1].Op != script.OpSHA256 {
		return nil, fmt.Errorf("expected OP_SHA256 at position %d, got 0x%02x", offset+1, chunks[offset+1].Op)
	}
	if len(chunks[offset+2].Data) != CapsuleHashLen {
		return nil, fmt.Errorf("capsule hash must be %d bytes, got %d", CapsuleHashLen, len(chunks[offset+2].Data))
	}
	return chunks[offset+2].Data, nil
}

// ExtractInvoiceIDFromHTLC extracts the invoice ID from an HTLC locking script,
// if present. Returns nil if the script uses the legacy format without an invoice ID prefix.
func ExtractInvoiceIDFromHTLC(htlcScript []byte) ([]byte, error) {
	s := script.NewFromBytes(htlcScript)
	chunks, err := s.Chunks()
	if err != nil {
		return nil, fmt.Errorf("parse HTLC script: %w", err)
	}
	if len(chunks) < 2 {
		return nil, nil // Too short to have prefix; legacy format.
	}
	// Check for <16-byte push data> OP_DROP pattern.
	if len(chunks[0].Data) == InvoiceIDLen && chunks[1].Op == script.OpDROP {
		return chunks[0].Data, nil
	}
	return nil, nil // Legacy format, no invoice ID.
}

// htlcInvoiceIDOffset returns the chunk offset to skip the optional
// <invoice_id_16> OP_DROP prefix. Returns 2 if the prefix is present, 0 otherwise.
func htlcInvoiceIDOffset(chunks []*script.ScriptChunk) int {
	if len(chunks) >= 2 && len(chunks[0].Data) == InvoiceIDLen && chunks[1].Op == script.OpDROP {
		return 2
	}
	return 0
}
