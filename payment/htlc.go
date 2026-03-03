package payment

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	bsvhash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// HTLCParams holds parameters for creating an HTLC transaction.
type HTLCParams struct {
	BuyerPubKey  []byte // Buyer's compressed public key (33 bytes)
	SellerPubKey []byte // Seller's compressed public key (33 bytes) — kept for BuildHTLCFundingTx compatibility; not embedded in the HTLC script
	SellerAddr   []byte // Seller's P2PKH address hash (20 bytes)
	CapsuleHash  []byte // SHA256(capsule), 32 bytes
	Amount       uint64 // Payment amount in satoshis
	Timeout      uint32 // Refund timeout in blocks (default 72 = ~12h), used as nLockTime. Must be in [MinHTLCTimeout, MaxHTLCTimeout].
	InvoiceID    []byte // 16-byte invoice ID for replay protection (mandatory)
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

// BuildHTLC constructs a plain Bitcoin Script HTLC locking script. The script
// encodes both the seller-claim path (hash-lock + P2PKH) and the buyer-refund
// path (P2PKH) in a single script:
//
//	<invoiceId>  OP_DROP
//	OP_IF
//	  OP_SHA256  <capsuleHash>  OP_EQUALVERIFY
//	  OP_DUP  OP_HASH160  <sellerPkh>  OP_EQUALVERIFY  OP_CHECKSIG
//	OP_ELSE
//	  OP_DUP  OP_HASH160  <buyerPkh>  OP_EQUALVERIFY  OP_CHECKSIG
//	OP_ENDIF
//
// Constructor parameters embedded in the script:
//
//   - invoiceId   — 16-byte replay protection token (mandatory)
//   - capsuleHash — SHA256(capsule), 32 bytes
//   - sellerPkh   — HASH160(seller public key), 20 bytes
//   - buyerPkh    — HASH160(buyer public key), 20 bytes
//
// The timeout is NOT embedded in the script. BSV post-Genesis treats OP_CLTV
// (0xb1) as OP_NOP2, which is rejected by standard mempool policy. Instead,
// the timeout is enforced at the transaction level via nLockTime on the refund
// transaction (consensus-enforced by miners).
//
// The seller claims by providing the capsule preimage, their signature, and OP_TRUE.
// The buyer refunds using OP_FALSE; the refund tx sets nLockTime = timeout.
func BuildHTLC(params *HTLCParams) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("%w: nil params", ErrHTLCBuildFailed)
	}
	if len(params.InvoiceID) != InvoiceIDLen {
		return nil, fmt.Errorf("%w: invoiceID is mandatory (%d bytes), got %d",
			ErrHTLCBuildFailed, InvoiceIDLen, len(params.InvoiceID))
	}
	if len(params.SellerAddr) != PubKeyHashLen {
		return nil, fmt.Errorf("%w: seller address must be %d bytes, got %d",
			ErrHTLCBuildFailed, PubKeyHashLen, len(params.SellerAddr))
	}
	if len(params.BuyerPubKey) != CompressedPubKeyLen {
		return nil, fmt.Errorf("%w: buyer pubkey must be %d bytes, got %d",
			ErrHTLCBuildFailed, CompressedPubKeyLen, len(params.BuyerPubKey))
	}
	if len(params.CapsuleHash) != CapsuleHashLen {
		return nil, fmt.Errorf("%w: capsule hash must be %d bytes, got %d",
			ErrHTLCBuildFailed, CapsuleHashLen, len(params.CapsuleHash))
	}
	if params.Amount == 0 {
		return nil, fmt.Errorf("%w: amount must be > 0", ErrHTLCBuildFailed)
	}

	// Derive buyer PKH from buyer public key.
	buyerPkh := bsvhash.Hash160(params.BuyerPubKey)

	s := &script.Script{}
	if err := s.AppendPushData(params.InvoiceID); err != nil {
		return nil, fmt.Errorf("%w: push invoiceId: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpDROP); err != nil {
		return nil, fmt.Errorf("%w: OP_DROP: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpIF); err != nil {
		return nil, fmt.Errorf("%w: OP_IF: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpSHA256); err != nil {
		return nil, fmt.Errorf("%w: OP_SHA256: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.CapsuleHash); err != nil {
		return nil, fmt.Errorf("%w: push capsuleHash: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, fmt.Errorf("%w: OP_EQUALVERIFY: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpDUP); err != nil {
		return nil, fmt.Errorf("%w: OP_DUP: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpHASH160); err != nil {
		return nil, fmt.Errorf("%w: OP_HASH160: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(params.SellerAddr); err != nil {
		return nil, fmt.Errorf("%w: push sellerPkh: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, fmt.Errorf("%w: OP_EQUALVERIFY: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpCHECKSIG); err != nil {
		return nil, fmt.Errorf("%w: OP_CHECKSIG: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpELSE); err != nil {
		return nil, fmt.Errorf("%w: OP_ELSE: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpDUP); err != nil {
		return nil, fmt.Errorf("%w: OP_DUP: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpHASH160); err != nil {
		return nil, fmt.Errorf("%w: OP_HASH160: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendPushData(buyerPkh); err != nil {
		return nil, fmt.Errorf("%w: push buyerPkh: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpEQUALVERIFY); err != nil {
		return nil, fmt.Errorf("%w: OP_EQUALVERIFY: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpCHECKSIG); err != nil {
		return nil, fmt.Errorf("%w: OP_CHECKSIG: %v", ErrHTLCBuildFailed, err)
	}
	if err := s.AppendOpcodes(script.OpENDIF); err != nil {
		return nil, fmt.Errorf("%w: OP_ENDIF: %v", ErrHTLCBuildFailed, err)
	}

	return s.Bytes(), nil
}

// ParseHTLCPreimage extracts the capsule from a spent HTLC claim input.
// The spending transaction's unlocking script for the claim path is:
//
//	<sig> <pubkey> <fileTxID||capsule> OP_TRUE
//
// Where OP_TRUE selects the IF branch (claim). The preimage pushed in the
// unlocking script is fileTxID (32 bytes) concatenated with the capsule (32
// bytes), totalling 64 bytes. The locking script verifies OP_SHA256 of this
// 64-byte preimage against the embedded capsuleHash = SHA256(fileTxID||capsule).
//
// If expectedCapsuleHash is non-nil, verifies SHA256(preimage) matches.
// If fileTxID is provided, additionally verifies the first 32 bytes of the
// preimage match the expected file transaction ID.
//
// Returns only the capsule (last 32 bytes of the preimage).
func ParseHTLCPreimage(spendingTx []byte, expectedCapsuleHash []byte, fileTxID ...[]byte) ([]byte, error) {
	if len(spendingTx) == 0 {
		return nil, fmt.Errorf("%w: empty spending transaction", ErrInvalidPreimage)
	}

	tx, err := transaction.NewTransactionFromBytes(spendingTx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	// Look through all inputs for an HTLC spend.
	for _, input := range tx.Inputs {
		if input.UnlockingScript == nil {
			continue
		}

		chunks, err := input.UnlockingScript.Chunks()
		if err != nil {
			continue
		}

		// Claim unlocking script: <sig> <pubkey> <fileTxID||capsule> OP_TRUE
		// We expect at least 4 chunks.
		if len(chunks) < 4 {
			continue
		}

		// The last chunk should be OP_TRUE/OP_1 (0x51) selecting claim path (IF branch).
		lastChunk := chunks[len(chunks)-1]
		if lastChunk.Op != script.OpTRUE && lastChunk.Op != script.Op1 {
			continue
		}

		// The preimage (fileTxID || capsule) is the third element (chunks[2]).
		// It must be exactly 64 bytes: 32-byte fileTxID + 32-byte capsule.
		preimageChunk := chunks[2]
		if len(preimageChunk.Data) < 64 {
			continue
		}

		preimageFileTxID := preimageChunk.Data[:32]
		capsule := preimageChunk.Data[32:64]

		// Optionally verify fileTxID matches.
		if len(fileTxID) > 0 && len(fileTxID[0]) > 0 {
			if !bytes.Equal(preimageFileTxID, fileTxID[0]) {
				continue
			}
		}

		// Verify hash if expected hash provided.
		// SHA256(fileTxID || capsule) must match the embedded capsuleHash.
		if expectedCapsuleHash != nil {
			h := sha256.Sum256(preimageChunk.Data[:64])
			if !bytes.Equal(h[:], expectedCapsuleHash) {
				continue
			}
		}

		return capsule, nil
	}

	return nil, fmt.Errorf("%w: no HTLC preimage found in transaction inputs", ErrInvalidPreimage)
}

// Byte offsets of parameters within the plain Bitcoin Script HTLC locking
// script. All offsets are fixed (no variable-length fields):
//
//	byte[0]      = 0x10 (PUSH 16 bytes)
//	byte[1..16]  = invoiceId (16 bytes)
//	byte[17]     = 0x75 (OP_DROP)
//	byte[18]     = 0x63 (OP_IF)
//	byte[19]     = 0xa8 (OP_SHA256)
//	byte[20]     = 0x20 (PUSH 32 bytes)
//	byte[21..52] = capsuleHash (32 bytes)
//	byte[53]     = 0x88 (OP_EQUALVERIFY)
//	byte[54..78] = OP_DUP OP_HASH160 0x14 sellerPkh(20) OP_EQUALVERIFY OP_CHECKSIG
//	byte[79]     = 0x67 (OP_ELSE)
//	byte[80..104]= OP_DUP OP_HASH160 0x14 buyerPkh(20) OP_EQUALVERIFY OP_CHECKSIG
//	byte[105]    = 0x68 (OP_ENDIF)
const (
	htlcInvoiceIDOffset_   = 1  // byte offset of invoiceId (16 bytes)
	htlcCapsuleHashOffset_ = 21 // byte offset of capsuleHash (32 bytes)
	htlcSellerPkhOffset_   = 57 // byte offset of sellerPkh (20 bytes)
	htlcBuyerPkhOffset_    = 83 // byte offset of buyerPkh (20 bytes)

	// Exact script length: 106 bytes (fixed, no variable-length timeout).
	htlcMinScriptLen = 106
)

// ExtractCapsuleHashFromHTLC extracts the 32-byte capsule hash embedded in an
// HTLC locking script produced by BuildHTLC.
func ExtractCapsuleHashFromHTLC(htlcScript []byte) ([]byte, error) {
	if len(htlcScript) < htlcMinScriptLen {
		return nil, fmt.Errorf("HTLC script too short: %d bytes", len(htlcScript))
	}
	if !isHTLCScript(htlcScript) {
		return nil, fmt.Errorf("HTLC script does not match expected format")
	}
	hash := make([]byte, CapsuleHashLen)
	copy(hash, htlcScript[htlcCapsuleHashOffset_:htlcCapsuleHashOffset_+CapsuleHashLen])
	return hash, nil
}

// ExtractInvoiceIDFromHTLC extracts the 16-byte invoice ID embedded in an
// HTLC locking script produced by BuildHTLC.
// Returns nil if the script does not match the expected HTLC format.
func ExtractInvoiceIDFromHTLC(htlcScript []byte) ([]byte, error) {
	if len(htlcScript) < htlcMinScriptLen {
		return nil, nil // Too short; cannot be an HTLC script.
	}
	if !isHTLCScript(htlcScript) {
		return nil, nil // Not an HTLC script.
	}
	id := make([]byte, InvoiceIDLen)
	copy(id, htlcScript[htlcInvoiceIDOffset_:htlcInvoiceIDOffset_+InvoiceIDLen])
	return id, nil
}

// isHTLCScript returns true if the script bytes match the expected plain
// Bitcoin Script HTLC format by checking structural marker bytes.
func isHTLCScript(scriptBytes []byte) bool {
	if len(scriptBytes) < htlcMinScriptLen {
		return false
	}
	return scriptBytes[0] == 0x10 && // PUSH 16 bytes (invoiceId)
		scriptBytes[17] == 0x75 && // OP_DROP
		scriptBytes[18] == 0x63 && // OP_IF
		scriptBytes[19] == 0xa8 && // OP_SHA256
		scriptBytes[20] == 0x20 // PUSH 32 bytes (capsuleHash)
}
