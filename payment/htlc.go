package payment

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	bsvhash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bitfsorg/libbitfs-go/method42"
)

// HTLCParams holds parameters for creating an HTLC transaction.
type HTLCParams struct {
	BuyerPubKey  []byte // Buyer's compressed public key (33 bytes)
	SellerPubKey []byte // Seller's compressed public key (33 bytes) — kept for BuildHTLCFundingTx compatibility; not embedded in sCrypt artifact script
	SellerAddr   []byte // Seller's P2PKH address hash (20 bytes)
	CapsuleHash  []byte // SHA256(capsule), 32 bytes
	Amount       uint64 // Payment amount in satoshis
	Timeout      uint32 // Refund timeout in blocks (default 72 = ~12h), used as nLockTime. Must be in [MinHTLCTimeout, MaxHTLCTimeout].
	InvoiceID    []byte // Invoice ID for replay protection (16 bytes, mandatory for sCrypt artifact)
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

// BuildHTLC constructs an HTLC locking script by instantiating the compiled
// sCrypt BitfsHTLC artifact. The artifact encodes both the seller-claim path
// (hash-lock + P2PKH) and the buyer-refund path (OP_PUSH_TX + nLockTime CLTV)
// in a single script. Constructor parameters embedded in the script:
//
//   - invoiceId   — 16-byte replay protection token (mandatory)
//   - capsuleHash — SHA256(capsule), 32 bytes
//   - sellerPkh   — HASH160(seller public key), 20 bytes
//   - buyerPkh    — HASH160(buyer public key), 20 bytes
//   - timeout     — refund timeout in blocks
//
// The seller claims by providing the capsule preimage and their signature.
// The buyer refunds on-chain after timeout using OP_PUSH_TX to verify nLockTime.
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

	// Derive buyer PKH from buyer public key.
	buyerPkh := bsvhash.Hash160(params.BuyerPubKey)

	art, err := LoadArtifact()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTLCBuildFailed, err)
	}

	scriptBytes, err := art.Instantiate(params.InvoiceID, params.CapsuleHash, params.SellerAddr, buyerPkh, params.Timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHTLCBuildFailed, err)
	}

	return scriptBytes, nil
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
			h, hErr := method42.ComputeCapsuleHash(ftxid, preimageChunk.Data)
			if hErr != nil || !bytes.Equal(h, expectedCapsuleHash) {
				continue // Hash mismatch or invalid input — try next input.
			}
		}

		return preimageChunk.Data, nil
	}

	return nil, fmt.Errorf("%w: no HTLC preimage found in transaction inputs", ErrInvalidPreimage)
}

// Byte offsets of constructor parameters within the instantiated sCrypt artifact
// script. These offsets are determined by the fixed-size prefix in the compiled
// hex template (107 bytes before the first parameter). All four data fields
// (invoiceId, capsuleHash, sellerPkh, buyerPkh) precede the variable-length
// timeout encoding, so their offsets are constant.
const (
	htlcInvoiceIDOffset_   = 107 // byte offset of invoiceId (16 bytes)
	htlcCapsuleHashOffset_ = 123 // byte offset of capsuleHash (32 bytes)
	htlcSellerPkhOffset_   = 155 // byte offset of sellerPkh (20 bytes)
	htlcBuyerPkhOffset_    = 175 // byte offset of buyerPkh (20 bytes)

	// Minimum script length: all fixed fields + at least 1-byte timeout + suffix.
	htlcMinScriptLen = htlcBuyerPkhOffset_ + PubKeyHashLen + 1
)

// ExtractCapsuleHashFromHTLC extracts the 32-byte capsule hash embedded in an
// HTLC locking script produced by the sCrypt BitfsHTLC artifact.
func ExtractCapsuleHashFromHTLC(htlcScript []byte) ([]byte, error) {
	if len(htlcScript) < htlcMinScriptLen {
		return nil, fmt.Errorf("HTLC script too short: %d bytes", len(htlcScript))
	}
	if !isArtifactScript(htlcScript) {
		return nil, fmt.Errorf("HTLC script does not match sCrypt artifact prefix")
	}
	hash := make([]byte, CapsuleHashLen)
	copy(hash, htlcScript[htlcCapsuleHashOffset_:htlcCapsuleHashOffset_+CapsuleHashLen])
	return hash, nil
}

// ExtractInvoiceIDFromHTLC extracts the 16-byte invoice ID embedded in an
// HTLC locking script produced by the sCrypt BitfsHTLC artifact.
// Returns nil if the script does not match the expected artifact format.
func ExtractInvoiceIDFromHTLC(htlcScript []byte) ([]byte, error) {
	if len(htlcScript) < htlcMinScriptLen {
		return nil, nil // Too short; cannot be an artifact script.
	}
	if !isArtifactScript(htlcScript) {
		return nil, nil // Not an artifact script.
	}
	id := make([]byte, InvoiceIDLen)
	copy(id, htlcScript[htlcInvoiceIDOffset_:htlcInvoiceIDOffset_+InvoiceIDLen])
	return id, nil
}

// artifactPrefixHex is the first portion of the compiled sCrypt hex template
// that appears before the constructor parameters. Used to identify whether a
// script was produced by the BitfsHTLC artifact.
var artifactPrefix []byte

func init() {
	// Load the artifact prefix from the hex template at init time.
	art, err := LoadArtifact()
	if err != nil {
		// Artifact is embedded via go:embed; if it's missing the binary is broken.
		panic(fmt.Sprintf("payment: load artifact for prefix: %v", err))
	}
	// The prefix is the hex template up to the first placeholder.
	idx := strings.Index(art.Hex, "<")
	if idx <= 0 {
		panic("payment: artifact hex has no placeholders")
	}
	artifactPrefix, err = hex.DecodeString(art.Hex[:idx])
	if err != nil {
		panic(fmt.Sprintf("payment: decode artifact prefix: %v", err))
	}
}

// isArtifactScript returns true if the script bytes start with the known
// sCrypt BitfsHTLC artifact prefix.
func isArtifactScript(scriptBytes []byte) bool {
	if len(scriptBytes) < len(artifactPrefix) {
		return false
	}
	return bytes.Equal(scriptBytes[:len(artifactPrefix)], artifactPrefix)
}
