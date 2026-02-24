package x402

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// HTLCParams holds parameters for creating an HTLC transaction.
type HTLCParams struct {
	BuyerPubKey  []byte // Buyer's compressed public key (33 bytes)
	SellerPubKey []byte // Seller's compressed public key (33 bytes)
	SellerAddr   []byte // Seller's P2PKH address hash (20 bytes)
	CapsuleHash  []byte // SHA256(capsule), 32 bytes
	Amount       uint64 // Payment amount in satoshis
	Timeout      uint32 // Timeout in blocks (default 144 = ~24 hours), used for nLockTime on refund tx
}

const (
	// DefaultHTLCTimeout is the default HTLC timeout in blocks (~24 hours).
	DefaultHTLCTimeout = 144

	// CompressedPubKeyLen is the expected length of a compressed public key.
	CompressedPubKeyLen = 33

	// PubKeyHashLen is the expected length of a P2PKH address hash.
	PubKeyHashLen = 20

	// CapsuleHashLen is the expected length of a capsule hash (SHA256).
	CapsuleHashLen = 32
)

// BuildHTLC constructs an HTLC locking script:
//
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

	s := &script.Script{}

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
func ParseHTLCPreimage(spendingTx []byte) ([]byte, error) {
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

		return preimageChunk.Data, nil
	}

	return nil, fmt.Errorf("%w: no HTLC preimage found in transaction inputs", ErrInvalidPreimage)
}
