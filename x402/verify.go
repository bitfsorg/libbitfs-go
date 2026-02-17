package x402

import (
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// VerifyPayment verifies that a submitted transaction pays the required invoice.
//  1. Check invoice is not expired
//  2. Deserialize raw_tx
//  3. Find output matching invoice amount and address
func VerifyPayment(proof *PaymentProof, invoice *Invoice) error {
	if proof == nil {
		return fmt.Errorf("%w: nil payment proof", ErrInvalidParams)
	}
	if invoice == nil {
		return fmt.Errorf("%w: nil invoice", ErrInvalidParams)
	}

	// Check invoice expiry
	if time.Now().Unix() > invoice.Expiry {
		return ErrInvoiceExpired
	}

	// Deserialize the transaction
	if len(proof.RawTx) == 0 {
		return fmt.Errorf("%w: empty raw transaction", ErrInvalidTx)
	}

	tx, err := transaction.NewTransactionFromBytes(proof.RawTx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTx, err)
	}

	// Parse the expected payment address to get its script
	expectedAddr, err := script.NewAddressFromString(invoice.PaymentAddr)
	if err != nil {
		return fmt.Errorf("%w: invalid invoice address: %v", ErrInvalidParams, err)
	}

	expectedPKH := []byte(expectedAddr.PublicKeyHash)
	if len(expectedPKH) == 0 {
		return fmt.Errorf("%w: empty public key hash from address", ErrInvalidParams)
	}

	// Search for a matching output
	found := false
	for _, output := range tx.Outputs {
		if output.LockingScript == nil {
			continue
		}

		// Check if the output is a P2PKH to the expected address
		if !output.LockingScript.IsP2PKH() {
			continue
		}

		outputPKH, err := output.LockingScript.PublicKeyHash()
		if err != nil {
			continue
		}

		// Compare public key hashes
		if len(outputPKH) != len(expectedPKH) {
			continue
		}

		match := true
		for i := range outputPKH {
			if outputPKH[i] != expectedPKH[i] {
				match = false
				break
			}
		}

		if !match {
			continue
		}

		// Check amount
		if output.Satoshis < invoice.Price {
			return fmt.Errorf("%w: output has %d satoshis, need %d",
				ErrInsufficientPayment, output.Satoshis, invoice.Price)
		}

		found = true
		break
	}

	if !found {
		return ErrNoMatchingOutput
	}

	return nil
}
