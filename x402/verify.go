package x402

import (
	"bytes"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// VerifyPayment checks that a submitted transaction contains an output paying
// the required invoice amount to the invoice address.
//
// WARNING: This function does NOT verify input signatures. Callers MUST
// independently confirm the transaction is accepted by the network (mempool
// or confirmed) before delivering content.
//
// WARNING: This function does NOT bind the payment to a specific InvoiceID.
// Callers MUST track used TxIDs to prevent cross-invoice payment reuse.
//
// Returns the transaction ID (TxID hex) on success for caller tracking.
func VerifyPayment(proof *PaymentProof, invoice *Invoice) (string, error) {
	if proof == nil {
		return "", fmt.Errorf("%w: nil payment proof", ErrInvalidParams)
	}
	if invoice == nil {
		return "", fmt.Errorf("%w: nil invoice", ErrInvalidParams)
	}

	// Check invoice expiry
	if time.Now().Unix() > invoice.Expiry {
		return "", ErrInvoiceExpired
	}

	// Deserialize the transaction
	if len(proof.RawTx) == 0 {
		return "", fmt.Errorf("%w: empty raw transaction", ErrInvalidTx)
	}

	tx, err := transaction.NewTransactionFromBytes(proof.RawTx)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	// Parse the expected payment address to get its script
	expectedAddr, err := script.NewAddressFromString(invoice.PaymentAddr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid invoice address: %w", ErrInvalidParams, err)
	}

	expectedPKH := []byte(expectedAddr.PublicKeyHash)
	if len(expectedPKH) == 0 {
		return "", fmt.Errorf("%w: empty public key hash from address", ErrInvalidParams)
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

		if !bytes.Equal(outputPKH, expectedPKH) {
			continue
		}

		// Check amount
		if output.Satoshis < invoice.Price {
			return "", fmt.Errorf("%w: output has %d satoshis, need %d",
				ErrInsufficientPayment, output.Satoshis, invoice.Price)
		}

		found = true
		break
	}

	if !found {
		return "", ErrNoMatchingOutput
	}

	return tx.TxID().String(), nil
}
