package payment

import (
	"bytes"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// PaymentVerification holds the result of a successful VerifyPayment call.
type PaymentVerification struct {
	// TxID is the transaction ID (hex string) of the verified payment.
	TxID string

	// InvoiceID is the invoice this payment was verified against, if provided.
	// Callers SHOULD use TxID + InvoiceID for deduplication tracking.
	InvoiceID string
}

// VerifyPayment checks that a submitted transaction contains an output paying
// the required invoice amount to the invoice address.
//
// WARNING: This function does NOT verify input signatures. An attacker can
// construct a transaction with valid-looking outputs but forged inputs.
// Callers MUST either:
//   - Call ValidateInputSignatures to verify script execution locally, OR
//   - Independently confirm the transaction is accepted by the network (mempool
//     or confirmed) before delivering content.
//
// WARNING: This function does NOT enforce TxID uniqueness across invocations.
// The same transaction can pass verification for multiple invoices if they share
// the same payment address and compatible amounts. Callers MUST track used TxIDs
// to prevent cross-invoice payment reuse.
//
// When invoice.ID is non-empty, it is included in the returned PaymentVerification
// for caller convenience in deduplication tracking.
//
// Returns a PaymentVerification containing the TxID (hex) and InvoiceID on success.
func VerifyPayment(proof *PaymentProof, invoice *Invoice) (*PaymentVerification, error) {
	if proof == nil {
		return nil, fmt.Errorf("%w: nil payment proof", ErrInvalidParams)
	}
	if invoice == nil {
		return nil, fmt.Errorf("%w: nil invoice", ErrInvalidParams)
	}

	// Check invoice expiry
	if time.Now().Unix() > invoice.Expiry {
		return nil, ErrInvoiceExpired
	}

	// Deserialize the transaction
	if len(proof.RawTx) == 0 {
		return nil, fmt.Errorf("%w: empty raw transaction", ErrInvalidTx)
	}

	tx, err := transaction.NewTransactionFromBytes(proof.RawTx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTx, err)
	}

	// Parse the expected payment address to get its script
	expectedAddr, err := script.NewAddressFromString(invoice.PaymentAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid invoice address: %w", ErrInvalidParams, err)
	}

	expectedPKH := []byte(expectedAddr.PublicKeyHash)
	if len(expectedPKH) == 0 {
		return nil, fmt.Errorf("%w: empty public key hash from address", ErrInvalidParams)
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
			return nil, fmt.Errorf("%w: output has %d satoshis, need %d",
				ErrInsufficientPayment, output.Satoshis, invoice.Price)
		}

		found = true
		break
	}

	if !found {
		return nil, ErrNoMatchingOutput
	}

	return &PaymentVerification{
		TxID:      tx.TxID().String(),
		InvoiceID: invoice.ID,
	}, nil
}

// ValidateInputSignatures verifies that all inputs of the given transaction have
// valid unlocking scripts that satisfy their corresponding locking scripts. This
// uses the BSV SDK's script interpreter to execute each input's script pair.
//
// Each input must have its source transaction output set (via SetSourceTxOutput)
// before calling this function. If any input lacks source output information, an
// error is returned.
//
// This function provides local signature verification without network access. It
// does NOT guarantee the inputs are unspent (no double-spend check) — that still
// requires network confirmation.
func ValidateInputSignatures(tx *transaction.Transaction) error {
	if tx == nil {
		return fmt.Errorf("%w: nil transaction", ErrInvalidParams)
	}
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("%w: transaction has no inputs", ErrInvalidParams)
	}

	eng := interpreter.NewEngine()

	for i, input := range tx.Inputs {
		prevOutput := input.SourceTxOutput()
		if prevOutput == nil {
			return fmt.Errorf("%w: input %d missing source transaction output", ErrInvalidParams, i)
		}
		if prevOutput.LockingScript == nil {
			return fmt.Errorf("%w: input %d source output has nil locking script", ErrInvalidParams, i)
		}

		if err := eng.Execute(
			interpreter.WithTx(tx, i, prevOutput),
			interpreter.WithForkID(),
			interpreter.WithAfterGenesis(),
		); err != nil {
			return fmt.Errorf("input %d script verification failed: %w", i, err)
		}
	}
	return nil
}
