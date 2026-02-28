package vault

import (
	"fmt"

	"github.com/tongxiaofeng/libbitfs-go/tx"
)

// buildAndSignBatch builds and signs a MutationBatch transaction.
// Returns the signed tx hex and the BatchResult (with TxID set on all UTXOs).
func buildAndSignBatch(batch *tx.MutationBatch) (string, *tx.BatchResult, error) {
	result, err := batch.Build()
	if err != nil {
		return "", nil, fmt.Errorf("batch build: %w", err)
	}
	txHex, err := batch.Sign(result)
	if err != nil {
		return "", nil, fmt.Errorf("batch sign: %w", err)
	}
	return txHex, result, nil
}
