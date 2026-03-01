package revshare

import (
	"fmt"
	"math/bits"
)

// ValidateShareConservation checks that total input shares equal total output shares.
// Uses overflow-safe summation to prevent uint64 wrap-around attacks.
func ValidateShareConservation(inputs []ShareData, outputs []ShareData) error {
	inputTotal, err := safeSum(inputs)
	if err != nil {
		return fmt.Errorf("%w: input %w", ErrOverflow, err)
	}
	outputTotal, err := safeSum(outputs)
	if err != nil {
		return fmt.Errorf("%w: output %w", ErrOverflow, err)
	}
	if inputTotal != outputTotal {
		return fmt.Errorf("%w: input=%d output=%d", ErrShareConservationViolation, inputTotal, outputTotal)
	}
	return nil
}

// ValidateDistribution checks that distribution amounts match registry proportions.
func ValidateDistribution(distributions []Distribution, entries []RevShareEntry, totalPayment, totalShares uint64) error {
	if len(distributions) != len(entries) {
		return fmt.Errorf("distribution count %d != entry count %d", len(distributions), len(entries))
	}

	expected, err := DistributeRevenue(totalPayment, entries, totalShares)
	if err != nil {
		return fmt.Errorf("validate distribution: %w", err)
	}

	for i := range distributions {
		if distributions[i].Address != expected[i].Address {
			return fmt.Errorf("entry %d: address mismatch", i)
		}
		if distributions[i].Amount != expected[i].Amount {
			return fmt.Errorf("entry %d: amount %d != expected %d", i, distributions[i].Amount, expected[i].Amount)
		}
	}
	return nil
}

// safeSum computes the sum of ShareData amounts with overflow detection.
func safeSum(items []ShareData) (uint64, error) {
	var total uint64
	for _, item := range items {
		sum, carry := bits.Add64(total, item.Amount, 0)
		if carry != 0 {
			return 0, fmt.Errorf("sum overflow at amount %d", item.Amount)
		}
		total = sum
	}
	return total, nil
}
