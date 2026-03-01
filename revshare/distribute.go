package revshare

import (
	"fmt"
	"math/bits"
)

// DistributeRevenue calculates per-shareholder payouts.
// The last entry gets the remainder to avoid integer division precision loss.
//
// Safety guarantees:
//   - Validates sum(entry.Share) == totalShares (prevents over/under-distribution)
//   - Uses 128-bit intermediate multiplication (prevents overflow on large values)
//   - Checks for underflow before remainder calculation
func DistributeRevenue(totalPayment uint64, entries []RevShareEntry, totalShares uint64) ([]Distribution, error) {
	if totalPayment == 0 {
		return nil, ErrInsufficientPayment
	}
	if len(entries) == 0 {
		return nil, ErrNoEntries
	}
	if totalShares == 0 {
		return nil, ErrZeroTotalShares
	}

	// C-3 fix: Validate that sum of entry shares equals totalShares.
	var shareSum uint64
	for _, entry := range entries {
		sum, carry := bits.Add64(shareSum, entry.Share, 0)
		if carry != 0 {
			return nil, fmt.Errorf("%w: share sum exceeds uint64", ErrOverflow)
		}
		shareSum = sum
	}
	if shareSum != totalShares {
		return nil, fmt.Errorf("%w: sum %d != totalShares %d", ErrShareSumMismatch, shareSum, totalShares)
	}

	distributions := make([]Distribution, len(entries))
	var distributed uint64

	for i, entry := range entries {
		distributions[i].Address = entry.Address
		if i == len(entries)-1 {
			// C-2 fix: Check for underflow before remainder calculation.
			if distributed > totalPayment {
				return nil, fmt.Errorf("%w: distributed %d exceeds total payment %d", ErrOverflow, distributed, totalPayment)
			}
			distributions[i].Amount = totalPayment - distributed
		} else {
			// C-1 fix: Use 128-bit intermediate multiplication to prevent overflow.
			amount := mulDiv64(totalPayment, entry.Share, totalShares)
			distributions[i].Amount = amount
			distributed += amount
		}
	}

	return distributions, nil
}

// mulDiv64 computes (a * b) / c using 128-bit intermediate multiplication
// to prevent overflow. Panics if c == 0 (caller must validate).
func mulDiv64(a, b, c uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi == 0 {
		// No overflow in multiplication — use simple division.
		return lo / c
	}
	// 128-bit division: (hi:lo) / c
	quo, _ := bits.Div64(hi, lo, c)
	return quo
}
