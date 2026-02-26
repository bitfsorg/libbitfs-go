package revshare

import "fmt"

// ValidateShareConservation checks that total input shares equal total output shares.
func ValidateShareConservation(inputs []ShareData, outputs []ShareData) error {
	var inputTotal, outputTotal uint64
	for _, in := range inputs {
		inputTotal += in.Amount
	}
	for _, out := range outputs {
		outputTotal += out.Amount
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
		return err
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
