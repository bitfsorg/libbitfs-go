package revshare

// DistributeRevenue calculates per-shareholder payouts.
// The last entry gets the remainder to avoid integer division precision loss.
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

	distributions := make([]Distribution, len(entries))
	var distributed uint64

	for i, entry := range entries {
		distributions[i].Address = entry.Address
		if i == len(entries)-1 {
			// Last shareholder gets remainder
			distributions[i].Amount = totalPayment - distributed
		} else {
			amount := totalPayment * entry.Share / totalShares
			distributions[i].Amount = amount
			distributed += amount
		}
	}

	return distributions, nil
}
