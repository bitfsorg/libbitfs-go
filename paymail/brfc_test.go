package paymail

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeBRFCID(t *testing.T) {
	t.Run("returns 12-char hex string", func(t *testing.T) {
		id := ComputeBRFCID("Test Title", "Test Author", "1.0")
		assert.Len(t, id, 12)
		// Verify it's valid hex
		_, err := hex.DecodeString(id)
		require.NoError(t, err)
	})

	t.Run("deterministic", func(t *testing.T) {
		id1 := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		id2 := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		assert.Equal(t, id1, id2)
	})

	t.Run("different inputs produce different outputs", func(t *testing.T) {
		idBrowse := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		idBuy := ComputeBRFCID("BitFS Buy", "BitFS", "1.0")
		idSell := ComputeBRFCID("BitFS Sell", "BitFS", "1.0")

		assert.NotEqual(t, idBrowse, idBuy)
		assert.NotEqual(t, idBrowse, idSell)
		assert.NotEqual(t, idBuy, idSell)
	})

	t.Run("different version produces different output", func(t *testing.T) {
		id1 := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		id2 := ComputeBRFCID("BitFS Browse", "BitFS", "2.0")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("different author produces different output", func(t *testing.T) {
		id1 := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		id2 := ComputeBRFCID("BitFS Browse", "Other", "1.0")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("empty inputs produce valid output", func(t *testing.T) {
		id := ComputeBRFCID("", "", "")
		assert.Len(t, id, 12)
		_, err := hex.DecodeString(id)
		require.NoError(t, err)
	})
}

func TestBRFCConstants(t *testing.T) {
	t.Run("BRFCBitFSBrowse matches computed value", func(t *testing.T) {
		expected := ComputeBRFCID("BitFS Browse", "BitFS", "1.0")
		assert.Equal(t, expected, BRFCBitFSBrowse)
	})

	t.Run("BRFCBitFSBuy matches computed value", func(t *testing.T) {
		expected := ComputeBRFCID("BitFS Buy", "BitFS", "1.0")
		assert.Equal(t, expected, BRFCBitFSBuy)
	})

	t.Run("BRFCBitFSSell matches computed value", func(t *testing.T) {
		expected := ComputeBRFCID("BitFS Sell", "BitFS", "1.0")
		assert.Equal(t, expected, BRFCBitFSSell)
	})

	t.Run("all constants are distinct", func(t *testing.T) {
		assert.NotEqual(t, BRFCBitFSBrowse, BRFCBitFSBuy)
		assert.NotEqual(t, BRFCBitFSBrowse, BRFCBitFSSell)
		assert.NotEqual(t, BRFCBitFSBuy, BRFCBitFSSell)
	})

	t.Run("all constants are 12-char hex", func(t *testing.T) {
		for name, id := range map[string]string{
			"Browse": BRFCBitFSBrowse,
			"Buy":    BRFCBitFSBuy,
			"Sell":   BRFCBitFSSell,
		} {
			assert.Len(t, id, 12, "BRFC %s should be 12 chars", name)
			_, err := hex.DecodeString(id)
			require.NoError(t, err, "BRFC %s should be valid hex", name)
		}
	})
}
