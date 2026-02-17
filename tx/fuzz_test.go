package tx

import (
	"bytes"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// FuzzParseOPReturnDataNoPanic ensures ParseOPReturnData never panics.
func FuzzParseOPReturnDataNoPanic(f *testing.F) {
	f.Add([]byte("meta"), []byte{}, []byte{}, []byte{})
	f.Add([]byte("meta"), make([]byte, CompressedPubKeyLen), []byte{}, []byte{0x01})
	f.Add([]byte("xxxx"), make([]byte, CompressedPubKeyLen), make([]byte, TxIDLen), []byte("payload"))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, p0, p1, p2, p3 []byte) {
		pushes := [][]byte{p0, p1, p2, p3}
		ParseOPReturnData(pushes)
	})
}

// FuzzBuildParseRoundTrip verifies BuildOPReturnData followed by
// ParseOPReturnData returns the original fields.
func FuzzBuildParseRoundTrip(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03})                  // payload, no parent
	f.Add(make([]byte, 100))                          // larger payload
	f.Add([]byte{0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00}) // TLV-like payload

	privKey, err := ec.NewPrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	pubKey := privKey.PubKey()

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 {
			return // BuildOPReturnData rejects empty payload
		}

		// Test with no parent (root node)
		pushes, err := BuildOPReturnData(pubKey, nil, payload)
		if err != nil {
			t.Fatalf("BuildOPReturnData(root): %v", err)
		}

		pNode, parentTxID, gotPayload, err := ParseOPReturnData(pushes)
		if err != nil {
			t.Fatalf("ParseOPReturnData(root): %v", err)
		}

		if !bytes.Equal(pNode, pubKey.Compressed()) {
			t.Error("P_node mismatch")
		}
		if len(parentTxID) != 0 {
			t.Errorf("expected empty parent TxID for root, got %d bytes", len(parentTxID))
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Error("payload mismatch")
		}

		// Test with parent TxID
		fakeTxID := make([]byte, TxIDLen)
		copy(fakeTxID, payload) // use payload bytes as seed
		pushes2, err := BuildOPReturnData(pubKey, fakeTxID, payload)
		if err != nil {
			t.Fatalf("BuildOPReturnData(child): %v", err)
		}

		pNode2, parentTxID2, gotPayload2, err := ParseOPReturnData(pushes2)
		if err != nil {
			t.Fatalf("ParseOPReturnData(child): %v", err)
		}

		if !bytes.Equal(pNode2, pubKey.Compressed()) {
			t.Error("P_node mismatch (child)")
		}
		if !bytes.Equal(parentTxID2, fakeTxID) {
			t.Error("parent TxID mismatch")
		}
		if !bytes.Equal(gotPayload2, payload) {
			t.Error("payload mismatch (child)")
		}
	})
}

// FuzzEstimateFeeNoPanic ensures EstimateFee handles all uint64 inputs.
func FuzzEstimateFeeNoPanic(f *testing.F) {
	f.Add(0, uint64(1))
	f.Add(1000, uint64(1))
	f.Add(100000, uint64(500))
	f.Add(1<<31-1, uint64(1<<63-1))

	f.Fuzz(func(t *testing.T, txSize int, feeRate uint64) {
		if txSize < 0 {
			return // negative size is meaningless
		}
		EstimateFee(txSize, feeRate)
	})
}
